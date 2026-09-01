from __future__ import annotations

import csv
import json
import stat
import subprocess
from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

import mas_safety.live as live_module
from mas_safety.enums import (
    Architecture,
    DecisionMode,
    Defense,
    Mechanism,
    SafetyVariant,
)
from mas_safety.live import (
    HARD_QA_EXPECTED_TESTS,
    _run_live_development_for_test,
    live_development_specs,
)
from mas_safety.live_analysis import (
    EXPECTED_REPETITIONS,
    EXPECTED_RUNS,
    MAX_AGENT_CALLS,
    analyze_live_development,
)
from mas_safety.live_backends import (
    DECISION_SCHEMA_SHA256,
    DECISION_SCHEMA_VERSION,
    INSTRUCTIONS_SHA256,
    PROMPT_VERSION,
)
from mas_safety.models import ActionSpec, AgentDecision
from mas_safety.scenarios import load_scenarios

TEST_FREEZE = {
    "commit_sha": "c" * 40,
    "working_tree_clean": True,
    "protocol_sha256": "d" * 64,
}


class StructuredOracleBackend:
    """Deterministic stand-in that exercises the live runner without API calls."""

    name = "openai_responses"

    def __init__(self, model_id: str, raw_log_dir: Path) -> None:
        self.model_id = model_id
        raw_log_dir.mkdir(parents=True, mode=0o700)
        self.call_count = 0
        self.run_metadata: dict[str, object] = {}
        self.configuration = {
            "test_only_no_external_io": True,
            "provider": "openai",
            "api": "responses",
            "base_url": "https://api.openai.com/v1",
            "ambient_endpoint_overrides_allowed": False,
            "ambient_custom_headers_allowed": False,
            "http_follow_redirects": False,
            "http_trust_env": False,
            "requested_model": model_id,
            "sdk_version": "3.6.0",
            "pinned_sdk_version": "3.6.0",
            "prompt_version": PROMPT_VERSION,
            "decision_schema_version": DECISION_SCHEMA_VERSION,
            "instructions_sha256": INSTRUCTIONS_SHA256,
            "decision_schema_sha256": DECISION_SCHEMA_SHA256,
            "structured_output": "json_schema_strict",
            "store": False,
            "max_output_tokens": 256,
            "temperature": "provider_default_unset",
            "top_p": "provider_default_unset",
            "tools": "none",
            "timeout_seconds": 120.0,
            "max_retries": 0,
            "seed_supported": False,
        }

    def set_run_metadata(self, metadata: dict[str, object]) -> None:
        self.run_metadata = dict(metadata)

    def decide(self, **kwargs: object) -> AgentDecision:
        self.call_count += 1
        candidate = kwargs["candidate_action"]
        assert isinstance(candidate, ActionSpec)
        assert kwargs["decision_mode"] is DecisionMode.EXECUTION_DECISION
        return AgentDecision.execute(
            candidate,
            raw_output='{"decision":"execute"}',
            provider_metadata={
                "provider": "openai",
                "response_id": f"resp-test-{self.call_count:04d}",
                "request_id": f"req-test-{self.call_count:04d}",
                "resolved_response_model": self.model_id,
                "model_snapshot": self.model_id,
                "status": "completed",
                "structured_output_valid": True,
                "structured_output": "json_schema_strict",
                "response_received": True,
                "model_response_received": True,
                "failure_type": None,
                "requested_model": self.model_id,
                "api": "responses",
                "raw_log_record": f"fake-call-{self.call_count:04d}",
                "prompt_sha256": "e" * 64,
                "provider_request_sha256": "f" * 64,
                "request_record_sha256": "1" * 64,
                "result_record_sha256": "2" * 64,
                "result_record_kind": "response",
                "seed_supported": False,
                "local_pairing_seed": kwargs["seed"],
                "call_order": self.call_count,
                "attempted_at_utc": "2026-08-31T12:00:00+00:00",
                "received_at_utc": "2026-08-31T12:00:01+00:00",
                **self.run_metadata,
            },
            input_tokens=11,
            output_tokens=3,
            latency_ms=0.25,
        )


def _backend_factory(model_id: str, raw_log_dir: Path) -> StructuredOracleBackend:
    return StructuredOracleBackend(model_id, raw_log_dir)


def test_hard_qa_sentinel() -> None:
    """Named sentinel proving the frozen suite executed rather than only collected."""

    assert EXPECTED_RUNS == 192


def test_hard_qa_attestation_sanitizes_ambient_pytest_controls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_run(command: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        captured["environment"] = kwargs["env"]
        junit_argument = next(
            item for item in command if item.startswith("--junitxml=")
        )
        junit_path = Path(junit_argument.split("=", 1)[1])
        cases = [
            '<testcase classname="tests.test_live_development" name="test_hard_qa_sentinel"/>'
        ] + [
            f'<testcase classname="tests.test_runner" name="test_{index}"/>'
            for index in range(HARD_QA_EXPECTED_TESTS - 1)
        ]
        junit_path.write_text(
            '<testsuites><testsuite>' + "".join(cases) + "</testsuite></testsuites>",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "passed", "")

    monkeypatch.setenv("PYTEST_ADDOPTS", "--collect-only -k nonexistent")
    monkeypatch.setenv("PYTEST_PLUGINS", "ambient_plugin")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "hostile-imports"))
    monkeypatch.setenv("PYTHONOPTIMIZE", "2")
    monkeypatch.setattr(live_module.subprocess, "run", fake_run)
    monkeypatch.setattr(live_module, "_git_repository_root", lambda **_kwargs: tmp_path)

    attestation = live_module._run_hard_qa_attestation(TEST_FREEZE)

    assert attestation["pass"] is True
    assert attestation["executed_test_count"] == HARD_QA_EXPECTED_TESTS
    assert attestation["sentinel_executed"] is True
    environment = captured["environment"]
    assert isinstance(environment, dict)
    assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert "PYTEST_ADDOPTS" not in environment
    assert "PYTEST_PLUGINS" not in environment
    assert "PYTHONPATH" not in environment
    assert "PYTHONOPTIMIZE" not in environment
    command = captured["command"]
    assert isinstance(command, tuple)
    assert "tests" in command
    assert "--override-ini=addopts=" in command


def test_stage_one_specs_are_exactly_96_paired_runs_per_model() -> None:
    scenarios = load_scenarios()
    specs = live_development_specs(scenarios)

    assert len(specs) == EXPECTED_RUNS // 2 == 96
    assert {spec.scenario_id for spec in specs} == {
        scenario.scenario_id for scenario in scenarios
    }
    assert {spec.mechanism for spec in specs} == set(Mechanism)
    assert {spec.safety_variant for spec in specs} == set(SafetyVariant)
    assert all(spec.defense is Defense.LOCAL_ONLY for spec in specs)
    assert all(spec.architecture is Architecture.MULTI_AGENT for spec in specs)
    assert all(
        spec.decision_mode is DecisionMode.EXECUTION_DECISION for spec in specs
    )

    logical_cells = Counter(
        (
            spec.scenario_id,
            spec.mechanism,
            spec.mechanism_active,
            spec.safety_variant,
        )
        for spec in specs
    )
    assert len(logical_cells) == 2 * 4 * 2 * 2
    assert set(logical_cells.values()) == {EXPECTED_REPETITIONS}

    pairs: dict[tuple[object, ...], list[object]] = defaultdict(list)
    for spec in specs:
        pairs[
            (
                spec.scenario_id,
                spec.mechanism,
                spec.safety_variant,
                spec.invocation_id,
                spec.seed,
            )
        ].append(spec)
        assert spec.cohort == (
            "mechanism_on" if spec.mechanism_active else "mechanism_off"
        )

    assert len(pairs) == 2 * 4 * 2 * EXPECTED_REPETITIONS == 48
    assert all(len(pair) == 2 for pair in pairs.values())
    assert all(
        {spec.mechanism_active for spec in pair} == {False, True}
        for pair in pairs.values()
    )


def test_two_model_stage_one_run_is_192_paired_runs_and_passes_gates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: list[tuple[object, ...]] = []
    real_analyze = live_module.analyze_live_development

    def capture_analysis(
        traces: object,
        output_dir: object,
        *,
        requested_model_ids: object,
        hard_qa_attestation: object,
        raw_archive_audit: object,
    ) -> dict[str, object]:
        trace_tuple = tuple(traces)  # type: ignore[arg-type]
        captured.append(trace_tuple)
        return real_analyze(
            trace_tuple,
            output_dir,
            requested_model_ids=requested_model_ids,  # type: ignore[arg-type]
            hard_qa_attestation=hard_qa_attestation,  # type: ignore[arg-type]
            raw_archive_audit=raw_archive_audit,  # type: ignore[arg-type]
        )

    monkeypatch.setattr(live_module, "analyze_live_development", capture_analysis)
    output_dir = tmp_path / "private-live"
    models = ("model-alpha-2026-08-01", "model-beta-2026-08-01")
    report = _run_live_development_for_test(
        scenarios=load_scenarios(),
        model_ids=models,
        output_dir=output_dir,
        provenance_signing_key=b"k" * 32,
        provenance_key_id="test-live-key-v1",
        backend_factory=_backend_factory,
        repository_freeze_override=TEST_FREEZE,
    )

    assert len(captured) == 1
    traces = captured[0]
    assert len(traces) == EXPECTED_RUNS == 192
    assert Counter(trace.model_id for trace in traces) == {
        models[0]: 96,
        models[1]: 96,
    }
    assert len({trace.run_id for trace in traces}) == EXPECTED_RUNS
    assert sum(len(trace.steps) for trace in traces) <= MAX_AGENT_CALLS == 768

    pairs: dict[tuple[object, ...], set[bool]] = defaultdict(set)
    for trace in traces:
        pairs[
            (
                trace.model_id,
                trace.scenario_id,
                trace.mechanism,
                trace.safety_variant,
                trace.invocation_id,
                trace.seed,
            )
        ].add(trace.mechanism_active)
    assert len(pairs) == 2 * 2 * 4 * 2 * 3 == 96
    assert set(map(frozenset, pairs.values())) == {frozenset({False, True})}
    model_matrices = {
        model_id: {
            (
                trace.scenario_id,
                trace.mechanism,
                trace.safety_variant,
                trace.invocation_id,
                trace.seed,
                trace.mechanism_active,
            )
            for trace in traces
            if trace.model_id == model_id
        }
        for model_id in models
    }
    assert model_matrices[models[0]] == model_matrices[models[1]]

    assert report["decision"] == "TEST_ONLY"
    assert report["empirical_claim_status"] == "test_only_non_empirical"
    assert report["all_evaluated_checks_pass"] is True
    assert all(gate["pass"] for gate in report["gates"].values())
    assert report["counts"]["workflow_runs"] == EXPECTED_RUNS
    assert report["counts"]["agent_calls"] <= MAX_AGENT_CALLS

    manifest_path = output_dir / "model_call_manifest.json"
    trace_path = output_dir / "traces.jsonl"
    manifest = json.loads(manifest_path.read_text())
    assert manifest["state"] == "completed"
    assert manifest["workflow_runs_completed"] == EXPECTED_RUNS
    assert manifest["agent_calls_completed"] == report["counts"]["agent_calls"]
    assert manifest["matrix"]["expected_workflow_runs"] == EXPECTED_RUNS
    assert manifest["matrix"]["maximum_agent_calls"] == MAX_AGENT_CALLS
    assert manifest["repository_freeze"] == TEST_FREEZE
    assert len(trace_path.read_text().splitlines()) == EXPECTED_RUNS
    assert stat.S_IMODE(output_dir.stat().st_mode) & 0o077 == 0
    assert stat.S_IMODE(manifest_path.stat().st_mode) & 0o077 == 0
    assert stat.S_IMODE(trace_path.stat().st_mode) & 0o077 == 0

    for artifact in (
        "runs.csv",
        "arm_metrics.csv",
        "mechanism_effects.csv",
        "micro_pilot_report.json",
        "micro_pilot_report.md",
    ):
        artifact_path = output_dir / artifact
        assert artifact_path.is_file()
        assert stat.S_IMODE(artifact_path.stat().st_mode) & 0o077 == 0

    with (output_dir / "mechanism_effects.csv").open(newline="") as handle:
        effect_rows = list(csv.DictReader(handle))
    assert Counter(row["scope"] for row in effect_rows) == {
        "workflow_repetition": 48,
        "model": 8,
        "pooled": 4,
    }
    assert {
        int(row["repetition"])
        for row in effect_rows
        if row["scope"] == "workflow_repetition"
    } == {1, 2, 3}

    with (output_dir / "runs.csv").open(newline="") as handle:
        run_rows = list(csv.DictReader(handle))
    assert {int(row["scheduled_workflow_run_order"]) for row in run_rows} == set(
        range(1, EXPECTED_RUNS + 1)
    )
    for model_id in models:
        assert {
            int(row["model_workflow_run_order"])
            for row in run_rows
            if row["model_id"] == model_id
        } == set(range(1, EXPECTED_RUNS // 2 + 1))

    broken_report = analyze_live_development(
        traces[:-1],
        tmp_path / "broken-matrix",
        requested_model_ids=models,
    )
    assert broken_report["decision"] == "NO_GO"
    assert broken_report["gates"]["design_complete"]["pass"] is False
    assert (
        broken_report["gates"]["design_complete"]["checks"]["on_off_pairs"]
        is False
    )

    mismatched = deepcopy(traces)
    target = next(trace for trace in mismatched if trace.model_id == models[1])
    target_key = (
        target.model_id,
        target.scenario_id,
        target.mechanism,
        target.safety_variant,
        target.invocation_id,
        target.seed,
    )
    for trace in mismatched:
        if (
            trace.model_id,
            trace.scenario_id,
            trace.mechanism,
            trace.safety_variant,
            trace.invocation_id,
            trace.seed,
        ) == target_key:
            trace.invocation_id += "-different-model-matrix"
    mismatch_report = analyze_live_development(
        mismatched,
        tmp_path / "mismatched-model-matrix",
        requested_model_ids=models,
    )
    design_checks = mismatch_report["gates"]["design_complete"]["checks"]
    assert design_checks["on_off_pairs"] is True
    assert design_checks["cross_model_matrix_frozen"] is False


def test_live_batch_checkpoints_an_abort_without_recording_exception_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FailingRunner:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def run(self, spec: object) -> object:
            del spec
            raise RuntimeError("sensitive provider error body")

    monkeypatch.setattr(live_module, "ExperimentRunner", FailingRunner)
    output_dir = tmp_path / "aborted-live"

    with pytest.raises(RuntimeError, match="sensitive provider error body"):
        _run_live_development_for_test(
            scenarios=load_scenarios(),
            model_ids=("model-alpha-2026-08-01", "model-beta-2026-08-01"),
            output_dir=output_dir,
            provenance_signing_key=b"k" * 32,
            provenance_key_id="test-live-key-v1",
            backend_factory=_backend_factory,
            repository_freeze_override=TEST_FREEZE,
        )

    manifest_path = output_dir / "model_call_manifest.json"
    manifest_text = manifest_path.read_text()
    manifest = json.loads(manifest_text)
    assert manifest["state"] == "aborted"
    assert manifest["workflow_runs_completed"] == 0
    assert manifest["agent_calls_completed"] == 0
    assert manifest["abort_error_type"] == "RuntimeError"
    assert "sensitive provider error body" not in manifest_text
    assert not (output_dir / "traces.jsonl").exists()
    assert stat.S_IMODE(manifest_path.stat().st_mode) & 0o077 == 0


def test_live_batch_refuses_to_overwrite_an_existing_checkpoint(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "existing-live"
    output_dir.mkdir()
    trace_path = output_dir / "traces.jsonl"
    trace_path.write_text("existing checkpoint\n")

    with pytest.raises(FileExistsError, match="Refusing to reuse"):
        _run_live_development_for_test(
            scenarios=load_scenarios(),
            model_ids=("model-alpha-2026-08-01", "model-beta-2026-08-01"),
            output_dir=output_dir,
            provenance_signing_key=b"k" * 32,
            provenance_key_id="test-live-key-v1",
            backend_factory=_backend_factory,
            repository_freeze_override=TEST_FREEZE,
        )
    assert trace_path.read_text() == "existing checkpoint\n"

    unrelated_output = tmp_path / "existing-derivatives"
    unrelated_output.mkdir()
    derivative = unrelated_output / "runs.csv"
    derivative.write_text("prior derivative\n")
    with pytest.raises(FileExistsError, match="Refusing to reuse"):
        _run_live_development_for_test(
            scenarios=load_scenarios(),
            model_ids=("model-alpha-2026-08-01", "model-beta-2026-08-01"),
            output_dir=unrelated_output,
            provenance_signing_key=b"k" * 32,
            provenance_key_id="test-live-key-v1",
            backend_factory=_backend_factory,
            repository_freeze_override=TEST_FREEZE,
        )
    assert derivative.read_text() == "prior derivative\n"

    empty_output = tmp_path / "existing-empty-live"
    empty_output.mkdir()
    with pytest.raises(FileExistsError, match="Refusing to reuse"):
        _run_live_development_for_test(
            scenarios=load_scenarios(),
            model_ids=("model-alpha-2026-08-01", "model-beta-2026-08-01"),
            output_dir=empty_output,
            provenance_signing_key=b"k" * 32,
            provenance_key_id="test-live-key-v1",
            backend_factory=_backend_factory,
            repository_freeze_override=TEST_FREEZE,
        )
    assert list(empty_output.iterdir()) == []


def test_live_batch_requires_snapshot_ids_and_private_repository_output(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="immutable YYYY-MM-DD snapshot"):
        _run_live_development_for_test(
            scenarios=load_scenarios(),
            model_ids=("mutable-model-latest", "other-model-latest"),
            output_dir=tmp_path / "mutable-models",
            provenance_signing_key=b"k" * 32,
            provenance_key_id="test-live-key-v1",
            backend_factory=_backend_factory,
            repository_freeze_override=TEST_FREEZE,
        )

    tracked_candidate = Path("live-output-test-never-created")
    assert not tracked_candidate.exists()
    with pytest.raises(ValueError, match="outputs/private"):
        _run_live_development_for_test(
            scenarios=load_scenarios(),
            model_ids=("model-alpha-2026-08-01", "model-beta-2026-08-01"),
            output_dir=tracked_candidate,
            provenance_signing_key=b"k" * 32,
            provenance_key_id="test-live-key-v1",
            backend_factory=_backend_factory,
            repository_freeze_override=TEST_FREEZE,
        )
    assert not tracked_candidate.exists()


def test_stage_one_rejects_nonpreregistered_scenario_identity() -> None:
    scenarios = list(load_scenarios())
    scenarios[0] = replace(scenarios[0], scenario_id="custom.unregistered_workflow")

    with pytest.raises(ValueError, match="exactly the two preregistered"):
        live_development_specs(scenarios)


def test_production_freeze_is_rechecked_after_hard_qa_before_provider_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    changed_freeze = {**TEST_FREEZE, "commit_sha": "e" * 40}
    freeze_values = iter((TEST_FREEZE, changed_freeze))
    provider_client_constructed = False

    def fail_if_constructed(
        _model_id: str, _raw_log_dir: Path
    ) -> StructuredOracleBackend:
        nonlocal provider_client_constructed
        provider_client_constructed = True
        raise AssertionError("provider client must not be constructed")

    monkeypatch.setattr(
        live_module, "_repository_freeze_metadata", lambda: next(freeze_values)
    )
    monkeypatch.setattr(
        live_module,
        "_run_hard_qa_attestation",
        lambda _freeze: {"required": True, "pass": True},
    )
    monkeypatch.setattr(live_module, "_default_backend_factory", fail_if_constructed)

    with pytest.raises(RuntimeError, match="during the hard-QA preflight"):
        live_module.run_live_development(
            scenarios=load_scenarios(),
            model_ids=("model-alpha-2026-08-01", "model-beta-2026-08-01"),
            output_dir=tmp_path / "never-created",
            provenance_signing_key=b"k" * 32,
            provenance_key_id="test-live-key-v1",
        )

    assert provider_client_constructed is False
    assert not (tmp_path / "never-created").exists()


def test_finalization_freeze_failure_invalidates_standalone_gate_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    changed_freeze = {**TEST_FREEZE, "protocol_sha256": "e" * 64}
    freeze_values = iter((TEST_FREEZE, TEST_FREEZE, TEST_FREEZE, changed_freeze))
    real_specs = live_module.live_development_specs

    def one_spec(
        scenarios: object, *, batch_id: str, repetitions: int = EXPECTED_REPETITIONS
    ) -> list[object]:
        return [
            real_specs(
                scenarios,  # type: ignore[arg-type]
                batch_id=batch_id,
                repetitions=repetitions,
            )[0]
        ]

    monkeypatch.setattr(
        live_module, "_repository_freeze_metadata", lambda: next(freeze_values)
    )
    monkeypatch.setattr(
        live_module,
        "_run_hard_qa_attestation",
        lambda _freeze: {"required": True, "pass": True},
    )
    monkeypatch.setattr(live_module, "_default_backend_factory", _backend_factory)
    monkeypatch.setattr(live_module, "live_development_specs", one_spec)
    monkeypatch.setattr(
        live_module,
        "_raw_archive_audit",
        lambda *_args, **_kwargs: {"required": True, "pass": True, "checks": {}},
    )
    output_dir = tmp_path / "finalization-abort"

    with pytest.raises(RuntimeError, match="during live-batch finalization"):
        live_module.run_live_development(
            scenarios=load_scenarios(),
            model_ids=("model-alpha-2026-08-01", "model-beta-2026-08-01"),
            output_dir=output_dir,
            provenance_signing_key=b"k" * 32,
            provenance_key_id="test-live-key-v1",
        )

    manifest = json.loads((output_dir / "model_call_manifest.json").read_text())
    report = json.loads((output_dir / "micro_pilot_report.json").read_text())
    assert manifest["state"] == "aborted"
    assert manifest["analysis_artifacts_invalidated"] is True
    assert report["decision"] == "ABORTED"
    assert report["prior_analysis_must_not_be_used"] is True
    assert "**ABORTED**" in (output_dir / "micro_pilot_report.md").read_text()
