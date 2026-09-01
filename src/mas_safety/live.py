from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Callable, Iterable, Sequence
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree

from .backends import AgentBackend
from .enums import Architecture, DecisionMode, Defense, Mechanism, SafetyVariant
from .live_analysis import EXPECTED_REPETITIONS, EXPECTED_RUNS, analyze_live_development
from .live_backends import OpenAIResponsesBackend
from .models import RunTrace, Scenario
from .runner import ExperimentRunner, RunSpec, frozen_program_hashes
from .scenarios import load_scenarios

BackendFactory = Callable[[str, Path], AgentBackend]
_SNAPSHOT_DATE = re.compile(
    r"(?:19|20)\d{2}[-_](?:0[1-9]|1[0-2])[-_](?:0[1-9]|[12]\d|3[01])"
)
DEVELOPMENT_SCENARIO_IDS = frozenset(
    {
        "healthcare.patient_summary_disclosure",
        "finance.unapproved_payment",
    }
)
HARD_QA_EXPECTED_TESTS = 107  # Updated only when the frozen release suite changes.
HARD_QA_SENTINEL_NAME = "test_hard_qa_sentinel"


def live_development_specs(
    scenarios: Iterable[Scenario],
    *,
    repetitions: int = EXPECTED_REPETITIONS,
    batch_id: str = "stage1-development-template",
) -> list[RunSpec]:
    """Return one model's paired Stage 1 local-only development matrix."""

    scenario_items = sorted(scenarios, key=lambda item: item.scenario_id)
    scenario_ids = {item.scenario_id for item in scenario_items}
    if (
        len(scenario_items) != 2
        or len(scenario_ids) != 2
        or scenario_ids != DEVELOPMENT_SCENARIO_IDS
    ):
        raise ValueError(
            "Stage 1 requires exactly the two preregistered development workflows"
        )
    if not batch_id.strip():
        raise ValueError("Stage 1 batch_id must be non-empty")
    if repetitions != EXPECTED_REPETITIONS:
        raise ValueError(
            f"Stage 1 is frozen at {EXPECTED_REPETITIONS} repetitions per cell"
        )

    specs: list[RunSpec] = []
    for repetition in range(1, repetitions + 1):
        for scenario in scenario_items:
            for mechanism in Mechanism:
                for safety_variant in SafetyVariant:
                    pair_material = (
                        f"v0.2-live|{scenario.scenario_id}|{mechanism.value}|"
                        f"{safety_variant.value}|{repetition}"
                    )
                    digest = hashlib.sha256(pair_material.encode()).hexdigest()
                    seed = int(digest[:8], 16) & 0x7FFFFFFF
                    invocation_id = f"stage1-r{repetition:02d}-{digest[8:20]}"
                    assignments = (False, True) if seed % 2 == 0 else (True, False)
                    for active in assignments:
                        specs.append(
                            RunSpec(
                                scenario_id=scenario.scenario_id,
                                mechanism=mechanism,
                                defense=Defense.LOCAL_ONLY,
                                safety_variant=safety_variant,
                                architecture=Architecture.MULTI_AGENT,
                                mechanism_active=active,
                                cohort="mechanism_on" if active else "mechanism_off",
                                seed=seed,
                                invocation_id=invocation_id,
                                batch_id=batch_id,
                                decision_mode=DecisionMode.EXECUTION_DECISION,
                            )
                        )
    expected_per_model = EXPECTED_RUNS // 2
    if len(specs) != expected_per_model:
        raise AssertionError(
            f"Stage 1 generator produced {len(specs)} specs, expected {expected_per_model}"
        )
    return specs


def run_live_development(
    *,
    scenarios: Sequence[Scenario],
    model_ids: Sequence[str],
    output_dir: str | Path,
    provenance_signing_key: bytes,
    provenance_key_id: str,
) -> dict[str, object]:
    """Run the production Stage 1 path with no injectable provider bypasses."""

    return _run_live_development_impl(
        scenarios=scenarios,
        model_ids=model_ids,
        output_dir=output_dir,
        provenance_signing_key=provenance_signing_key,
        provenance_key_id=provenance_key_id,
        backend_factory=None,
        repository_freeze_override=None,
        test_mode=False,
    )


def _run_live_development_for_test(
    *,
    scenarios: Sequence[Scenario],
    model_ids: Sequence[str],
    output_dir: str | Path,
    provenance_signing_key: bytes,
    provenance_key_id: str,
    backend_factory: BackendFactory,
    repository_freeze_override: dict[str, object],
) -> dict[str, object]:
    """Exercise orchestration without an empirical GO; for repository tests only."""

    return _run_live_development_impl(
        scenarios=scenarios,
        model_ids=model_ids,
        output_dir=output_dir,
        provenance_signing_key=provenance_signing_key,
        provenance_key_id=provenance_key_id,
        backend_factory=backend_factory,
        repository_freeze_override=repository_freeze_override,
        test_mode=True,
    )


def _run_live_development_impl(
    *,
    scenarios: Sequence[Scenario],
    model_ids: Sequence[str],
    output_dir: str | Path,
    provenance_signing_key: bytes,
    provenance_key_id: str,
    backend_factory: BackendFactory | None,
    repository_freeze_override: dict[str, object] | None,
    test_mode: bool,
) -> dict[str, object]:
    """Execute and checkpoint the complete two-model Stage 1 matrix.

    The output directory is private by design because traces contain raw model
    outputs and the sibling ``raw_responses`` tree contains full prompts and API
    responses. Share only reviewed, redacted derivatives.
    """

    models = tuple(model_ids)
    if len(models) != 2 or len(set(models)) != 2 or any(not item.strip() for item in models):
        raise ValueError("Provide exactly two distinct, non-empty model IDs")
    if any(_SNAPSHOT_DATE.search(item) is None for item in models):
        raise ValueError(
            "Each live model ID must contain an immutable YYYY-MM-DD snapshot date"
        )
    if len(provenance_signing_key) < 32:
        raise ValueError("Live provenance signing key must contain at least 32 bytes")
    if not provenance_key_id.strip() or provenance_key_id.startswith("development"):
        raise ValueError("Live provenance key ID must be explicit and non-development")

    # Freeze a defensive snapshot of the exact preregistered scenario objects.
    frozen_scenarios = tuple(deepcopy(tuple(scenarios)))
    frozen_scenario_hashes = _scenario_hashes(frozen_scenarios)
    if set(frozen_scenario_hashes) != DEVELOPMENT_SCENARIO_IDS:
        raise ValueError(
            "Stage 1 requires exactly the two preregistered development workflows"
        )

    destination = Path(output_dir)
    _assert_private_output_destination(destination)
    if test_mode is not (backend_factory is not None):
        raise AssertionError("Backend injection must match the internal test mode")
    if test_mode is not (repository_freeze_override is not None):
        raise AssertionError("Freeze override must match the internal test mode")
    injected_test_backend = test_mode
    repository_freeze = (
        _validated_freeze_override(repository_freeze_override)
        if repository_freeze_override is not None
        else _repository_freeze_metadata()
    )
    if not injected_test_backend:
        repository_root = _git_repository_root(required=True)
        assert repository_root is not None
        committed_scenario_hashes = _scenario_hashes(
            tuple(load_scenarios(repository_root / "scenarios"))
        )
        if frozen_scenario_hashes != committed_scenario_hashes:
            raise RuntimeError(
                "Live scenarios differ from the preregistered repository fixtures"
            )
    hard_qa_attestation = (
        {
            "required": False,
            "pass": True,
            "reason": "injected_test_backend",
            "commit_sha": repository_freeze["commit_sha"],
        }
        if injected_test_backend
        else _run_hard_qa_attestation(repository_freeze)
    )
    if not injected_test_backend:
        _assert_repository_freeze_unchanged(
            repository_freeze,
            context="during the hard-QA preflight",
        )
    frozen_components = frozen_program_hashes()
    batch_id = _new_batch_id()
    trace_path = destination / "traces.jsonl"
    manifest_path = destination / "model_call_manifest.json"
    if destination.exists():
        raise FileExistsError(
            "Refusing to reuse a live output path; choose a new batch directory"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir(exist_ok=False, mode=0o700)
    try:
        destination.chmod(0o700)
    except OSError:
        pass

    specs = live_development_specs(frozen_scenarios, batch_id=batch_id)
    factory = backend_factory or _default_backend_factory
    backends = [
        factory(model_id, destination / "raw_responses" / f"model-{index:02d}")
        for index, model_id in enumerate(models, start=1)
    ]
    if injected_test_backend and any(
        getattr(backend, "configuration", {}).get("test_only_no_external_io")
        is not True
        for backend in backends
    ):
        raise ValueError(
            "The internal injected-backend path accepts only explicitly marked "
            "no-external-I/O test doubles"
        )
    runners = [
        ExperimentRunner(
            frozen_scenarios,
            backend,
            provenance_signing_key=provenance_signing_key,
            provenance_key_id=provenance_key_id,
        )
        for backend in backends
    ]
    started_at = _utc_now()
    manifest: dict[str, object] = {
        "schema_version": "0.2.0",
        "stage": "stage_1_local_only_live_micro_pilot",
        "state": "running",
        "started_at_utc": started_at,
        "completed_at_utc": None,
        "batch_id": batch_id,
        "execution_mode": (
            "injected_test_backend" if injected_test_backend else "default_live_backend"
        ),
        "requested_model_ids": list(models),
        "backend_configurations": [dict(backend.configuration) for backend in backends],
        "matrix": {
            "workflows": 2,
            "mechanisms": len(Mechanism),
            "assignments": 2,
            "safety_variants": len(SafetyVariant),
            "repetitions": EXPECTED_REPETITIONS,
            "models": 2,
            "expected_workflow_runs": EXPECTED_RUNS,
            "maximum_agent_calls": EXPECTED_RUNS * 4,
            "defense": Defense.LOCAL_ONLY.value,
            "architecture": Architecture.MULTI_AGENT.value,
            "decision_mode": DecisionMode.EXECUTION_DECISION.value,
        },
        "run_spec_sha256": _spec_hash(specs),
        "repository_freeze": repository_freeze,
        "hard_qa_attestation": hard_qa_attestation,
        "frozen_component_hashes": frozen_components,
        "frozen_scenario_hashes": frozen_scenario_hashes,
        "scenario_source": (
            "injected_test_objects"
            if injected_test_backend
            else "preregistered_repository_fixtures"
        ),
        "provenance_key_id": provenance_key_id,
        "provenance_key_material_recorded": False,
        "raw_data": {
            "location": "raw_responses/ (private; gitignored by repository policy)",
            "contains_full_prompts_and_responses": True,
            "review_before_sharing": True,
        },
        "retry_policy": {
            "sdk_max_retries": 0,
            "application_retries": 0,
            "per_call_timeout_seconds": 120.0,
        },
        "workflow_runs_completed": 0,
        "agent_calls_completed": 0,
    }
    _write_private_json(manifest_path, manifest)

    traces: list[RunTrace] = []
    model_run_counts = [0, 0]
    try:
        for spec_index, spec in enumerate(specs):
            # Counterbalance which provider is sampled first across adjacent cells.
            runner_order = (0, 1) if (spec_index + spec.seed) % 2 == 0 else (1, 0)
            for runner_index in runner_order:
                model_run_counts[runner_index] += 1
                set_run_metadata = getattr(backends[runner_index], "set_run_metadata", None)
                if callable(set_run_metadata):
                    set_run_metadata(
                        {
                            "scheduled_workflow_run_order": len(traces) + 1,
                            "model_workflow_run_order": model_run_counts[runner_index],
                            "repetition": _repetition_from(spec),
                            "condition_id": spec.condition_id,
                            "invocation_id": spec.invocation_id,
                            "scenario_id": spec.scenario_id,
                            "mechanism": spec.mechanism.value,
                            "mechanism_active": spec.mechanism_active,
                            "safety_variant": spec.safety_variant.value,
                            "protocol_commit_sha": repository_freeze["commit_sha"],
                            "protocol_sha256": repository_freeze["protocol_sha256"],
                            "batch_id": batch_id,
                        }
                    )
                trace = runners[runner_index].run(spec)
                _assert_trace_matches_freeze(
                    trace,
                    batch_id=batch_id,
                    frozen_components=frozen_components,
                    frozen_scenario_hashes=frozen_scenario_hashes,
                )
                traces.append(trace)
                _append_private_trace(trace_path, trace)
                manifest["workflow_runs_completed"] = len(traces)
                manifest["agent_calls_completed"] = sum(
                    len(item.steps) for item in traces
                )
                _write_private_json(manifest_path, manifest)
    except BaseException as exc:
        manifest.update(
            {
                "state": "aborted",
                "completed_at_utc": _utc_now(),
                "abort_error_type": type(exc).__name__,
            }
        )
        _write_private_json(manifest_path, manifest)
        abort_analysis_error_type: str | None = None
        if traces:
            try:
                raw_archive_audit = _raw_archive_audit(
                    destination,
                    traces,
                    models,
                    repository_freeze=repository_freeze,
                    required=not injected_test_backend,
                )
                analyze_live_development(
                    traces,
                    destination,
                    requested_model_ids=models,
                    hard_qa_attestation=hard_qa_attestation,
                    raw_archive_audit=raw_archive_audit,
                )
            except BaseException as analysis_exc:  # noqa: BLE001
                # Partial-batch analysis is best-effort and must never replace the
                # original provider/runtime failure being re-raised below.
                abort_analysis_error_type = type(analysis_exc).__name__
        analysis_artifacts_invalidated = _invalidate_live_analysis_report(
            destination,
            abort_error_type=type(exc).__name__,
        )
        manifest["analysis_artifacts_invalidated"] = analysis_artifacts_invalidated
        if abort_analysis_error_type is not None:
            manifest["abort_analysis_error_type"] = abort_analysis_error_type
        _write_private_json(manifest_path, manifest)
        raise

    try:
        if not injected_test_backend:
            _assert_repository_freeze_unchanged(
                repository_freeze,
                context="during the live batch",
            )
        if frozen_program_hashes() != frozen_components:
            raise RuntimeError(
                "A frozen program or schema component changed during the live batch"
            )
        if _scenario_hashes(frozen_scenarios) != frozen_scenario_hashes:
            raise RuntimeError("A frozen scenario object changed during the live batch")

        raw_archive_audit = _raw_archive_audit(
            destination,
            traces,
            models,
            repository_freeze=repository_freeze,
            required=not injected_test_backend,
        )
        report = analyze_live_development(
            traces,
            destination,
            requested_model_ids=models,
            hard_qa_attestation=hard_qa_attestation,
            raw_archive_audit=raw_archive_audit,
        )
        if not injected_test_backend:
            _assert_repository_freeze_unchanged(
                repository_freeze,
                context="during live-batch finalization",
            )
        if frozen_program_hashes() != frozen_components:
            raise RuntimeError(
                "A frozen program or schema component changed during finalization"
            )
        if _scenario_hashes(frozen_scenarios) != frozen_scenario_hashes:
            raise RuntimeError(
                "A frozen scenario object changed during live-batch finalization"
            )
        component_hash_sets = {
            json.dumps(trace.component_hashes, sort_keys=True) for trace in traces
        }
        manifest.update(
            {
                "state": "completed",
                "completed_at_utc": _utc_now(),
                "workflow_runs_completed": len(traces),
                "agent_calls_completed": sum(len(trace.steps) for trace in traces),
                "resolved_response_models": sorted(
                    {
                        str(step.provider_metadata["resolved_response_model"])
                        for trace in traces
                        for step in trace.steps
                        if step.provider_metadata.get("resolved_response_model")
                    }
                ),
                "component_hash_sets": [
                    json.loads(item) for item in sorted(component_hash_sets)
                ],
                "raw_archive_audit": raw_archive_audit,
                "trace_file_sha256": raw_archive_audit.get("trace_file_sha256"),
                "development_gate_decision": report["decision"],
            }
        )
        _write_private_json(manifest_path, manifest)
        return report
    except BaseException as exc:
        analysis_artifacts_invalidated = _invalidate_live_analysis_report(
            destination,
            abort_error_type=type(exc).__name__,
        )
        manifest.update(
            {
                "state": "aborted",
                "completed_at_utc": _utc_now(),
                "abort_error_type": type(exc).__name__,
                "analysis_artifacts_invalidated": analysis_artifacts_invalidated,
            }
        )
        _write_private_json(manifest_path, manifest)
        raise


def _default_backend_factory(model_id: str, raw_log_dir: Path) -> AgentBackend:
    return OpenAIResponsesBackend(model_id=model_id, raw_log_dir=raw_log_dir)


def _spec_hash(specs: Sequence[RunSpec]) -> str:
    payload = [
        {
            "condition_id": spec.condition_id,
            "seed": spec.seed,
            "invocation_id": spec.invocation_id,
        }
        for spec in specs
    ]
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _new_batch_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"stage1-{timestamp}-{uuid.uuid4().hex[:12]}"


def _scenario_hashes(scenarios: Sequence[Scenario]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for scenario in scenarios:
        if scenario.scenario_id in hashes:
            raise ValueError("Stage 1 scenario identifiers must be unique")
        canonical = json.dumps(
            asdict(scenario), sort_keys=True, separators=(",", ":"), default=str
        )
        hashes[scenario.scenario_id] = (
            "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        )
    return dict(sorted(hashes.items()))


def _assert_trace_matches_freeze(
    trace: RunTrace,
    *,
    batch_id: str,
    frozen_components: dict[str, object],
    frozen_scenario_hashes: dict[str, str],
) -> None:
    if trace.batch_id != batch_id:
        raise RuntimeError("Trace batch identity differs from the frozen live batch")
    expected_scenario_hash = frozen_scenario_hashes.get(trace.scenario_id)
    if trace.component_hashes.get("scenario") != expected_scenario_hash:
        raise RuntimeError("Trace scenario content differs from the frozen snapshot")
    if any(
        trace.component_hashes.get(key) != value
        for key, value in frozen_components.items()
    ):
        raise RuntimeError("Trace program/schema hashes differ from the batch preflight")


def _run_hard_qa_attestation(
    repository_freeze: dict[str, object],
) -> dict[str, object]:
    repository_root = _git_repository_root(required=True)
    assert repository_root is not None
    started_at = _utc_now()
    with tempfile.TemporaryDirectory(prefix="mas-safety-hard-qa-") as qa_temp:
        qa_temp_path = Path(qa_temp)
        junit_path = qa_temp_path / "pytest-report.xml"
        qa_home = qa_temp_path / "home"
        qa_home.mkdir(mode=0o700)
        qa_environment = {
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "LANG", "LC_ALL", "TMPDIR", "TZ", "SYSTEMROOT"}
        }
        qa_environment.update(
            {
                "HOME": str(qa_home),
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            }
        )
        command = (
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests",
            "--override-ini=addopts=",
            "-p",
            "no:cacheprovider",
            f"--junitxml={junit_path}",
        )
        try:
            process = subprocess.run(
                command,
                cwd=repository_root,
                env=qa_environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                "Frozen hard-QA test suite exceeded its 300-second limit"
            ) from exc
        try:
            test_cases = ElementTree.parse(junit_path).findall(".//testcase")
        except (OSError, ElementTree.ParseError) as exc:
            raise RuntimeError(
                "Frozen hard-QA suite did not produce a valid execution report"
            ) from exc
        executed_test_count = len(test_cases)
        sentinel_executed = any(
            case.attrib.get("name") == HARD_QA_SENTINEL_NAME for case in test_cases
        )
    completed_at = _utc_now()
    captured = f"{process.stdout}\n{process.stderr}"
    passed = (
        process.returncode == 0
        and executed_test_count == HARD_QA_EXPECTED_TESTS
        and sentinel_executed
    )
    attestation = {
        "required": True,
        "pass": passed,
        "command": [
            "python",
            "-m",
            "pytest",
            "-q",
            "tests",
            "--override-ini=addopts=",
            "-p",
            "no:cacheprovider",
            "--junitxml=<private-temporary-path>",
        ],
        "commit_sha": repository_freeze["commit_sha"],
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "return_code": process.returncode,
        "expected_test_count": HARD_QA_EXPECTED_TESTS,
        "executed_test_count": executed_test_count,
        "sentinel_executed": sentinel_executed,
        "ambient_pytest_controls_removed": True,
        "plugin_autoload_disabled": True,
        "captured_output_sha256": hashlib.sha256(
            captured.encode("utf-8")
        ).hexdigest(),
    }
    if not passed:
        raise RuntimeError(
            "Frozen hard-QA assertions, exact test count, or execution sentinel "
            "failed; no live provider client was created"
        )
    return attestation


def _assert_repository_freeze_unchanged(
    repository_freeze: dict[str, object], *, context: str
) -> None:
    if _repository_freeze_metadata() != repository_freeze:
        raise RuntimeError(
            f"Repository commit, worktree, or protocol hash changed {context}"
        )


def _raw_archive_audit(
    destination: Path,
    traces: Sequence[RunTrace],
    model_ids: Sequence[str],
    *,
    repository_freeze: dict[str, object],
    required: bool,
) -> dict[str, object]:
    if not required:
        return {
            "required": False,
            "pass": True,
            "reason": "injected_test_backend",
            "checks": {"explicit_test_exemption": True},
        }

    checks = {
        "model_directories_present": True,
        "every_step_has_unique_raw_link": True,
        "request_set_matches_trace_links": True,
        "one_response_or_error_per_request": True,
        "response_error_kind_matches_trace": True,
        "request_hashes_recompute_and_match_trace": True,
        "result_records_parse_hash_and_match_trace": True,
        "no_orphan_or_unexpected_records": True,
        "private_file_permissions": True,
        "persisted_trace_matches_memory": True,
    }
    request_count = 0
    response_count = 0
    error_count = 0
    expected_call_count = sum(len(trace.steps) for trace in traces)
    trace_path = destination / "traces.jsonl"
    trace_file_sha256: str | None = None
    try:
        trace_bytes = trace_path.read_bytes()
        trace_file_sha256 = hashlib.sha256(trace_bytes).hexdigest()
        persisted_traces = [
            json.loads(line)
            for line in trace_bytes.decode("utf-8").splitlines()
            if line.strip()
        ]
        if persisted_traces != [trace.to_dict() for trace in traces]:
            checks["persisted_trace_matches_memory"] = False
        if trace_path.stat().st_mode & 0o077:
            checks["private_file_permissions"] = False
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        checks["persisted_trace_matches_memory"] = False
    scheduled_orders = {
        trace.run_id: index for index, trace in enumerate(traces, start=1)
    }
    model_orders = {
        trace.run_id: index
        for model_id in model_ids
        for index, trace in enumerate(
            (item for item in traces if item.model_id == model_id), start=1
        )
    }

    for model_index, model_id in enumerate(model_ids, start=1):
        raw_dir = destination / "raw_responses" / f"model-{model_index:02d}"
        if not raw_dir.is_dir():
            checks["model_directories_present"] = False
            continue
        model_trace_steps = [
            (trace, step)
            for trace in traces
            if trace.model_id == model_id
            for step in trace.steps
        ]
        links = [
            step.provider_metadata.get("raw_log_record")
            for _trace, step in model_trace_steps
        ]
        string_links = [item for item in links if isinstance(item, str) and item]
        if len(string_links) != len(model_trace_steps) or len(
            set(string_links)
        ) != len(string_links):
            checks["every_step_has_unique_raw_link"] = False
        call_orders = [
            step.provider_metadata.get("call_order")
            for _trace, step in model_trace_steps
        ]
        if sorted(item for item in call_orders if isinstance(item, int)) != list(
            range(1, len(model_trace_steps) + 1)
        ):
            checks["request_hashes_recompute_and_match_trace"] = False

        files = [path for path in raw_dir.iterdir() if path.is_file()]
        requests = {
            path.name.removesuffix(".request.json"): path
            for path in files
            if path.name.endswith(".request.json")
        }
        responses = {
            path.name.removesuffix(".response.json"): path
            for path in files
            if path.name.endswith(".response.json")
        }
        errors = {
            path.name.removesuffix(".error.json"): path
            for path in files
            if path.name.endswith(".error.json")
        }
        request_count += len(requests)
        response_count += len(responses)
        error_count += len(errors)

        if set(requests) != set(string_links):
            checks["request_set_matches_trace_links"] = False
        if any((stem in responses) == (stem in errors) for stem in requests):
            checks["one_response_or_error_per_request"] = False
        if (set(responses) | set(errors)) != set(requests):
            checks["no_orphan_or_unexpected_records"] = False
        expected_names = {
            path.name for path in (*requests.values(), *responses.values(), *errors.values())
        }
        if {path.name for path in files} != expected_names:
            checks["no_orphan_or_unexpected_records"] = False
        if any(path.stat().st_mode & 0o077 for path in files):
            checks["private_file_permissions"] = False

        trace_step_by_link = {
            str(step.provider_metadata.get("raw_log_record")): (trace, step)
            for trace, step in model_trace_steps
            if isinstance(step.provider_metadata.get("raw_log_record"), str)
        }
        for stem, request_path in requests.items():
            trace_step = trace_step_by_link.get(stem)
            if trace_step is None:
                checks["request_hashes_recompute_and_match_trace"] = False
                continue
            trace, step = trace_step
            try:
                request_record = json.loads(request_path.read_text(encoding="utf-8"))
                provider_request = request_record["provider_request"]
                prompt = provider_request["input"]
                prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
                request_hash = hashlib.sha256(
                    json.dumps(
                        provider_request, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ).hexdigest()
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                checks["request_hashes_recompute_and_match_trace"] = False
                continue
            metadata = step.provider_metadata
            repetition_match = re.fullmatch(
                r"stage1-r(\d{2})-[0-9a-f]{12}", trace.invocation_id
            )
            expected_run_metadata = {
                "scheduled_workflow_run_order": scheduled_orders[trace.run_id],
                "model_workflow_run_order": model_orders[trace.run_id],
                "repetition": (
                    int(repetition_match.group(1)) if repetition_match else None
                ),
                "condition_id": trace.condition_id,
                "invocation_id": trace.invocation_id,
                "scenario_id": trace.scenario_id,
                "mechanism": trace.mechanism.value,
                "mechanism_active": trace.mechanism_active,
                "safety_variant": trace.safety_variant.value,
                "protocol_commit_sha": repository_freeze["commit_sha"],
                "protocol_sha256": repository_freeze["protocol_sha256"],
                "batch_id": trace.batch_id,
            }
            if not (
                request_record.get("record_version") == "0.2.0"
                and request_record.get("provider_call_order")
                == metadata.get("call_order")
                and request_record.get("local_pairing_seed")
                == trace.seed + step.step_index
                and request_record.get("prompt_sha256") == prompt_hash
                and request_record.get("provider_request_sha256") == request_hash
                and metadata.get("prompt_sha256") == prompt_hash
                and metadata.get("provider_request_sha256") == request_hash
                and metadata.get("request_record_sha256")
                == hashlib.sha256(request_path.read_bytes()).hexdigest()
                and request_record.get("run_metadata") == expected_run_metadata
                and all(
                    metadata.get(key) == value
                    for key, value in expected_run_metadata.items()
                )
                and metadata.get("local_pairing_seed")
                == trace.seed + step.step_index
            ):
                checks["request_hashes_recompute_and_match_trace"] = False
            model_response_received = metadata.get("model_response_received")
            if not (
                (
                    model_response_received is True
                    and stem in responses
                    and stem not in errors
                )
                or (
                    model_response_received is False
                    and stem in errors
                    and stem not in responses
                )
            ):
                checks["response_error_kind_matches_trace"] = False
            result_kind = metadata.get("result_record_kind")
            result_path = (
                responses.get(stem)
                if result_kind == "response"
                else errors.get(stem)
                if result_kind == "error"
                else None
            )
            if result_path is None:
                checks["result_records_parse_hash_and_match_trace"] = False
                continue
            try:
                result_record = json.loads(result_path.read_text(encoding="utf-8"))
            except (ValueError, json.JSONDecodeError):
                checks["result_records_parse_hash_and_match_trace"] = False
                continue
            if not (
                result_record.get("record_version") == "0.2.0"
                and metadata.get("result_record_sha256")
                == hashlib.sha256(result_path.read_bytes()).hexdigest()
            ):
                checks["result_records_parse_hash_and_match_trace"] = False
            if result_kind == "response":
                provider_response = result_record.get("provider_response")
                if not (
                    isinstance(provider_response, dict)
                    and result_record.get("transport_request_id")
                    == metadata.get("request_id")
                    and provider_response.get("id") == metadata.get("response_id")
                    and provider_response.get("model")
                    == metadata.get("resolved_response_model")
                    and provider_response.get("status") == metadata.get("status")
                ):
                    checks["result_records_parse_hash_and_match_trace"] = False
            else:
                provider_error_response = result_record.get("provider_error_response")
                if not (
                    result_record.get("error_type") == metadata.get("error_type")
                    and result_record.get("transport_request_id")
                    == metadata.get("request_id")
                    and (provider_error_response is not None)
                    is (metadata.get("response_received") is True)
                ):
                    checks["result_records_parse_hash_and_match_trace"] = False

    checks["request_set_matches_trace_links"] = bool(
        checks["request_set_matches_trace_links"]
        and request_count == expected_call_count
    )
    return {
        "required": True,
        "pass": all(checks.values()),
        "checks": checks,
        "expected_agent_calls": expected_call_count,
        "request_record_count": request_count,
        "response_record_count": response_count,
        "error_record_count": error_count,
        "trace_file_sha256": trace_file_sha256,
    }


def _repetition_from(spec: RunSpec) -> int:
    match = re.fullmatch(r"stage1-r(\d{2})-[0-9a-f]{12}", spec.invocation_id)
    if match is None:
        raise ValueError("Stage 1 invocation ID does not encode its repetition")
    repetition = int(match.group(1))
    if not 1 <= repetition <= EXPECTED_REPETITIONS:
        raise ValueError("Stage 1 invocation repetition is outside the frozen matrix")
    return repetition


def _assert_private_output_destination(destination: Path) -> None:
    repository_root = _git_repository_root(required=False)
    if repository_root is None:
        return
    resolved = destination.resolve()
    try:
        relative = resolved.relative_to(repository_root)
    except ValueError:
        return
    if len(relative.parts) < 3 or relative.parts[:2] != ("outputs", "private"):
        raise ValueError(
            "Live output inside the repository must be a batch-specific child of "
            "outputs/private/"
        )


def _repository_freeze_metadata() -> dict[str, object]:
    repository_root = _git_repository_root(required=True)
    assert repository_root is not None
    _assert_runtime_source_in_repository(repository_root)
    commit_sha = _git_output(repository_root, "rev-parse", "HEAD")
    status = _git_output(
        repository_root,
        "status",
        "--porcelain=v1",
        "--untracked-files=normal",
    )
    if status:
        raise RuntimeError(
            "Live execution requires a clean committed worktree; commit and review "
            "the frozen protocol before making provider calls"
        )
    protocol_path = repository_root / "protocols" / "v0.2-live.md"
    if not protocol_path.is_file():
        raise RuntimeError("Could not locate the frozen v0.2 protocol")
    return {
        "commit_sha": commit_sha,
        "working_tree_clean": True,
        "protocol_sha256": hashlib.sha256(protocol_path.read_bytes()).hexdigest(),
    }


def _assert_runtime_source_in_repository(repository_root: Path) -> None:
    expected_package = (repository_root / "src" / "mas_safety").resolve()
    imported_package = Path(__file__).resolve().parent
    if imported_package != expected_package:
        raise RuntimeError(
            "The imported mas_safety package is not the frozen repository checkout"
        )


def _validated_freeze_override(value: dict[str, object]) -> dict[str, object]:
    expected = {"commit_sha", "working_tree_clean", "protocol_sha256"}
    if set(value) != expected:
        raise ValueError("Repository freeze override has unexpected fields")
    if (
        not isinstance(value["commit_sha"], str)
        or re.fullmatch(r"[0-9a-f]{40,64}", value["commit_sha"]) is None
        or value["working_tree_clean"] is not True
        or not isinstance(value["protocol_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["protocol_sha256"]) is None
    ):
        raise ValueError("Repository freeze override is malformed or not clean")
    return dict(value)


def _git_repository_root(*, required: bool) -> Path | None:
    try:
        root = _git_output(Path.cwd(), "rev-parse", "--show-toplevel")
    except RuntimeError:
        if required:
            raise RuntimeError(
                "Live execution requires a Git checkout with a frozen commit"
            ) from None
        return None
    return Path(root).resolve()


def _git_output(cwd: Path, *arguments: str) -> str:
    process = subprocess.run(
        ("git", *arguments),
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if process.returncode != 0:
        raise RuntimeError(f"Git metadata command failed: {' '.join(arguments)}")
    return process.stdout.strip()


def _append_private_trace(path: Path, trace: RunTrace) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(trace.to_dict(), sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _write_private_json(path: Path, payload: object) -> None:
    _write_private_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _write_private_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _invalidate_live_analysis_report(
    destination: Path, *, abort_error_type: str
) -> bool:
    json_path = destination / "micro_pilot_report.json"
    markdown_path = destination / "micro_pilot_report.md"
    if not json_path.exists() and not markdown_path.exists():
        return False
    invalidated = {
        "schema_version": "0.2.0",
        "stage": "stage_1_local_only_live_micro_pilot",
        "decision": "ABORTED",
        "all_evaluated_checks_pass": False,
        "empirical_claim_status": "invalidated_by_batch_abort",
        "abort_error_type": abort_error_type,
        "prior_analysis_must_not_be_used": True,
    }
    try:
        _write_private_json(json_path, invalidated)
        _write_private_text(
            markdown_path,
            "# Stage 1 live micro-pilot report\n\n"
            "Decision: **ABORTED**\n\n"
            "The batch failed finalization integrity checks. Any earlier gate "
            "decision from this batch is invalid and must not be used.\n",
        )
    except OSError:
        return False
    return True


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
