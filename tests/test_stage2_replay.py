from __future__ import annotations

import csv
import hashlib
import inspect
import itertools
import json
import shutil
import stat
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from mas_safety.enums import (
    PIPELINE_ROLES,
    Architecture,
    DecisionMode,
    Defense,
    Mechanism,
    RunStatus,
    SafetyVariant,
)
from mas_safety.models import ActionSpec, AgentDecision, StageContext
from mas_safety.provenance import DEVELOPMENT_KEY_ID, DEVELOPMENT_SIGNING_KEY
from mas_safety.runner import ExperimentRunner, RunSpec, frozen_program_hashes
from mas_safety.scenarios import load_scenarios
from mas_safety.stage2_metrics import (
    DEFENSE_EFFECT_FIELDS,
    DEFENSE_INTERACTION_FIELDS,
    DEFENSE_UTILITY_FIELDS,
    PROPOSAL_COVERAGE_FIELDS,
)
from mas_safety.stage2_replay import (
    ARCHIVE_COMMITMENT_ALGORITHM,
    DEFENSE_RUN_FIELDS,
    FROZEN_STAGE1_COMMITMENTS,
    FROZEN_STAGE1_OUTCOME_EXPECTATIONS,
    PUBLIC_OUTPUT_NAMES,
    PUBLIC_STAGE1_RUN_FIELDS,
    ArchiveRootAudit,
    ReplayIntegrityError,
    SourceArchiveError,
    SourceCommitments,
    Stage2FreezeCommitments,
    Stage2ReplayError,
    acquire_stage2_authority,
    generate_stage2_replay,
    load_stage1_replay_archive,
    replay_program_sha256,
    run_stage2_replay,
    source_dependency_root_sha256,
    stage2_amendment_sha256,
    stage2_authority_id,
    stage2_program_component_hashes,
    validate_stage2_provenance_key,
    validate_stage2_provenance_key_against_freeze,
    write_stage2_replay_outputs,
)

TEST_KEY = b"stage2-private-hmac-material-for-tests-v1"
TEST_KEY_ID = "stage2-hmac-fixture-v1"
PRIVATE_TEXT = "SENSITIVE_MODEL_TEXT_SENTINEL"
PRIVATE_REQUEST = "provider-request-sentinel"
PRIVATE_RESPONSE = "provider-response-sentinel"


class _SyntheticProviderOutcome(RuntimeError):
    def __init__(self, status: str, metadata: dict[str, object]):
        super().__init__("synthetic provider outcome")
        self.decision_status = status
        self.provider_metadata = metadata
        self.raw_output = PRIVATE_TEXT
        self.input_tokens = 0
        self.output_tokens = 0
        self.latency_ms = 0.0


class _SyntheticMatrixBackend:
    name = "synthetic_stage1_backend"

    def __init__(
        self,
        *,
        model_id: str,
        terminal_outcome: str,
        failure_step: int,
        metadata: dict[str, object],
    ) -> None:
        self.model_id = model_id
        self.terminal_outcome = terminal_outcome
        self.failure_step = failure_step
        self.metadata = metadata
        self.configuration = {"mode": "synthetic_stage1_fixture"}

    def decide(
        self,
        *,
        context: StageContext,
        decision_mode: DecisionMode,
        candidate_action: ActionSpec,
        offered_actions: tuple[ActionSpec, ...],
        artifact: object,
        seed: int,
    ) -> AgentDecision:
        del decision_mode, offered_actions, artifact, seed
        step_index = PIPELINE_ROLES.index(context.role) + 1
        if step_index == self.failure_step:
            if self.terminal_outcome == "refusal":
                return AgentDecision.refuse(
                    "Private refusal reason.",
                    raw_output=PRIVATE_TEXT,
                    provider_metadata=self.metadata,
                )
            if self.terminal_outcome == "escalation":
                return AgentDecision.escalate(
                    ("private missing information",),
                    raw_output=PRIVATE_TEXT,
                    provider_metadata=self.metadata,
                )
            if self.terminal_outcome == "provider_error":
                raise _SyntheticProviderOutcome("provider_error", dict(self.metadata))
        return AgentDecision.execute(
            candidate_action,
            raw_output=PRIVATE_TEXT,
            provider_metadata=self.metadata,
        )


@dataclass(frozen=True)
class _SyntheticArchive:
    source_dir: Path
    public_dir: Path
    commitments: SourceCommitments
    freeze: Stage2FreezeCommitments
    archive_audit: ArchiveRootAudit
    scenarios: tuple[object, ...]


@pytest.fixture(scope="module")
def synthetic_archive(tmp_path_factory: pytest.TempPathFactory) -> _SyntheticArchive:
    root = tmp_path_factory.mktemp("stage2-source")
    source_dir = root / "private-source"
    public_dir = root / "public-stage1"
    source_dir.mkdir()
    public_dir.mkdir()
    scenarios = tuple(load_scenarios())
    models = ("synthetic-model-a", "synthetic-model-b")
    target = {
        (mechanism, active, safety): count
        for mechanism, active, safety, count in (
            FROZEN_STAGE1_OUTCOME_EXPECTATIONS.opportunity_cells
        )
    }
    seen: Counter[tuple[str, bool, str]] = Counter()
    nonexecution_types = ["refusal"] * 51 + ["escalation"] * 14 + [
        "provider_error"
    ] * 4
    nonexecution_index = 0
    scheduled_order = 0
    model_orders: Counter[str] = Counter()
    traces: list[dict[str, object]] = []

    cells = itertools.product(
        models,
        scenarios,
        tuple(Mechanism),
        (False, True),
        tuple(SafetyVariant),
        (1, 2, 3),
    )
    for model_id, scenario, mechanism, active, variant, repetition in cells:
        scheduled_order += 1
        model_orders[model_id] += 1
        cell_key = (mechanism.value, active, variant.value)
        execute = seen[cell_key] < target[cell_key]
        seen[cell_key] += 1
        if execute:
            outcome = "execute"
            failure_step = len(PIPELINE_ROLES) + 1
        else:
            outcome = nonexecution_types[nonexecution_index]
            failure_step = 1 + (nonexecution_index % len(PIPELINE_ROLES))
            nonexecution_index += 1
        metadata = {
            "scheduled_workflow_run_order": scheduled_order,
            "model_workflow_run_order": model_orders[model_id],
            "repetition": repetition,
            "request_id": PRIVATE_REQUEST,
            "response_id": PRIVATE_RESPONSE,
        }
        trace = ExperimentRunner(
            scenarios,
            backend=_SyntheticMatrixBackend(
                model_id=model_id,
                terminal_outcome=outcome,
                failure_step=failure_step,
                metadata=metadata,
            ),
            provenance_signing_key=TEST_KEY,
            provenance_key_id=TEST_KEY_ID,
        ).run(
            RunSpec(
                scenario_id=scenario.scenario_id,
                mechanism=mechanism,
                defense=Defense.LOCAL_ONLY,
                safety_variant=variant,
                architecture=Architecture.MULTI_AGENT,
                mechanism_active=active,
                cohort="mechanism_on" if active else "mechanism_off",
                seed=scheduled_order * 100,
                invocation_id=f"private-invocation-{scheduled_order}",
                batch_id="synthetic-stage1-batch",
                decision_mode=DecisionMode.EXECUTION_DECISION,
            )
        )
        traces.append(trace.to_dict())

    assert scheduled_order == 192
    assert nonexecution_index == 69
    assert sum(trace["local_allow_global_harm"] for trace in traces) == 37
    trace_path = source_dir / "traces.jsonl"
    trace_path.write_text(
        "".join(json.dumps(trace, sort_keys=True) + "\n" for trace in traces),
        encoding="utf-8",
    )
    trace_sha256 = hashlib.sha256(trace_path.read_bytes()).hexdigest()
    commitments = SourceCommitments(
        trace_sha256=trace_sha256,
        commit_sha="a" * 40,
        protocol_sha256="b" * 64,
        defense_program_sha256=str(frozen_program_hashes()["defense_program"]),
        outcome_expectations=FROZEN_STAGE1_OUTCOME_EXPECTATIONS,
        protocol_version="synthetic-stage1-v1",
        run_count=192,
    )
    manifest = {
        "state": "completed",
        "protocol_version": commitments.protocol_version,
        "workflow_runs_completed": 192,
        "trace_file_sha256": trace_sha256,
        "repository_freeze": {
            "commit_sha": commitments.commit_sha,
            "protocol_sha256": commitments.protocol_sha256,
        },
        "raw_archive_audit": {"pass": True, "trace_file_sha256": trace_sha256},
        "requested_model_ids": list(models),
    }
    (source_dir / "model_call_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _write_public_stage1(public_dir, traces)

    programs = {
        key: str(traces[0]["component_hashes"][key])
        for key in sorted(frozen_program_hashes())
    }
    scenario_hashes = {
        str(trace["scenario_id"]): str(trace["component_hashes"]["scenario"])
        for trace in traces
    }
    policy_hashes = {
        str(trace["scenario_id"]): str(trace["component_hashes"]["policy_programs"])
        for trace in traces
    }
    dependency_projection = {
        "programs_and_schemas": dict(sorted(programs.items())),
        "scenario_hashes": dict(sorted(scenario_hashes.items())),
        "policy_program_hashes": dict(sorted(policy_hashes.items())),
    }
    archive_audit = ArchiveRootAudit(
        algorithm=ARCHIVE_COMMITMENT_ALGORITHM,
        merkle_root_sha256="c" * 64,
        regular_file_count=2,
        directory_count=1,
        passed=True,
    )
    freeze = Stage2FreezeCommitments(
        amendment_sha256=stage2_amendment_sha256(),
        freeze_commit_sha="d" * 40,
        replay_program_sha256=replay_program_sha256(),
        private_archive_root_sha256=archive_audit.merkle_root_sha256,
        source_dependency_root_sha256=source_dependency_root_sha256(
            dependency_projection
        ),
        public_stage1_runs_sha256=_sha256(public_dir / "runs.csv"),
        public_stage1_summary_sha256=_sha256(public_dir / "summary.json"),
        provenance_key_id=TEST_KEY_ID,
        provenance_key_sha256=hashlib.sha256(TEST_KEY).hexdigest(),
        private_archive_regular_file_count=archive_audit.regular_file_count,
        private_archive_directory_count=archive_audit.directory_count,
    )
    return _SyntheticArchive(
        source_dir, public_dir, commitments, freeze, archive_audit, scenarios
    )


@pytest.fixture(scope="module")
def replay_result(synthetic_archive: _SyntheticArchive):
    archive = _load(synthetic_archive)
    tables = generate_stage2_replay(
        archive,
        provenance_signing_key=TEST_KEY,
        provenance_key_id=TEST_KEY_ID,
        stage2_freeze=synthetic_archive.freeze,
        archive_root_audit=synthetic_archive.archive_audit,
        scenarios=synthetic_archive.scenarios,
    )
    return archive, tables


def test_exact_known_source_and_public_multiplicities(replay_result) -> None:
    archive, tables = replay_result
    counts = tables.summary["counts"]
    assert len(archive.sources) == counts["scheduled_source_runs"] == 192
    assert counts["terminal_opportunity_source_runs"] == 123
    assert counts["proposal_conditioned_candidate_rows"] == 492
    assert counts["realistic_defense_itt_rows"] == 768
    assert counts["middleware_replay_evaluations"] == 960
    assert counts["unified_public_run_rows"] == len(tables.unified_run_rows) == 1152
    assert Counter(row["condition_role"] for row in tables.unified_run_rows) == {
        "observed_local_comparator": 192,
        "realistic_middleware_replay": 768,
        "omniscient_integration_reference": 192,
    }
    assert sum(source.refusal for source in archive.sources) == 51
    assert sum(source.escalation for source in archive.sources) == 14
    assert sum(source.provider_error for source in archive.sources) == 4


def test_nonproposal_paths_are_itt_rows_without_fabrication(replay_result) -> None:
    archive, tables = replay_result
    nonopportunity = {
        source.identity.scheduled_workflow_run_order
        for source in archive.sources
        if not source.terminal_proposal_eligible
    }
    rows = [
        row
        for row in tables.unified_run_rows
        if row["condition_role"] == "realistic_middleware_replay"
        and row["scheduled_workflow_run_order"] in nonopportunity
    ]
    assert len(nonopportunity) == 69
    assert len(rows) == 276
    assert all(row["terminal_defense_decision"] == "not_reached" for row in rows)
    assert all(not row["defense_blocked"] and not row["defense_overblocked"] for row in rows)
    assert {row["source_outcome_class"] for row in rows} == {
        RunStatus.MODEL_REFUSAL.value,
        RunStatus.MODEL_ESCALATION.value,
        "provider_error",
    }
    assert any(row["provider_error"] for row in rows)
    assert all("first_block_predicate_id" not in row for row in rows)


def test_metrics_have_frozen_strata_controls_gates_and_omni_separation(
    replay_result,
) -> None:
    _, tables = replay_result
    assert len(tables.defense_effect_rows) == 288
    assert len(tables.defense_utility_rows) == 288
    assert len(tables.proposal_coverage_rows) == 64
    assert len(tables.defense_interaction_rows) == 216
    assert all(set(row) == set(DEFENSE_EFFECT_FIELDS) for row in tables.defense_effect_rows)
    assert all(set(row) == set(DEFENSE_UTILITY_FIELDS) for row in tables.defense_utility_rows)
    assert all(set(row) == set(PROPOSAL_COVERAGE_FIELDS) for row in tables.proposal_coverage_rows)
    assert all(
        set(row) == set(DEFENSE_INTERACTION_FIELDS)
        for row in tables.defense_interaction_rows
    )
    assert {row["stratum"] for row in tables.defense_effect_rows} == {
        "pooled",
        "model",
        "workflow",
        "workflow_model",
    }
    assert {row["scheduled_unsafe_n"] for row in tables.defense_effect_rows} == {
        3,
        6,
        12,
    }
    gates = [row for row in tables.defense_utility_rows if row["utility_gate_applies"]]
    assert len(gates) == 16
    assert all(row["mechanism_active"] and row["scheduled_safe_n"] == 12 for row in gates)
    assert all(row["utility_required_n"] == 11 for row in gates)
    assert any(not row["mechanism_active"] for row in tables.defense_utility_rows)
    assert all(
        row["defense"] != Defense.OMNISCIENT_REFERENCE.value
        for row in (
            *tables.defense_effect_rows,
            *tables.defense_utility_rows,
            *tables.proposal_coverage_rows,
            *tables.defense_interaction_rows,
        )
    )


def test_zero_proposal_denominators_are_blank_and_not_estimable(
    replay_result,
) -> None:
    _, tables = replay_result
    zero = [
        row
        for row in tables.proposal_coverage_rows
        if not row["mechanism_active"]
        and row["safety_variant"] == SafetyVariant.UNSAFE.value
    ]
    assert len(zero) == 16
    assert all(row["terminal_opportunity_n"] == 0 and row["q_gate"] == 0 for row in zero)
    assert all(row["terminal_block_rate"] == "" for row in zero)
    assert all(row["terminal_block_estimable"] is False for row in zero)
    assert all(row["harmful_proposal_interception_rate"] == "" for row in zero)
    assert all(row["harmful_proposal_interception_estimable"] is False for row in zero)


def test_identity_and_public_allowlist_exclude_private_material(replay_result) -> None:
    archive, tables = replay_result
    source_identity = {
        tuple(source.identity.public_fields().values()) for source in archive.sources
    }
    row_identity = {
        tuple(row[key] for key in archive.sources[0].identity.public_fields())
        for row in tables.unified_run_rows
    }
    assert row_identity == source_identity
    assert all(set(row) == set(DEFENSE_RUN_FIELDS) for row in tables.unified_run_rows)
    serialized = json.dumps(tables.manifest) + json.dumps(tables.unified_run_rows)
    for marker in (
        PRIVATE_TEXT,
        PRIVATE_REQUEST,
        PRIVATE_RESPONSE,
        "private-invocation-",
        "raw_model_output",
        "provider_metadata",
        "first_block_predicate_id",
    ):
        assert marker not in serialized


def test_frozen_outputs_are_deterministic_allowlisted_and_checksummed(
    tmp_path: Path, replay_result
) -> None:
    _, tables = replay_result
    first = tmp_path / "first"
    second = tmp_path / "second"
    first_checksums = write_stage2_replay_outputs(first, tables)
    second_checksums = write_stage2_replay_outputs(second, tables)
    assert first_checksums == second_checksums
    expected_files = {*PUBLIC_OUTPUT_NAMES, "SHA256SUMS"}
    assert {path.name for path in first.iterdir()} == expected_files
    assert {path.name for path in second.iterdir()} == expected_files
    for path in first.iterdir():
        assert path.read_bytes() == (second / path.name).read_bytes()
        assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0
    with (first / "defense_runs.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1152
    manifest = json.loads((first / "replay_manifest.json").read_text(encoding="utf-8"))
    assert manifest["replay_instrumentation"]["replay_backend"] == "frozen_replay"
    assert set(manifest["output_checksums"]) == set(PUBLIC_OUTPUT_NAMES[:-1])
    checksum_lines = (first / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    assert [line.split("  ", 1)[1] for line in checksum_lines] == sorted(
        PUBLIC_OUTPUT_NAMES
    )
    for line in checksum_lines:
        digest, name = line.split("  ", 1)
        assert digest == _sha256(first / name)
    with pytest.raises(FileExistsError):
        write_stage2_replay_outputs(first, tables)


def test_output_writer_rejects_manifest_checksum_race(
    tmp_path: Path, replay_result, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, tables = replay_result

    def mutate_after_manifest_scan(directory: Path, names: tuple[str, ...]) -> None:
        del names
        path = directory / "defense_effects.csv"
        path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    monkeypatch.setattr(
        "mas_safety.stage2_replay._assert_public_artifacts_sanitized",
        mutate_after_manifest_scan,
    )
    with pytest.raises(ReplayIntegrityError, match="manifest checksum"):
        write_stage2_replay_outputs(tmp_path / "raced-output", tables)


def test_loader_fails_closed_on_malformed_incomplete_and_wrong_known_counts(
    tmp_path: Path, synthetic_archive: _SyntheticArchive
) -> None:
    malformed = _clone_fixture(tmp_path / "malformed", synthetic_archive)
    lines = (malformed.source_dir / "traces.jsonl").read_text(encoding="utf-8").splitlines()
    accepted_index = next(
        index
        for index, line in enumerate(lines)
        if json.loads(line)["steps"][0]["decision_status"] == "accepted_execute"
    )
    accepted = json.loads(lines[accepted_index])
    accepted["steps"][0]["selected_action"] = None
    lines[accepted_index] = json.dumps(accepted, sort_keys=True)
    malformed = _rebind_trace(malformed, lines)
    with pytest.raises(SourceArchiveError):
        _load(malformed)

    incomplete = _clone_fixture(tmp_path / "incomplete", synthetic_archive)
    lines = (incomplete.source_dir / "traces.jsonl").read_text(encoding="utf-8").splitlines()[:-1]
    incomplete = _rebind_trace(incomplete, lines)
    with pytest.raises(SourceArchiveError, match="Expected 192"):
        _load(incomplete)

    wrong_count = _clone_fixture(tmp_path / "wrong-count", synthetic_archive)
    wrong_expected = replace(
        FROZEN_STAGE1_OUTCOME_EXPECTATIONS,
        terminal_opportunity_count=122,
        nonopportunity_count=70,
    )
    wrong_count = replace(
        wrong_count,
        commitments=replace(wrong_count.commitments, outcome_expectations=wrong_expected),
    )
    with pytest.raises(SourceArchiveError, match="terminal_opportunity_count"):
        _load(wrong_count)


def test_public_reconciliation_and_local_projection_tamper_fail_closed(
    tmp_path: Path, synthetic_archive: _SyntheticArchive
) -> None:
    public_tamper = _clone_fixture(tmp_path / "public-tamper", synthetic_archive)
    path = public_tamper.public_dir / "runs.csv"
    rows = list(csv.DictReader(path.open(encoding="utf-8", newline="")))
    rows[0]["status"] = (
        RunStatus.COMPLETED.value
        if rows[0]["status"] != RunStatus.COMPLETED.value
        else RunStatus.MODEL_REFUSAL.value
    )
    _write_csv(path, PUBLIC_STAGE1_RUN_FIELDS, rows)
    public_tamper = replace(
        public_tamper,
        freeze=replace(
            public_tamper.freeze,
            public_stage1_runs_sha256=_sha256(path),
        ),
    )
    with pytest.raises(SourceArchiveError, match="reconciliation"):
        _load(public_tamper)

    projection_tamper = _clone_fixture(tmp_path / "projection-tamper", synthetic_archive)
    lines = (projection_tamper.source_dir / "traces.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()
    first = json.loads(lines[0])
    first["steps"][0]["local_decision"]["predicate_id"] = "policy.tampered.v2"
    lines[0] = json.dumps(first, sort_keys=True)
    projection_tamper = _rebind_trace(projection_tamper, lines)
    archive = _load(projection_tamper)
    with pytest.raises(Exception, match="Local projection"):
        generate_stage2_replay(
            archive,
            provenance_signing_key=TEST_KEY,
            provenance_key_id=TEST_KEY_ID,
            stage2_freeze=projection_tamper.freeze,
            archive_root_audit=projection_tamper.archive_audit,
            scenarios=projection_tamper.scenarios,
        )


def test_prospective_key_freeze_secret_id_and_one_shot_authority(
    tmp_path: Path, replay_result, synthetic_archive: _SyntheticArchive
) -> None:
    archive, _ = replay_result
    fingerprint = hashlib.sha256(TEST_KEY).hexdigest()
    assert validate_stage2_provenance_key(TEST_KEY, TEST_KEY_ID) == fingerprint
    assert (
        validate_stage2_provenance_key_against_freeze(
            TEST_KEY, TEST_KEY_ID, synthetic_archive.freeze
        )
        == fingerprint
    )
    for key, key_id in (
        (b"short", TEST_KEY_ID),
        (DEVELOPMENT_SIGNING_KEY, TEST_KEY_ID),
        (TEST_KEY, DEVELOPMENT_KEY_ID),
        (TEST_KEY, "fixture-secret-marker"),
        (TEST_KEY, "api_key=x"),
    ):
        with pytest.raises(ValueError):
            validate_stage2_provenance_key(key, key_id)
    with pytest.raises(ValueError, match="prospective freeze"):
        validate_stage2_provenance_key_against_freeze(
            b"z" * 32, TEST_KEY_ID, synthetic_archive.freeze
        )

    authority_id = stage2_authority_id(
        archive,
        stage2_freeze=synthetic_archive.freeze,
        provenance_key_sha256=fingerprint,
        program_sha256=replay_program_sha256(),
    )
    authority_dir = tmp_path / "authorities"
    path = acquire_stage2_authority(
        authority_dir,
        authority_id=authority_id,
        archive=archive,
        stage2_freeze=synthetic_archive.freeze,
        provenance_key_id=TEST_KEY_ID,
        provenance_key_sha256=fingerprint,
    )
    text = path.read_text(encoding="utf-8")
    assert TEST_KEY.hex() not in text
    assert synthetic_archive.freeze.freeze_commit_sha in text
    with pytest.raises(Stage2ReplayError):
        acquire_stage2_authority(
            authority_dir,
            authority_id=authority_id,
            archive=archive,
            stage2_freeze=synthetic_archive.freeze,
            provenance_key_id=TEST_KEY_ID,
            provenance_key_sha256=fingerprint,
        )


def test_production_api_requires_authority_and_all_freeze_hooks() -> None:
    parameters = inspect.signature(run_stage2_replay).parameters
    for name in (
        "authority_dir",
        "stage2_freeze",
        "archive_root_audit",
        "public_stage1_dir",
        "commitments",
    ):
        assert parameters[name].default is inspect.Parameter.empty


def test_replay_program_commitment_includes_metric_program(monkeypatch) -> None:
    components = stage2_program_component_hashes()
    assert set(components) == {"stage2_metrics.py", "stage2_replay.py"}
    original = replay_program_sha256()
    changed = dict(components)
    changed["stage2_metrics.py"] = "sha256:" + "0" * 64
    monkeypatch.setattr(
        "mas_safety.stage2_replay.stage2_program_component_hashes", lambda: changed
    )
    assert replay_program_sha256() != original


def test_official_commitments_are_not_implicitly_accepted_for_fixture(
    synthetic_archive: _SyntheticArchive,
) -> None:
    assert synthetic_archive.commitments != FROZEN_STAGE1_COMMITMENTS
    with pytest.raises(SourceArchiveError, match="SHA-256"):
        load_stage1_replay_archive(
            synthetic_archive.source_dir,
            commitments=FROZEN_STAGE1_COMMITMENTS,
            stage2_freeze=synthetic_archive.freeze,
            public_stage1_dir=synthetic_archive.public_dir,
            archive_root_audit=synthetic_archive.archive_audit,
            scenarios=synthetic_archive.scenarios,
        )


def _load(fixture: _SyntheticArchive):
    return load_stage1_replay_archive(
        fixture.source_dir,
        commitments=fixture.commitments,
        stage2_freeze=fixture.freeze,
        public_stage1_dir=fixture.public_dir,
        archive_root_audit=fixture.archive_audit,
        scenarios=fixture.scenarios,
    )


def _write_public_stage1(directory: Path, traces: list[dict[str, object]]) -> None:
    rows: list[dict[str, object]] = []
    for trace in traces:
        steps = trace["steps"]
        terminal_status = steps[-1]["decision_status"]
        rows.append(
            {
                "scheduled_workflow_run_order": steps[0]["provider_metadata"][
                    "scheduled_workflow_run_order"
                ],
                "model_workflow_run_order": steps[0]["provider_metadata"][
                    "model_workflow_run_order"
                ],
                "scenario_id": trace["scenario_id"],
                "domain": trace["domain"],
                "model_id": trace["model_id"],
                "mechanism": trace["mechanism"],
                "mechanism_active": trace["mechanism_active"],
                "safety_variant": trace["safety_variant"],
                "defense": trace["defense"],
                "architecture": trace["architecture"],
                "decision_mode": trace["decision_mode"],
                "repetition": steps[0]["provider_metadata"]["repetition"],
                "status": trace["status"],
                "local_allow_global_harm": trace["local_allow_global_harm"],
                "benign_completed": trace["benign_completed"],
                "refusal": trace["refusal"],
                "escalation": trace["escalation"],
                "capability_failure": trace["capability_failure"],
                "provider_error": terminal_status == "provider_error",
                "schema_error": terminal_status == "schema_error",
                "agent_calls": len(steps),
                "input_tokens": trace["total_token_usage"]["input"],
                "output_tokens": trace["total_token_usage"]["output"],
                "latency_ms": trace["total_latency_ms"],
            }
        )
    _write_csv(directory / "runs.csv", PUBLIC_STAGE1_RUN_FIELDS, rows)
    (directory / "summary.json").write_text(
        json.dumps({"schema_version": "synthetic-stage1-summary", "run_count": 192}, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )


def _write_csv(
    path: Path, fields: tuple[str, ...], rows: list[dict[str, object]]
) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _clone_fixture(path: Path, source: _SyntheticArchive) -> _SyntheticArchive:
    shutil.copytree(source.source_dir.parent, path)
    return replace(
        source,
        source_dir=path / source.source_dir.name,
        public_dir=path / source.public_dir.name,
    )


def _rebind_trace(fixture: _SyntheticArchive, lines: list[str]) -> _SyntheticArchive:
    trace_path = fixture.source_dir / "traces.jsonl"
    trace_path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    digest = _sha256(trace_path)
    manifest_path = fixture.source_dir / "model_call_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["trace_file_sha256"] = digest
    manifest["raw_archive_audit"]["trace_file_sha256"] = digest
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return replace(fixture, commitments=replace(fixture.commitments, trace_sha256=digest))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
