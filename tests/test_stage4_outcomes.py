from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from mas_safety.backends import ScriptedBackend
from mas_safety.enums import RunStatus
from mas_safety.runner import ExperimentRunner
from mas_safety.scenarios import load_scenarios
from mas_safety.stage4_analysis import Stage4RunOutcome
from mas_safety.stage4_live import build_stage4_schedule, load_confirmatory_workflows
from mas_safety.stage4_outcomes import (
    EXECUTION_COMMITMENT_SCHEMA_VERSION,
    PROVIDER_FAILURE,
    SCHEMA_FAILURE,
    Stage4ExecutionCommitments,
    Stage4ProviderCallAudit,
    Stage4RunArtifactCommitment,
    Stage4RunFailure,
    Stage4TraceRecord,
    convert_stage4_outcomes,
    validate_stage4_outcome_set,
)
from mas_safety.stage4_runtime import (
    FROZEN_MODEL_IDS,
    build_stage4_run_bindings,
    stage4_run_bindings_sha256,
)


REPOSITORY = Path(__file__).resolve().parents[1]
BATCH_ID = "stage4-outcome-test"
PROTOCOL_COMMIT = "c" * 40
PROTOCOL_SHA256 = "d" * 64
PROVENANCE_KEY_ID = "stage4-test-provenance"
BACKEND_NAME = "openai_responses"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def _design():
    schedule = build_stage4_schedule(
        load_confirmatory_workflows(REPOSITORY / "scenarios" / "confirmatory"),
        FROZEN_MODEL_IDS,
        seed="stage4-outcome-test-seed",
    )
    bindings = build_stage4_run_bindings(schedule, batch_id=BATCH_ID)
    artifacts = tuple(
        Stage4RunArtifactCommitment(
            scheduled_run_id=run.run_id,
            component_hashes_sha256=_sha(f"components:{run.run_id}"),
            backend_configuration_sha256=_sha(f"backend:{run.run_id}"),
        )
        for run in schedule.runs
    )
    commitments = Stage4ExecutionCommitments(
        schema_version=EXECUTION_COMMITMENT_SCHEMA_VERSION,
        run_bindings_sha256=stage4_run_bindings_sha256(bindings),
        protocol_commit_sha=PROTOCOL_COMMIT,
        protocol_sha256=PROTOCOL_SHA256,
        provenance_key_id=PROVENANCE_KEY_ID,
        backend_name=BACKEND_NAME,
        run_artifacts=artifacts,
    )
    return schedule, bindings, commitments


def _model_orders(schedule) -> dict[str, int]:
    counts = {model: 0 for model in schedule.model_ids}
    result: dict[str, int] = {}
    for run in schedule.runs:
        counts[run.model_id] += 1
        result[run.run_id] = counts[run.model_id]
    return result


def _call(
    run,
    binding,
    *,
    model_order: int,
    provider_order: int,
    step_index: int = 1,
    status: str = PROVIDER_FAILURE,
) -> Stage4ProviderCallAudit:
    token = f"{run.run_id}:{step_index}:{status}"
    valid = status in {"accepted_execute", "model_refusal", "model_escalation"}
    return Stage4ProviderCallAudit(
        step_index=step_index,
        provider_call_order=provider_order,
        decision_status=status,
        structured_output_valid=valid,
        requested_model=run.model_id,
        local_pairing_seed=binding.run_spec.seed + step_index,
        scheduled_workflow_run_order=run.sequence_index + 1,
        model_workflow_run_order=model_order,
        repetition=run.repetition,
        condition_id=binding.run_spec.condition_id,
        invocation_id=binding.run_spec.invocation_id,
        scenario_id=run.scenario_id,
        mechanism=run.mechanism,
        mechanism_active=run.mechanism_on,
        safety_variant=run.safety_variant,
        protocol_commit_sha=PROTOCOL_COMMIT,
        protocol_sha256=PROTOCOL_SHA256,
        batch_id=BATCH_ID,
        raw_log_record=f"raw-{token}",
        provider_request_sha256=_sha(f"provider:{token}"),
        request_record_sha256=_sha(f"request:{token}"),
        result_record_sha256=_sha(f"result:{token}"),
        result_record_kind="error" if status == PROVIDER_FAILURE else "response",
        ledger_reservation_id=f"reservation-{token}",
        ledger_reservation_event_sha256=_sha(f"held:{token}"),
        ledger_terminal_event_sha256=_sha(f"terminal:{token}"),
        retry_count=0,
    )


def _failure_records(schedule, bindings, *, schema_index: int | None = None):
    orders = _model_orders(schedule)
    provider_orders = {model: 0 for model in schedule.model_ids}
    records = []
    for index, (run, binding) in enumerate(zip(schedule.runs, bindings)):
        provider_orders[run.model_id] += 1
        reason = SCHEMA_FAILURE if index == schema_index else PROVIDER_FAILURE
        records.append(
            Stage4RunFailure(
                scheduled_run_id=run.run_id,
                reason=reason,
                calls=(
                    _call(
                        run,
                        binding,
                        model_order=orders[run.run_id],
                        provider_order=provider_orders[run.model_id],
                        status=reason,
                    ),
                ),
            )
        )
    return records


def test_attempted_provider_and_schema_failures_are_total_noncompletion_labels() -> None:
    schedule, bindings, commitments = _design()
    outcomes = convert_stage4_outcomes(
        schedule,
        _failure_records(schedule, bindings, schema_index=7),
        run_bindings=bindings,
        commitments=commitments,
    )

    assert outcomes.scheduled_run_count == 768
    assert outcomes.attempted_agent_calls == 768
    assert outcomes.valid_structured_decisions == 0
    assert [item.run_id for item in outcomes.outcomes] == [
        run.run_id for run in schedule.runs
    ]
    assert sum(item.failure_reason == PROVIDER_FAILURE for item in outcomes.outcomes) == 767
    assert sum(item.failure_reason == SCHEMA_FAILURE for item in outcomes.outcomes) == 1
    assert all(
        item.local_lgh == item.safe_completion == item.run_completed == 0
        for item in outcomes.outcomes
    )
    assert all(
        item.refusal is False and item.escalation is False
        for item in outcomes.outcomes
    )
    assert all(
        len(item.source_record_commitment_sha256) == 64
        and item.source_record_commitment_sha256.islower()
        for item in outcomes.outcomes
    )


def test_unattempted_duplicate_replacement_and_same_cell_swap_fail_closed() -> None:
    schedule, bindings, commitments = _design()
    records = _failure_records(schedule, bindings)

    with pytest.raises(ValueError, match="missing/unattempted"):
        convert_stage4_outcomes(
            schedule,
            records[:-1],
            run_bindings=bindings,
            commitments=commitments,
        )
    with pytest.raises(ValueError, match="duplicate or replacement"):
        convert_stage4_outcomes(
            schedule,
            [records[0], *records],
            run_bindings=bindings,
            commitments=commitments,
        )
    with pytest.raises(ValueError, match="replacement runs are forbidden"):
        replace(records[0], replacement_attempted=True)

    swapped = list(records)
    swapped[0] = replace(records[0], scheduled_run_id=records[1].scheduled_run_id)
    swapped[1] = replace(records[1], scheduled_run_id=records[0].scheduled_run_id)
    with pytest.raises(ValueError, match="runtime binding"):
        convert_stage4_outcomes(
            schedule,
            swapped,
            run_bindings=bindings,
            commitments=commitments,
        )


def test_repetition_raw_ledger_and_structured_status_tampering_is_rejected() -> None:
    schedule, bindings, commitments = _design()
    records = _failure_records(schedule, bindings)

    bad_call = replace(records[0].calls[0], repetition=2 if schedule.runs[0].repetition != 2 else 3)
    tampered = [replace(records[0], calls=(bad_call,)), *records[1:]]
    with pytest.raises(ValueError, match="repetition differs"):
        convert_stage4_outcomes(
            schedule,
            tampered,
            run_bindings=bindings,
            commitments=commitments,
        )

    duplicate_ledger = replace(
        records[1].calls[0],
        ledger_reservation_id=records[0].calls[0].ledger_reservation_id,
    )
    tampered = [records[0], replace(records[1], calls=(duplicate_ledger,)), *records[2:]]
    with pytest.raises(ValueError, match="duplicate Stage 4 call evidence"):
        convert_stage4_outcomes(
            schedule,
            tampered,
            run_bindings=bindings,
            commitments=commitments,
        )

    with pytest.raises(ValueError, match="conflicts with the trusted decision status"):
        replace(records[0].calls[0], structured_output_valid=True)


def test_outcome_set_validation_rejects_identity_type_and_commitment_tampering() -> None:
    schedule, bindings, commitments = _design()
    outcomes = convert_stage4_outcomes(
        schedule,
        _failure_records(schedule, bindings),
        run_bindings=bindings,
        commitments=commitments,
    )
    rows = list(outcomes.outcomes)

    rows[0] = replace(rows[0], seed=rows[0].seed + 1)
    with pytest.raises(ValueError, match="frozen binding"):
        validate_stage4_outcome_set(
            schedule,
            replace(outcomes, outcomes=tuple(rows)),
            run_bindings=bindings,
            commitments=commitments,
        )

    rows = list(outcomes.outcomes)
    rows[0] = replace(rows[0], local_lgh=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="exact binary integer"):
        validate_stage4_outcome_set(
            schedule,
            replace(outcomes, outcomes=tuple(rows)),
            run_bindings=bindings,
            commitments=commitments,
        )

    rows = list(outcomes.outcomes)
    rows[0] = replace(rows[0], source_record_commitment_sha256="A" * 64)
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        validate_stage4_outcome_set(
            schedule,
            replace(outcomes, outcomes=tuple(rows)),
            run_bindings=bindings,
            commitments=commitments,
        )

    rows = list(outcomes.outcomes)
    rows[0] = replace(rows[0], refusal=1)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="exact bools"):
        validate_stage4_outcome_set(
            schedule,
            replace(outcomes, outcomes=tuple(rows)),
            run_bindings=bindings,
            commitments=commitments,
        )

    rows = list(outcomes.outcomes)
    rows[0] = replace(
        rows[0],
        attempted_agent_calls=4,
        valid_structured_decisions=0,
    )
    with pytest.raises(ValueError, match="exactly one invalid terminal call"):
        validate_stage4_outcome_set(
            schedule,
            replace(outcomes, outcomes=tuple(rows)),
            run_bindings=bindings,
            commitments=commitments,
        )

    rows = list(outcomes.outcomes)
    rows[0] = replace(
        rows[0],
        run_completed=1,
        local_lgh=int(rows[0].safety_variant == "unsafe"),
        safe_completion=int(rows[0].safety_variant == "safe"),
        noncompletion_reason=None,
        failure_reason=None,
        source_kind="trace",
        attempted_agent_calls=3,
        valid_structured_decisions=3,
    )
    with pytest.raises(ValueError, match="all four attempted calls"):
        validate_stage4_outcome_set(
            schedule,
            replace(outcomes, outcomes=tuple(rows)),
            run_bindings=bindings,
            commitments=commitments,
        )

    rows = list(outcomes.outcomes)
    rows[0] = replace(
        rows[0],
        attempted_agent_calls=4,
        valid_structured_decisions=0,
        refusal=True,
        noncompletion_reason="model_refusal",
        failure_reason=None,
        source_kind="trace",
    )
    with pytest.raises(ValueError, match="provider-native invalid terminal call"):
        validate_stage4_outcome_set(
            schedule,
            replace(outcomes, outcomes=tuple(rows)),
            run_bindings=bindings,
            commitments=commitments,
        )


def test_exact_binary_analysis_inputs_reject_bool_and_float() -> None:
    for invalid in (False, True, 0.0, 1.0):
        with pytest.raises(ValueError, match="exact binary integer"):
            Stage4RunOutcome("run", local_lgh=invalid, safe_completion=0)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="exact binary integer"):
            Stage4RunOutcome("run", local_lgh=0, safe_completion=invalid)  # type: ignore[arg-type]


def test_completed_trace_is_bound_to_calls_components_backend_and_provenance() -> None:
    schedule, bindings, commitments = _design()
    target_index = next(
        index for index, run in enumerate(schedule.runs) if run.safety_variant == "safe"
    )
    target_run = schedule.runs[target_index]
    target_binding = bindings[target_index]
    scenarios = load_scenarios(REPOSITORY / "scenarios" / "confirmatory")
    scenario = next(item for item in scenarios if item.scenario_id == target_run.scenario_id)
    trace = ExperimentRunner([scenario], backend=ScriptedBackend()).run(
        target_binding.run_spec
    )
    assert trace.status is RunStatus.COMPLETED

    trace.model_id = target_run.model_id
    trace.backend = BACKEND_NAME
    trace.provenance_key_id = PROVENANCE_KEY_ID
    trace.backend_configuration = {"frozen": "stage4-test-backend"}
    trace.component_hashes = {"frozen": "stage4-test-components"}

    orders = _model_orders(schedule)
    calls = tuple(
        _call(
            target_run,
            target_binding,
            model_order=orders[target_run.run_id],
            provider_order=1000 + step_index,
            step_index=step_index,
            status="accepted_execute",
        )
        for step_index in range(1, 5)
    )
    for step, call in zip(trace.steps, calls):
        step.provider_metadata = {
            "requested_model": call.requested_model,
            "scheduled_workflow_run_order": call.scheduled_workflow_run_order,
            "model_workflow_run_order": call.model_workflow_run_order,
            "repetition": call.repetition,
            "condition_id": call.condition_id,
            "invocation_id": call.invocation_id,
            "scenario_id": call.scenario_id,
            "mechanism": call.mechanism,
            "mechanism_active": call.mechanism_active,
            "safety_variant": call.safety_variant,
            "protocol_commit_sha": call.protocol_commit_sha,
            "protocol_sha256": call.protocol_sha256,
            "batch_id": call.batch_id,
            "local_pairing_seed": call.local_pairing_seed,
            "call_order": call.provider_call_order,
            "structured_output_valid": True,
            "raw_log_record": call.raw_log_record,
            "provider_request_sha256": call.provider_request_sha256,
            "request_record_sha256": call.request_record_sha256,
            "result_record_sha256": call.result_record_sha256,
            "result_record_kind": call.result_record_kind,
            "retry_count": 0,
        }

    artifacts = list(commitments.run_artifacts)
    artifacts[target_index] = Stage4RunArtifactCommitment(
        scheduled_run_id=target_run.run_id,
        component_hashes_sha256=_canonical_sha(trace.component_hashes),
        backend_configuration_sha256=_canonical_sha(trace.backend_configuration),
    )
    commitments = replace(commitments, run_artifacts=tuple(artifacts))
    records = _failure_records(schedule, bindings)
    records[target_index] = Stage4TraceRecord(
        scheduled_run_id=target_run.run_id,
        trace=trace,
        calls=calls,
    )

    outcomes = convert_stage4_outcomes(
        schedule,
        records,
        run_bindings=bindings,
        commitments=commitments,
    )
    label = outcomes.outcomes[target_index]
    assert label.run_completed == label.safe_completion == 1
    assert label.attempted_agent_calls == label.valid_structured_decisions == 4
    assert label.noncompletion_reason is None

    trace.steps[0].provider_metadata["repetition"] = 99
    with pytest.raises(ValueError, match="metadata differs"):
        convert_stage4_outcomes(
            schedule,
            records,
            run_bindings=bindings,
            commitments=commitments,
        )
