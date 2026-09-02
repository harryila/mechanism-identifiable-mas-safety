from __future__ import annotations

import pytest

from mas_safety.stage4_analysis import Stage4RunOutcome, analyze_stage4
from mas_safety.stage4_live import ConfirmatoryWorkflow, build_stage4_schedule


WORKFLOWS = (
    ConfirmatoryWorkflow("confirmatory.h1", "healthcare"),
    ConfirmatoryWorkflow("confirmatory.h2", "healthcare"),
    ConfirmatoryWorkflow("confirmatory.e1", "education"),
    ConfirmatoryWorkflow("confirmatory.e2", "education"),
    ConfirmatoryWorkflow("confirmatory.p1", "public_services"),
    ConfirmatoryWorkflow("confirmatory.p2", "public_services"),
    ConfirmatoryWorkflow("confirmatory.f1", "finance_procurement"),
    ConfirmatoryWorkflow("confirmatory.f2", "finance_procurement"),
)
MODELS = ("provider/model-a@2026-08-01", "provider/model-b@2026-08-15")


@pytest.fixture
def schedule():
    return build_stage4_schedule(WORKFLOWS, MODELS, seed="analysis-test-seed")


def _synthetic_outcomes(schedule) -> list[Stage4RunOutcome]:
    workflow_order = {
        workflow.scenario_id: index for index, workflow in enumerate(schedule.workflows)
    }
    first_model = schedule.model_ids[0]
    outcomes: list[Stage4RunOutcome] = []
    for run in schedule.runs:
        workflow_index = workflow_order[run.scenario_id]
        if run.mechanism == "intent_decomposition":
            risk_delta = 1 if workflow_index < 4 else (-1 if workflow_index < 6 else 0)
        elif run.mechanism == "context_fragmentation":
            risk_delta = 1
        elif run.mechanism == "authorization_drift":
            risk_delta = 1 if run.model_id == first_model else -1
        else:
            risk_delta = 0

        if risk_delta > 0:
            local_lgh = int(run.mechanism_on)
        elif risk_delta < 0:
            local_lgh = int(not run.mechanism_on)
        else:
            local_lgh = 0

        if run.mechanism == "context_fragmentation":
            safe_completion = int(not run.mechanism_on)
        else:
            safe_completion = 1

        outcomes.append(
            Stage4RunOutcome(
                run_id=run.run_id,
                local_lgh=local_lgh,
                safe_completion=safe_completion,
            )
        )
    return outcomes


def test_analysis_uses_workflow_clustered_equal_weighting(schedule) -> None:
    analysis = analyze_stage4(schedule, _synthetic_outcomes(schedule))

    assert analysis.analysis_unit == "workflow"
    assert analysis.repetitions_nested_within_workflow_model_cells is True
    assert analysis.models_crossed_with_workflows is True
    assert analysis.workflow_count == 8
    assert analysis.model_count == 2
    assert analysis.repetitions_per_cell == 3
    assert analysis.scheduled_run_count == 768
    assert len(analysis.repetition_effects) == 384
    assert len(analysis.workflow_model_effects) == 64
    assert len(analysis.workflow_effects) == 32
    assert len(analysis.model_mechanism_strata) == 8
    assert len(analysis.mechanism_effects) == 4
    assert len(analysis.direction_counts) == 4
    assert len(analysis.leave_one_workflow_out) == 32
    assert len(analysis.leave_one_domain_out) == 16

    mechanism = {value.mechanism: value for value in analysis.mechanism_effects}
    assert mechanism["intent_decomposition"].risk_effect == pytest.approx(0.25)
    assert mechanism["context_fragmentation"].risk_effect == pytest.approx(1.0)
    assert mechanism["context_fragmentation"].utility_effect == pytest.approx(-1.0)
    assert mechanism["authorization_drift"].risk_effect == pytest.approx(0.0)
    assert mechanism["policy_heterogeneity"].risk_effect == pytest.approx(0.0)


def test_model_strata_and_workflow_direction_counts_are_not_call_counts(schedule) -> None:
    analysis = analyze_stage4(schedule, _synthetic_outcomes(schedule))
    authorization = {
        value.model_id: value
        for value in analysis.model_mechanism_strata
        if value.mechanism == "authorization_drift"
    }

    assert authorization[schedule.model_ids[0]].workflow_count == 8
    assert authorization[schedule.model_ids[0]].risk_effect == pytest.approx(1.0)
    assert authorization[schedule.model_ids[1]].workflow_count == 8
    assert authorization[schedule.model_ids[1]].risk_effect == pytest.approx(-1.0)

    directions = {
        value.mechanism: value for value in analysis.direction_counts
    }["intent_decomposition"]
    assert directions.workflow_count == 8
    assert (directions.positive, directions.zero, directions.negative) == (4, 2, 2)
    assert directions.positive + directions.zero + directions.negative == 8


def test_leave_one_workflow_and_domain_out_use_workflow_effects(schedule) -> None:
    analysis = analyze_stage4(schedule, _synthetic_outcomes(schedule))

    leave_h1 = next(
        value
        for value in analysis.leave_one_workflow_out
        if value.mechanism == "intent_decomposition"
        and value.omitted_scenario_id == "confirmatory.h1"
    )
    assert leave_h1.retained_workflow_count == 7
    assert leave_h1.risk_effect == pytest.approx(1 / 7)

    by_domain = {
        value.omitted_domain: value
        for value in analysis.leave_one_domain_out
        if value.mechanism == "intent_decomposition"
    }
    assert by_domain["healthcare"].retained_workflow_count == 6
    assert by_domain["healthcare"].risk_effect == pytest.approx(0.0)
    assert by_domain["education"].risk_effect == pytest.approx(0.0)
    assert by_domain["public_services"].risk_effect == pytest.approx(2 / 3)
    assert by_domain["finance_procurement"].risk_effect == pytest.approx(1 / 3)


def test_analysis_fails_closed_on_missing_duplicate_or_extra_outcomes(schedule) -> None:
    outcomes = _synthetic_outcomes(schedule)

    with pytest.raises(ValueError, match="1 missing"):
        analyze_stage4(schedule, outcomes[:-1])
    with pytest.raises(ValueError, match="duplicate Stage 4 outcome"):
        analyze_stage4(schedule, [*outcomes, outcomes[0]])
    with pytest.raises(ValueError, match="1 unexpected"):
        analyze_stage4(
            schedule,
            [
                *outcomes,
                Stage4RunOutcome(
                    run_id="stage4-run-unexpected",
                    local_lgh=0,
                    safe_completion=0,
                ),
            ],
        )


def test_outcomes_require_trusted_binary_labels() -> None:
    with pytest.raises(ValueError, match="local_lgh"):
        Stage4RunOutcome("run", local_lgh=2, safe_completion=1)
    with pytest.raises(ValueError, match="safe_completion"):
        Stage4RunOutcome("run", local_lgh=0, safe_completion=-1)
