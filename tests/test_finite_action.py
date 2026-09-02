from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import replace

import pytest

from mas_safety.enums import (
    AgentDecisionKind,
    Architecture,
    DecisionMode,
    Defense,
    Mechanism,
    SafetyVariant,
)
from mas_safety.finite_action import (
    FINITE_ACTION_EXPECTED_PAIRS,
    FINITE_ACTION_EXPECTED_RUNS,
    FINITE_ACTION_SEMANTIC_BINDINGS,
    FINITE_ACTION_SEMANTIC_CHOICES,
    audit_finite_action_schedule,
    build_finite_action_schedule,
    finite_action_semantic_choice,
    finite_action_schedule_sha256,
)
from mas_safety.runner import offered_actions_for
from mas_safety.scenarios import load_scenarios

MODELS = ("model-alpha-2026-04-23", "model-beta-2026-03-05")


def test_finite_action_schedule_is_complete_adjacent_and_balanced() -> None:
    schedule = build_finite_action_schedule(load_scenarios(), MODELS)
    audit = audit_finite_action_schedule(schedule)

    assert len(schedule) == FINITE_ACTION_EXPECTED_RUNS
    assert audit == {
        "schema_version": "finite-action-schedule-audit-v1",
        "pass": True,
        "scheduled_runs": 192,
        "adjacent_pairs": 96,
        "mechanism_on_first_pairs": 48,
        "mechanism_off_first_pairs": 48,
        "within_stratum_order_balance": "3_on_first_3_off_first",
        "cartesian_cells_complete": True,
        "model_ids": ["model-alpha-2026-04-23", "model-beta-2026-03-05"],
        "scenario_ids": [
            "finance.unapproved_payment",
            "healthcare.patient_summary_disclosure",
        ],
        "batch_id": "finite-action-development-template",
        "decision_mode": "finite_action_selection",
        "candidate_defense": "local_only",
        "semantic_choices": [
            "execute",
            "request_authorization",
            "request_context",
            "escalate",
            "stop",
        ],
        "semantic_choice_runtime_bindings": [
            {
                "semantic_choice": "execute",
                "decision_kind": "execute",
                "selected_action": "focal_candidate",
            },
            {
                "semantic_choice": "request_authorization",
                "decision_kind": "execute",
                "selected_action": "request_authorization",
            },
            {
                "semantic_choice": "request_context",
                "decision_kind": "execute",
                "selected_action": "request_more_context",
            },
            {
                "semantic_choice": "escalate",
                "decision_kind": "escalate",
                "selected_action": None,
            },
            {
                "semantic_choice": "stop",
                "decision_kind": "refuse",
                "selected_action": None,
            },
        ],
        "pooled_with_execution_decision": False,
    }
    assert tuple(audit["semantic_choices"]) == FINITE_ACTION_SEMANTIC_CHOICES
    assert all(
        item.run_spec.decision_mode is DecisionMode.FINITE_ACTION_SELECTION
        for item in schedule
    )

    pairs = defaultdict(list)
    for item in schedule:
        pairs[item.pair_id].append(item)
    assert len(pairs) == FINITE_ACTION_EXPECTED_PAIRS
    for rows in pairs.values():
        assert len(rows) == 2
        assert rows[1].scheduled_order == rows[0].scheduled_order + 1
        assert {item.run_spec.mechanism_active for item in rows} == {False, True}

    cells = Counter(
        (
            item.model_id,
            item.run_spec.scenario_id,
            item.run_spec.mechanism,
            item.run_spec.safety_variant,
            item.repetition,
            item.run_spec.mechanism_active,
        )
        for item in schedule
    )
    assert len(cells) == FINITE_ACTION_EXPECTED_RUNS
    assert set(cells.values()) == {1}


def test_finite_action_schedule_and_hash_are_deterministic() -> None:
    first = build_finite_action_schedule(load_scenarios(), MODELS)
    second = build_finite_action_schedule(load_scenarios(), tuple(reversed(MODELS)))

    assert [item.to_dict() for item in first] == [item.to_dict() for item in second]
    first_hash = finite_action_schedule_sha256(first)
    assert first_hash == finite_action_schedule_sha256(second)
    assert first_hash == (
        "cc34c513bdb2cd7ecb3d62c3ddb24fadbed6a1bddd231c7f4886ef180c373fac"
    )


def test_all_five_semantic_choices_map_to_existing_trusted_runtime_outcomes() -> None:
    candidate = load_scenarios()[0].actions[0]
    offered = offered_actions_for(candidate, DecisionMode.FINITE_ACTION_SELECTION)

    assert tuple(item.semantic_choice for item in FINITE_ACTION_SEMANTIC_BINDINGS) == (
        FINITE_ACTION_SEMANTIC_CHOICES
    )
    assert [item.name for item in offered] == [
        candidate.name,
        "request_authorization",
        "request_more_context",
    ]
    cases = (
        (AgentDecisionKind.EXECUTE, offered[0], "execute"),
        (AgentDecisionKind.EXECUTE, offered[1], "request_authorization"),
        (AgentDecisionKind.EXECUTE, offered[2], "request_context"),
        (AgentDecisionKind.ESCALATE, None, "escalate"),
        (AgentDecisionKind.REFUSE, None, "stop"),
    )
    assert tuple(
        finite_action_semantic_choice(
            decision_kind=kind,
            selected_action=selected,
            candidate_action=candidate,
        )
        for kind, selected, _semantic in cases
    ) == tuple(semantic for _kind, _selected, semantic in cases)


def test_semantic_choice_mapping_fails_closed() -> None:
    candidate = load_scenarios()[0].actions[0]
    unoffered = replace(candidate, name="invented_action")

    with pytest.raises(ValueError, match="trusted finite action"):
        finite_action_semantic_choice(
            decision_kind=AgentDecisionKind.EXECUTE,
            selected_action=unoffered,
            candidate_action=candidate,
        )
    with pytest.raises(ValueError, match="Non-execute"):
        finite_action_semantic_choice(
            decision_kind=AgentDecisionKind.REFUSE,
            selected_action=candidate,
            candidate_action=candidate,
        )


@pytest.mark.parametrize(
    ("scenarios", "models", "repetitions", "message"),
    [
        ([], MODELS, 3, "two frozen development workflow"),
        (None, (MODELS[0],), 3, "exactly two distinct"),
        (None, ("mutable-model", MODELS[1]), 3, "immutable snapshot"),
        (None, ("model-alpha-2026-02-31", MODELS[1]), 3, "valid immutable"),
        (None, MODELS, 2, "fixed at 3 repetitions"),
    ],
)
def test_finite_action_schedule_rejects_nonfrozen_population(
    scenarios: object,
    models: tuple[str, ...],
    repetitions: int,
    message: str,
) -> None:
    selected = load_scenarios() if scenarios is None else scenarios
    with pytest.raises(ValueError, match=message):
        build_finite_action_schedule(selected, models, repetitions=repetitions)


def test_finite_action_audit_rejects_nonadjacent_pair() -> None:
    schedule = build_finite_action_schedule(load_scenarios(), MODELS)
    tampered = list(schedule)
    tampered[1] = replace(tampered[1], scheduled_order=999)

    with pytest.raises(ValueError, match="Scheduled order"):
        audit_finite_action_schedule(tampered)


@pytest.mark.parametrize(
    "field",
    [
        "model_id",
        "scenario_id",
        "mechanism",
        "safety_variant",
        "repetition",
        "mechanism_active",
        "cohort",
        "batch_id",
        "pair_id",
        "pair_position",
        "mechanism_on_first",
        "seed",
        "invocation_id",
        "decision_mode",
        "defense",
        "architecture",
    ],
)
def test_finite_action_audit_rejects_population_and_identity_tampering(
    field: str,
) -> None:
    tampered = build_finite_action_schedule(load_scenarios(), MODELS)
    row = tampered[0]
    spec = row.run_spec
    if field == "model_id":
        row = replace(row, model_id="model-gamma-2026-05-01")
    elif field == "scenario_id":
        row = replace(row, run_spec=replace(spec, scenario_id="invented.workflow"))
    elif field == "mechanism":
        row = replace(
            row,
            run_spec=replace(spec, mechanism=Mechanism.CONTEXT_FRAGMENTATION),
        )
    elif field == "safety_variant":
        row = replace(
            row,
            run_spec=replace(spec, safety_variant=SafetyVariant.SAFE),
        )
    elif field == "repetition":
        row = replace(row, repetition=99)
    elif field == "mechanism_active":
        row = replace(
            row,
            run_spec=replace(spec, mechanism_active=not spec.mechanism_active),
        )
    elif field == "cohort":
        row = replace(row, run_spec=replace(spec, cohort="wrong_cohort"))
    elif field == "batch_id":
        row = replace(row, run_spec=replace(spec, batch_id="other-batch"))
    elif field == "pair_id":
        row = replace(row, pair_id="invented-pair")
    elif field == "pair_position":
        row = replace(row, pair_position=99)
    elif field == "mechanism_on_first":
        row = replace(row, mechanism_on_first=not row.mechanism_on_first)
    elif field == "seed":
        row = replace(row, run_spec=replace(spec, seed=spec.seed + 1))
    elif field == "invocation_id":
        row = replace(row, run_spec=replace(spec, invocation_id="invented"))
    elif field == "decision_mode":
        row = replace(
            row,
            run_spec=replace(spec, decision_mode=DecisionMode.EXECUTION_DECISION),
        )
    elif field == "defense":
        row = replace(
            row,
            run_spec=replace(spec, defense=Defense.HISTORY_MONITOR),
        )
    elif field == "architecture":
        row = replace(
            row,
            run_spec=replace(
                spec, architecture=Architecture.SINGLE_AGENT_FULL_CONTEXT
            ),
        )
    else:  # pragma: no cover - the parameter list is exhaustive
        raise AssertionError(field)
    tampered[0] = row

    with pytest.raises(ValueError):
        audit_finite_action_schedule(tampered)


def test_finite_action_audit_binds_expected_models_and_batch() -> None:
    schedule = build_finite_action_schedule(load_scenarios(), MODELS)

    with pytest.raises(ValueError, match="model IDs do not match"):
        audit_finite_action_schedule(
            schedule,
            expected_model_ids=(MODELS[0], "model-gamma-2026-05-01"),
        )
    with pytest.raises(ValueError, match="batch ID does not match"):
        audit_finite_action_schedule(schedule, expected_batch_id="other-batch")
