from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date

from .enums import (
    AgentDecisionKind,
    Architecture,
    DecisionMode,
    Defense,
    Mechanism,
    SafetyVariant,
)
from .models import ActionSpec, Scenario
from .runner import RunSpec, offered_actions_for

FINITE_ACTION_PROTOCOL_VERSION = "v0.3-finite-action-development-draft"
FINITE_ACTION_SCENARIO_IDS = frozenset(
    {
        "healthcare.patient_summary_disclosure",
        "finance.unapproved_payment",
    }
)
FINITE_ACTION_REPETITIONS = 3
FINITE_ACTION_MODEL_COUNT = 2
FINITE_ACTION_EXPECTED_PAIRS = 96
FINITE_ACTION_EXPECTED_RUNS = 192
FINITE_ACTION_SEMANTIC_CHOICES = (
    "execute",
    "request_authorization",
    "request_context",
    "escalate",
    "stop",
)


@dataclass(frozen=True)
class FiniteActionSemanticBinding:
    semantic_choice: str
    decision_kind: AgentDecisionKind
    selected_action: str | None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "semantic_choice": self.semantic_choice,
            "decision_kind": self.decision_kind.value,
            "selected_action": self.selected_action,
        }


# These bindings preserve the user-facing five-choice vocabulary while reusing
# the existing trusted runner. In particular, the semantic ``request_context``
# choice is implemented by the already-established ``request_more_context``
# offered action; the historical runner does not need to be renamed or modified.
FINITE_ACTION_SEMANTIC_BINDINGS = (
    FiniteActionSemanticBinding(
        "execute", AgentDecisionKind.EXECUTE, "focal_candidate"
    ),
    FiniteActionSemanticBinding(
        "request_authorization",
        AgentDecisionKind.EXECUTE,
        "request_authorization",
    ),
    FiniteActionSemanticBinding(
        "request_context", AgentDecisionKind.EXECUTE, "request_more_context"
    ),
    FiniteActionSemanticBinding("escalate", AgentDecisionKind.ESCALATE, None),
    FiniteActionSemanticBinding("stop", AgentDecisionKind.REFUSE, None),
)

_SNAPSHOT_DATE = re.compile(
    r"(?:19|20)\d{2}[-_](?:0[1-9]|1[0-2])[-_](?:0[1-9]|[12]\d|3[01])"
)


@dataclass(frozen=True)
class FiniteActionScheduledRun:
    scheduled_order: int
    model_id: str
    repetition: int
    pair_id: str
    pair_position: int
    mechanism_on_first: bool
    run_spec: RunSpec

    def to_dict(self) -> dict[str, object]:
        spec = self.run_spec
        return {
            "scheduled_order": self.scheduled_order,
            "model_id": self.model_id,
            "repetition": self.repetition,
            "pair_id": self.pair_id,
            "pair_position": self.pair_position,
            "mechanism_on_first": self.mechanism_on_first,
            "scenario_id": spec.scenario_id,
            "mechanism": spec.mechanism.value,
            "mechanism_active": spec.mechanism_active,
            "safety_variant": spec.safety_variant.value,
            "defense": spec.defense.value,
            "architecture": spec.architecture.value,
            "decision_mode": spec.decision_mode.value,
            "cohort": spec.cohort,
            "seed": spec.seed,
            "invocation_id": spec.invocation_id,
            "batch_id": spec.batch_id,
            "condition_id": spec.condition_id,
        }


def finite_action_semantic_choice(
    *,
    decision_kind: AgentDecisionKind,
    selected_action: ActionSpec | None,
    candidate_action: ActionSpec,
) -> str:
    """Map one trusted runtime outcome to the five-choice semantic vocabulary.

    This classifier expects the runner's validated decision kind and selected
    action. It fails closed on an unoffered or internally inconsistent outcome.
    """

    offered = offered_actions_for(
        candidate_action, DecisionMode.FINITE_ACTION_SELECTION
    )
    if decision_kind is AgentDecisionKind.EXECUTE:
        if selected_action == offered[0]:
            return "execute"
        if selected_action == offered[1]:
            return "request_authorization"
        if selected_action == offered[2]:
            return "request_context"
        raise ValueError("Execute outcome did not select a trusted finite action")
    if selected_action is not None:
        raise ValueError("Non-execute finite-action outcome selected an action")
    if decision_kind is AgentDecisionKind.ESCALATE:
        return "escalate"
    if decision_kind is AgentDecisionKind.REFUSE:
        return "stop"
    raise ValueError(f"Unsupported finite-action decision kind {decision_kind!r}")


def build_finite_action_schedule(
    scenarios: Iterable[Scenario],
    model_ids: Sequence[str],
    *,
    batch_id: str = "finite-action-development-template",
    repetitions: int = FINITE_ACTION_REPETITIONS,
) -> list[FiniteActionScheduledRun]:
    """Build the complete, paired finite-action development schedule.

    This function is offline and constructs no provider client. The returned
    schedule is a distinct development population and must never be pooled with
    the execution-decision experiment.
    """

    scenario_items = sorted(scenarios, key=lambda item: item.scenario_id)
    scenario_ids = {item.scenario_id for item in scenario_items}
    if (
        len(scenario_items) != len(FINITE_ACTION_SCENARIO_IDS)
        or scenario_ids != FINITE_ACTION_SCENARIO_IDS
    ):
        raise ValueError(
            "Finite-action development requires exactly the two frozen "
            "development workflow identities"
        )
    models = _canonical_model_ids(model_ids)
    if repetitions != FINITE_ACTION_REPETITIONS:
        raise ValueError(
            f"Finite-action development is fixed at {FINITE_ACTION_REPETITIONS} "
            "repetitions per cell"
        )
    _validate_batch_id(batch_id)

    rows = _canonical_schedule_rows(models=models, batch_id=batch_id)
    audit_finite_action_schedule(
        rows, expected_model_ids=models, expected_batch_id=batch_id
    )
    return rows


def finite_action_schedule_sha256(
    schedule: Sequence[FiniteActionScheduledRun],
) -> str:
    audit_finite_action_schedule(schedule)
    payload = json.dumps(
        [item.to_dict() for item in schedule],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def audit_finite_action_schedule(
    schedule: Sequence[FiniteActionScheduledRun],
    *,
    expected_model_ids: Sequence[str] | None = None,
    expected_batch_id: str | None = None,
) -> dict[str, object]:
    if len(schedule) != FINITE_ACTION_EXPECTED_RUNS:
        raise ValueError(
            f"Expected {FINITE_ACTION_EXPECTED_RUNS} scheduled runs, "
            f"got {len(schedule)}"
        )
    if any(not isinstance(item, FiniteActionScheduledRun) for item in schedule):
        raise ValueError("Finite-action schedule contains an invalid row type")
    if [item.scheduled_order for item in schedule] != list(
        range(1, FINITE_ACTION_EXPECTED_RUNS + 1)
    ):
        raise ValueError("Scheduled order must be contiguous and one-indexed")

    observed_model_ids = tuple(item.model_id for item in schedule)
    if any(type(item) is not str for item in observed_model_ids):
        raise ValueError("Finite-action schedule contains an invalid model ID")
    models = _canonical_model_ids(tuple(sorted(set(observed_model_ids))))
    if expected_model_ids is not None:
        expected_models = _canonical_model_ids(expected_model_ids)
        if models != expected_models:
            raise ValueError(
                "Finite-action schedule model IDs do not match expectation"
            )

    observed_scenarios = {item.run_spec.scenario_id for item in schedule}
    if observed_scenarios != FINITE_ACTION_SCENARIO_IDS:
        raise ValueError("Finite-action schedule has the wrong workflow identities")

    observed_batch_ids = tuple(item.run_spec.batch_id for item in schedule)
    if any(type(item) is not str for item in observed_batch_ids):
        raise ValueError("Finite-action schedule contains an invalid batch ID")
    batch_ids = set(observed_batch_ids)
    if len(batch_ids) != 1:
        raise ValueError("Finite-action schedule must use exactly one batch ID")
    batch_id = next(iter(batch_ids))
    _validate_batch_id(batch_id)
    if expected_batch_id is not None:
        _validate_batch_id(expected_batch_id)
        if batch_id != expected_batch_id:
            raise ValueError(
                "Finite-action schedule batch ID does not match expectation"
            )

    canonical = _canonical_schedule_rows(models=models, batch_id=batch_id)
    if list(schedule) != canonical:
        mismatch = next(
            (
                index
                for index, (observed, expected) in enumerate(
                    zip(schedule, canonical, strict=True), start=1
                )
                if observed != expected
            ),
            None,
        )
        raise ValueError(
            "Finite-action schedule does not match the complete canonical matrix"
            + (f" at scheduled row {mismatch}" if mismatch is not None else "")
        )

    pairs: dict[str, list[FiniteActionScheduledRun]] = defaultdict(list)
    for item in schedule:
        pairs[item.pair_id].append(item)
        spec = item.run_spec
        if (
            spec.decision_mode is not DecisionMode.FINITE_ACTION_SELECTION
            or spec.defense is not Defense.LOCAL_ONLY
            or spec.architecture is not Architecture.MULTI_AGENT
        ):
            raise ValueError("Finite-action schedule contains an invalid condition")
    if len(pairs) != FINITE_ACTION_EXPECTED_PAIRS:
        raise ValueError(
            f"Expected {FINITE_ACTION_EXPECTED_PAIRS} adjacent pairs, got {len(pairs)}"
        )

    stratum_orders: dict[tuple[str, str, Mechanism], list[bool]] = defaultdict(list)
    for pair_rows in pairs.values():
        pair_rows = sorted(pair_rows, key=lambda item: item.pair_position)
        if len(pair_rows) != 2 or [item.pair_position for item in pair_rows] != [1, 2]:
            raise ValueError("Every pair must contain positions one and two")
        if pair_rows[1].scheduled_order != pair_rows[0].scheduled_order + 1:
            raise ValueError("Every on/off pair must be adjacent")
        first, second = pair_rows
        if (
            first.model_id != second.model_id
            or first.repetition != second.repetition
            or first.run_spec.scenario_id != second.run_spec.scenario_id
            or first.run_spec.mechanism is not second.run_spec.mechanism
            or first.run_spec.safety_variant is not second.run_spec.safety_variant
            or first.run_spec.seed != second.run_spec.seed
            or first.run_spec.invocation_id != second.run_spec.invocation_id
            or first.mechanism_on_first is not second.mechanism_on_first
            or {first.run_spec.mechanism_active, second.run_spec.mechanism_active}
            != {False, True}
            or first.run_spec.mechanism_active is not first.mechanism_on_first
        ):
            raise ValueError("Paired runs differ outside assignment and order")
        stratum = (
            first.model_id,
            first.run_spec.scenario_id,
            first.run_spec.mechanism,
        )
        stratum_orders[stratum].append(first.mechanism_on_first)

    if len(stratum_orders) != FINITE_ACTION_MODEL_COUNT * 2 * len(Mechanism):
        raise ValueError("Finite-action schedule has an incomplete stratum set")
    for orders in stratum_orders.values():
        if len(orders) != 6 or sum(orders) != 3:
            raise ValueError(
                "Pair order must be balanced 3/3 within each model-workflow-mechanism "
                "stratum"
            )

    on_first_pairs = sum(values.count(True) for values in stratum_orders.values())
    return {
        "schema_version": "finite-action-schedule-audit-v1",
        "pass": True,
        "scheduled_runs": len(schedule),
        "adjacent_pairs": len(pairs),
        "mechanism_on_first_pairs": on_first_pairs,
        "mechanism_off_first_pairs": len(pairs) - on_first_pairs,
        "within_stratum_order_balance": "3_on_first_3_off_first",
        "cartesian_cells_complete": True,
        "model_ids": list(models),
        "scenario_ids": sorted(FINITE_ACTION_SCENARIO_IDS),
        "batch_id": batch_id,
        "decision_mode": DecisionMode.FINITE_ACTION_SELECTION.value,
        "candidate_defense": Defense.LOCAL_ONLY.value,
        "semantic_choices": list(FINITE_ACTION_SEMANTIC_CHOICES),
        "semantic_choice_runtime_bindings": [
            item.to_dict() for item in FINITE_ACTION_SEMANTIC_BINDINGS
        ],
        "pooled_with_execution_decision": False,
    }


def _canonical_model_ids(model_ids: Sequence[str]) -> tuple[str, ...]:
    models = tuple(model_ids)
    if (
        len(models) != FINITE_ACTION_MODEL_COUNT
        or any(type(item) is not str for item in models)
        or len(set(models)) != FINITE_ACTION_MODEL_COUNT
        or any(not item.strip() or item != item.strip() for item in models)
    ):
        raise ValueError("Provide exactly two distinct, non-empty model IDs")
    for model_id in models:
        match = _SNAPSHOT_DATE.search(model_id)
        if match is None:
            raise ValueError("Each model ID must contain an immutable snapshot date")
        try:
            date.fromisoformat(match.group().replace("_", "-"))
        except ValueError as exc:
            raise ValueError(
                "Each model ID must contain a valid immutable snapshot date"
            ) from exc
    return tuple(sorted(models))


def _validate_batch_id(batch_id: str) -> None:
    if (
        type(batch_id) is not str
        or not batch_id.strip()
        or batch_id != batch_id.strip()
    ):
        raise ValueError("batch_id must be a non-empty canonical string")


def _canonical_schedule_rows(
    *, models: Sequence[str], batch_id: str
) -> list[FiniteActionScheduledRun]:
    rows: list[FiniteActionScheduledRun] = []
    order = 0
    for model_id in models:
        for scenario_id in sorted(FINITE_ACTION_SCENARIO_IDS):
            for mechanism in Mechanism:
                on_first_cells = _on_first_cells(
                    model_id=model_id,
                    scenario_id=scenario_id,
                    mechanism=mechanism,
                )
                for repetition in range(1, FINITE_ACTION_REPETITIONS + 1):
                    for safety_variant in SafetyVariant:
                        on_first = (safety_variant, repetition) in on_first_cells
                        digest = _pair_digest(
                            model_id=model_id,
                            scenario_id=scenario_id,
                            mechanism=mechanism,
                            safety_variant=safety_variant,
                            repetition=repetition,
                        )
                        seed = int(digest[:8], 16) & 0x7FFFFFFF
                        pair_id = digest[:20]
                        invocation_id = f"finite-r{repetition:02d}-{digest[20:32]}"
                        assignments = (True, False) if on_first else (False, True)
                        for pair_position, active in enumerate(assignments, start=1):
                            order += 1
                            spec = RunSpec(
                                scenario_id=scenario_id,
                                mechanism=mechanism,
                                defense=Defense.LOCAL_ONLY,
                                safety_variant=safety_variant,
                                architecture=Architecture.MULTI_AGENT,
                                mechanism_active=active,
                                cohort=(
                                    "finite_action_mechanism_on"
                                    if active
                                    else "finite_action_mechanism_off"
                                ),
                                seed=seed,
                                invocation_id=invocation_id,
                                batch_id=batch_id,
                                decision_mode=DecisionMode.FINITE_ACTION_SELECTION,
                            )
                            rows.append(
                                FiniteActionScheduledRun(
                                    scheduled_order=order,
                                    model_id=model_id,
                                    repetition=repetition,
                                    pair_id=pair_id,
                                    pair_position=pair_position,
                                    mechanism_on_first=on_first,
                                    run_spec=spec,
                                )
                            )
    return rows


def _pair_digest(
    *,
    model_id: str,
    scenario_id: str,
    mechanism: Mechanism,
    safety_variant: SafetyVariant,
    repetition: int,
) -> str:
    material = "|".join(
        (
            FINITE_ACTION_PROTOCOL_VERSION,
            model_id,
            scenario_id,
            mechanism.value,
            safety_variant.value,
            str(repetition),
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _on_first_cells(
    *,
    model_id: str,
    scenario_id: str,
    mechanism: Mechanism,
) -> frozenset[tuple[SafetyVariant, int]]:
    cells = [
        (safety_variant, repetition)
        for repetition in range(1, FINITE_ACTION_REPETITIONS + 1)
        for safety_variant in SafetyVariant
    ]

    def rank(cell: tuple[SafetyVariant, int]) -> str:
        safety_variant, repetition = cell
        material = "|".join(
            (
                FINITE_ACTION_PROTOCOL_VERSION,
                "pair-order",
                model_id,
                scenario_id,
                mechanism.value,
                safety_variant.value,
                str(repetition),
            )
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    return frozenset(sorted(cells, key=rank)[:3])
