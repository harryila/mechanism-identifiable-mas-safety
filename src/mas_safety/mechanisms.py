from __future__ import annotations

from dataclasses import dataclass

from .enums import PIPELINE_ROLES, Architecture, Mechanism, Role, SafetyVariant
from .models import Scenario, StageContext
from .scenarios import resolve_evidence

NOT_AVAILABLE = "NOT_AVAILABLE"
NOT_PROVIDED = "NOT_PROVIDED"


@dataclass(frozen=True)
class MechanismSetup:
    contexts: tuple[StageContext, ...]
    intervention_coordinate: str
    transformation_diff_allowlist: tuple[str, ...]
    transformation_delta: tuple[str, ...]
    source_anchor: dict[str, object]


def build_mechanism_setup(
    scenario: Scenario,
    mechanism: Mechanism,
    variant: SafetyVariant,
    *,
    active: bool,
    architecture: Architecture,
) -> MechanismSetup:
    """Create the role-local views for one identified intervention.

    Within a mechanism pair, `active=False` restores exactly the targeted causal
    variable. Derived prompt/evidence changes are recorded in the trace.
    """

    facts = scenario.facts_for(variant)
    full_objective = scenario.full_objective.format(
        terminal_authorized=str(bool(facts["terminal_authorized"])).lower()
    )

    if architecture is Architecture.SINGLE_AGENT_FULL_CONTEXT:
        source_policy = scenario.policies["single_agent"].policy_id
        contexts = tuple(
            StageContext(
                role=role,
                task=scenario.local_tasks[role],
                objective_view=full_objective,
                visible_facts=dict(facts),
                local_policy_id=source_policy,
                restriction_visible=True,
                restriction_text=scenario.source_restriction,
                shareable_message=full_objective,
                public_evidence=resolve_evidence(
                    scenario.public_evidence_by_role[role], facts
                ),
                applicable_policy_ids=(scenario.policies["source"].policy_id,),
            )
            for role in PIPELINE_ROLES
        )
        return MechanismSetup(
            contexts=contexts,
            intervention_coordinate="architecture_mode",
            transformation_diff_allowlist=("/architecture",),
            transformation_delta=("architecture:multi_agent->single_agent_full_context",),
            source_anchor={
                "restriction_present": True,
                "restriction_active": not bool(facts["terminal_authorized"]),
                "restriction_text": scenario.source_restriction,
            },
        )

    builders = {
        Mechanism.INTENT_DECOMPOSITION: _intent_context,
        Mechanism.CONTEXT_FRAGMENTATION: _context_fragmentation_context,
        Mechanism.AUTHORIZATION_DRIFT: _authorization_drift_context,
        Mechanism.POLICY_HETEROGENEITY: _policy_heterogeneity_context,
    }
    contexts = tuple(
        builders[mechanism](scenario, role, facts, full_objective, active)
        for role in PIPELINE_ROLES
    )

    delta = {
        Mechanism.INTENT_DECOMPOSITION: "objective_view:full->stage_local",
        Mechanism.CONTEXT_FRAGMENTATION: "visible_facts:co_located->fragmented",
        Mechanism.AUTHORIZATION_DRIFT: "restriction_visibility:forwarded->dropped",
        Mechanism.POLICY_HETEROGENEITY: "actuator_policy:source->downstream",
    }
    coordinate = {
        Mechanism.INTENT_DECOMPOSITION: "objective_projection_mode",
        Mechanism.CONTEXT_FRAGMENTATION: "fact_routing_mode",
        Mechanism.AUTHORIZATION_DRIFT: "restriction_forwarded",
        Mechanism.POLICY_HETEROGENEITY: "policy_assignment_by_role.actuator",
    }
    allowlist = {
        Mechanism.INTENT_DECOMPOSITION: ("/roles/*/objective_view",),
        Mechanism.CONTEXT_FRAGMENTATION: ("/roles/*/visible_facts",),
        Mechanism.AUTHORIZATION_DRIFT: (
            "/roles/retriever/restriction",
            "/roles/transformer/restriction",
            "/roles/actuator/restriction",
        ),
        Mechanism.POLICY_HETEROGENEITY: (
            "/roles/actuator/local_policy_id",
            "/roles/actuator/applicable_policy_ids",
        ),
    }
    source_anchor_evaluation_complete = mechanism in {
        Mechanism.AUTHORIZATION_DRIFT,
        Mechanism.POLICY_HETEROGENEITY,
    }
    source_anchor = {
        "restriction_present": True,
        "evaluation_complete": source_anchor_evaluation_complete,
        "restriction_active": (
            source_anchor_evaluation_complete
            and not bool(facts["terminal_authorized"])
        ),
        "restriction_text": scenario.source_restriction,
    }
    return MechanismSetup(
        contexts=contexts,
        intervention_coordinate=coordinate[mechanism],
        transformation_diff_allowlist=allowlist[mechanism],
        transformation_delta=(delta[mechanism],) if active else (),
        source_anchor=source_anchor,
    )


def _base_context(
    scenario: Scenario,
    role: Role,
    *,
    task: str,
    objective_view: str,
    visible_facts: dict[str, object],
    local_policy_id: str,
    restriction_visible: bool,
    public_evidence: dict[str, object],
    applicable_policy_ids: tuple[str, ...],
) -> StageContext:
    return StageContext(
        role=role,
        task=task,
        objective_view=objective_view,
        visible_facts=visible_facts,
        local_policy_id=local_policy_id,
        restriction_visible=restriction_visible,
        restriction_text=(
            scenario.source_restriction if restriction_visible else NOT_PROVIDED
        ),
        shareable_message=task,
        public_evidence=public_evidence,
        applicable_policy_ids=applicable_policy_ids,
    )


def _intent_context(
    scenario: Scenario,
    role: Role,
    facts: dict[str, object],
    full_objective: str,
    active: bool,
) -> StageContext:
    policy = scenario.policies["intent"].policy_id
    objective = (
        f"{scenario.local_tasks[role]} [global_objective={NOT_AVAILABLE}]"
        if active
        else f"{scenario.local_tasks[role]} [global_objective={full_objective}]"
    )
    public_evidence = resolve_evidence(scenario.public_evidence_by_role[role], facts)
    return _base_context(
        scenario,
        role,
        task=scenario.local_tasks[role],
        objective_view=objective,
        visible_facts=dict(facts),
        local_policy_id=policy,
        restriction_visible=False,
        public_evidence=public_evidence,
        applicable_policy_ids=(policy,),
    )


def _context_fragmentation_context(
    scenario: Scenario,
    role: Role,
    facts: dict[str, object],
    full_objective: str,
    active: bool,
) -> StageContext:
    del full_objective
    policy = scenario.policies["context"].policy_id
    visible = dict(facts)
    if active:
        permitted_keys = set(scenario.context_fragments[role])
        visible = {
            key: value if key in permitted_keys else NOT_AVAILABLE
            for key, value in facts.items()
        }
    return _base_context(
        scenario,
        role,
        task=scenario.local_tasks[role],
        objective_view=scenario.local_tasks[role],
        visible_facts=visible,
        local_policy_id=policy,
        restriction_visible=False,
        public_evidence={"workflow_stage": role.value},
        applicable_policy_ids=(policy,),
    )


def _authorization_drift_context(
    scenario: Scenario,
    role: Role,
    facts: dict[str, object],
    full_objective: str,
    active: bool,
) -> StageContext:
    del full_objective
    policy = scenario.policies["restriction"].policy_id
    restriction_visible = not active or role is Role.PLANNER
    return _base_context(
        scenario,
        role,
        task=scenario.local_tasks[role],
        objective_view=scenario.local_tasks[role],
        visible_facts=dict(facts),
        local_policy_id=policy,
        restriction_visible=restriction_visible,
        public_evidence={"workflow_stage": role.value},
        applicable_policy_ids=(policy,),
    )


def _policy_heterogeneity_context(
    scenario: Scenario,
    role: Role,
    facts: dict[str, object],
    full_objective: str,
    active: bool,
) -> StageContext:
    del full_objective
    source_policy = scenario.policies["source"].policy_id
    downstream_policy = scenario.policies["downstream"].policy_id
    local_policy = (
        downstream_policy if active and role is Role.ACTUATOR else source_policy
    )
    applicable = (
        (source_policy, downstream_policy)
        if active and role is Role.ACTUATOR
        else (source_policy,)
    )
    return _base_context(
        scenario,
        role,
        task=scenario.local_tasks[role],
        objective_view=scenario.local_tasks[role],
        visible_facts=dict(facts),
        local_policy_id=local_policy,
        restriction_visible=False,
        public_evidence={"workflow_stage": role.value},
        applicable_policy_ids=applicable,
    )
