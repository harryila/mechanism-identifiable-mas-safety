from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

from .enums import PIPELINE_ROLES, Architecture, Mechanism, Role, SafetyVariant
from .models import Scenario, StageContext
from .policies import render_policy_contract
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
    model_visibility_map: dict[str, dict[str, object]]


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
                local_policy_contract=_policy_contract(scenario, source_policy),
                restriction_visible=True,
                restriction_text=scenario.source_restriction,
                shareable_message=full_objective,
                public_evidence=resolve_evidence(
                    scenario.public_evidence_by_role[role], facts
                ),
                applicable_policy_ids=(scenario.policies["source"].policy_id,),
                applicable_policy_contracts=_applicable_policy_contracts(
                    scenario, (scenario.policies["source"].policy_id,)
                ),
            )
            for role in PIPELINE_ROLES
        )
        return MechanismSetup(
            contexts=contexts,
            intervention_coordinate="architecture_mode",
            transformation_diff_allowlist=("/architecture",),
            transformation_delta=(
                "architecture:multi_agent->single_agent_full_context",
            ),
            source_anchor={
                "restriction_present": True,
                "restriction_active": not bool(facts["terminal_authorized"]),
                "restriction_text": scenario.source_restriction,
            },
            model_visibility_map=inspect_model_visibility(contexts),
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
        Mechanism.INTENT_DECOMPOSITION: (
            "intent_projection:full_authorization_context->stage_local"
        ),
        Mechanism.CONTEXT_FRAGMENTATION: "visible_facts:co_located->fragmented",
        Mechanism.AUTHORIZATION_DRIFT: ("authorization_information:forwarded->dropped"),
        Mechanism.POLICY_HETEROGENEITY: "actuator_policy:source->downstream",
    }
    coordinate = {
        Mechanism.INTENT_DECOMPOSITION: "objective_projection_mode",
        Mechanism.CONTEXT_FRAGMENTATION: "fact_routing_mode",
        Mechanism.AUTHORIZATION_DRIFT: "authorization_information_forwarded",
        Mechanism.POLICY_HETEROGENEITY: "policy_assignment_by_role.actuator",
    }
    allowlist = {
        Mechanism.INTENT_DECOMPOSITION: (
            "/roles/*/objective_view",
        ),
        Mechanism.CONTEXT_FRAGMENTATION: ("/roles/*/visible_facts",),
        Mechanism.AUTHORIZATION_DRIFT: (
            "/roles/retriever/restriction_visible",
            "/roles/retriever/restriction_text",
            "/roles/transformer/restriction_visible",
            "/roles/transformer/restriction_text",
            "/roles/actuator/restriction_visible",
            "/roles/actuator/restriction_text",
            "/roles/retriever/visible_facts",
            "/roles/transformer/visible_facts",
            "/roles/actuator/visible_facts",
            "/roles/retriever/public_evidence",
            "/roles/transformer/public_evidence",
            "/roles/actuator/public_evidence",
        ),
        Mechanism.POLICY_HETEROGENEITY: (
            "/roles/actuator/local_policy_id",
            "/roles/actuator/local_policy_contract",
            "/roles/actuator/applicable_policy_ids",
            "/roles/actuator/applicable_policy_contracts",
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
            source_anchor_evaluation_complete and not bool(facts["terminal_authorized"])
        ),
        "restriction_text": scenario.source_restriction,
    }
    return MechanismSetup(
        contexts=contexts,
        intervention_coordinate=coordinate[mechanism],
        transformation_diff_allowlist=allowlist[mechanism],
        transformation_delta=(delta[mechanism],) if active else (),
        source_anchor=source_anchor,
        model_visibility_map=inspect_model_visibility(contexts),
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
        local_policy_contract=_policy_contract(scenario, local_policy_id),
        restriction_visible=restriction_visible,
        restriction_text=(
            scenario.source_restriction if restriction_visible else NOT_PROVIDED
        ),
        shareable_message=task,
        public_evidence=public_evidence,
        applicable_policy_ids=applicable_policy_ids,
        applicable_policy_contracts=_applicable_policy_contracts(
            scenario, applicable_policy_ids
        ),
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
    authorization_keys = _authorization_fact_family(scenario)
    # Hold alternate authorization channels hidden in both arms so the paired
    # intervention changes only the objective projection slot.
    visible_facts = _mask_facts(facts, authorization_keys)
    public_evidence = _resolve_visible_evidence(
        scenario.public_evidence_by_role[role],
        facts,
        hidden_fact_keys=authorization_keys,
    )
    return _base_context(
        scenario,
        role,
        task=scenario.local_tasks[role],
        objective_view=objective,
        visible_facts=visible_facts,
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
        authorization_fact = str(scenario.global_invariant["authorization_fact"])
        if authorization_fact in permitted_keys:
            permitted_keys.update(_authorization_fact_family(scenario))
        for key in _decisive_fact_keys(scenario) - permitted_keys:
            visible[key] = NOT_AVAILABLE
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
    downstream_drift = active and role is not Role.PLANNER
    restriction_visible = not downstream_drift
    authorization_keys = _authorization_fact_family(scenario)
    visible_facts = (
        _mask_facts(facts, authorization_keys) if downstream_drift else dict(facts)
    )
    public_evidence = _resolve_visible_evidence(
        scenario.public_evidence_by_role[role],
        facts,
        hidden_fact_keys=authorization_keys if downstream_drift else frozenset(),
    )
    return _base_context(
        scenario,
        role,
        task=scenario.local_tasks[role],
        objective_view=scenario.local_tasks[role],
        visible_facts=visible_facts,
        local_policy_id=policy,
        restriction_visible=restriction_visible,
        public_evidence=public_evidence,
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


def _policy_contract(scenario: Scenario, policy_id: str) -> str:
    by_id = {policy.policy_id: policy for policy in scenario.policies.values()}
    return render_policy_contract(scenario, by_id[policy_id])


def _applicable_policy_contracts(
    scenario: Scenario, policy_ids: tuple[str, ...]
) -> tuple[tuple[str, str], ...]:
    return tuple(
        (policy_id, _policy_contract(scenario, policy_id)) for policy_id in policy_ids
    )


def _decisive_fact_keys(scenario: Scenario) -> frozenset[str]:
    invariant = scenario.global_invariant
    return frozenset(
        {
            str(invariant["trigger_fact"]),
            *_authorization_fact_family(scenario),
            *(str(key) for key in invariant.get("always_required_facts", [])),
        }
    )


def _authorization_fact_family(scenario: Scenario) -> frozenset[str]:
    """Return the authorization fact and every transitively derived alias."""

    authorization = str(scenario.global_invariant["authorization_fact"])
    family = {authorization}
    changed = True
    while changed:
        changed = False
        for target, rule in scenario.derived_fact_rules.items():
            source = str(rule)[1:]
            if source in family and target not in family:
                family.add(target)
                changed = True
    return frozenset(family)


def _mask_facts(
    facts: dict[str, object], hidden_fact_keys: frozenset[str]
) -> dict[str, object]:
    return {
        key: NOT_AVAILABLE if key in hidden_fact_keys else value
        for key, value in facts.items()
    }


def _resolve_visible_evidence(
    template: dict[str, object],
    facts: dict[str, object],
    *,
    hidden_fact_keys: frozenset[str],
) -> dict[str, object]:
    resolved = resolve_evidence(template, facts)
    for evidence_key, template_value in template.items():
        source_key = (
            template_value[1:]
            if isinstance(template_value, str) and template_value.startswith("$")
            else None
        )
        if evidence_key in hidden_fact_keys or source_key in hidden_fact_keys:
            resolved.pop(evidence_key, None)
    return resolved


def inspect_model_visibility(
    contexts: tuple[StageContext, ...],
) -> dict[str, dict[str, object]]:
    """Serialize exactly the mechanism-controlled inputs visible to each agent.

    Simulator ground truth, defense-only source anchors, and trusted
    policy-intersection inputs are deliberately absent.  The runtime reduces the
    backend's applicable-policy view to the local policy represented here.
    """

    return {
        context.role.value: {
            "role": context.role.value,
            "task": context.task,
            "objective_view": context.objective_view,
            "visible_facts": deepcopy(context.visible_facts),
            "local_policy": {
                "policy_id": context.local_policy_id,
                "contract": context.local_policy_contract,
            },
            "restriction": (
                context.restriction_text
                if context.restriction_visible
                else NOT_PROVIDED
            ),
            "shareable_message": context.shareable_message,
            "public_evidence": deepcopy(context.public_evidence),
        }
        for context in contexts
    }
