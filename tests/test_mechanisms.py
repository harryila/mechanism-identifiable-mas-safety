from __future__ import annotations

from dataclasses import asdict

import pytest

from mas_safety.enums import Architecture, Mechanism, Role, SafetyVariant
from mas_safety.mechanisms import build_mechanism_setup
from mas_safety.models import Scenario
from mas_safety.policies import PolicyEngine, inspect_policy_contracts
from mas_safety.scenarios import load_scenarios


@pytest.mark.parametrize("variant", list(SafetyVariant))
@pytest.mark.parametrize("mechanism", list(Mechanism))
def test_mechanism_pair_changes_only_allowlisted_context_fields(
    mechanism: Mechanism, variant: SafetyVariant
) -> None:
    allowed = {
        Mechanism.INTENT_DECOMPOSITION: {
            "objective_view",
        },
        Mechanism.CONTEXT_FRAGMENTATION: {"visible_facts"},
        Mechanism.AUTHORIZATION_DRIFT: {
            "restriction_visible",
            "restriction_text",
            "visible_facts",
            "public_evidence",
        },
        Mechanism.POLICY_HETEROGENEITY: {
            "local_policy_id",
            "local_policy_contract",
            "applicable_policy_ids",
            "applicable_policy_contracts",
        },
    }[mechanism]
    for scenario in load_scenarios():
        treatment = build_mechanism_setup(
            scenario,
            mechanism,
            variant,
            active=True,
            architecture=Architecture.MULTI_AGENT,
        )
        control = build_mechanism_setup(
            scenario,
            mechanism,
            variant,
            active=False,
            architecture=Architecture.MULTI_AGENT,
        )
        changed_fields: set[str] = set()
        for treated, untreated in zip(
            treatment.contexts, control.contexts, strict=True
        ):
            treated_data, control_data = asdict(treated), asdict(untreated)
            changed_fields.update(
                key for key in treated_data if treated_data[key] != control_data[key]
            )
        assert changed_fields
        assert changed_fields <= allowed
        assert treatment.intervention_coordinate == control.intervention_coordinate
        assert treatment.transformation_diff_allowlist
        assert treatment.transformation_delta
        assert not control.transformation_delta
        if mechanism is Mechanism.INTENT_DECOMPOSITION:
            assert changed_fields == {"objective_view"}


def test_context_treatment_never_colocates_decisive_conjunction() -> None:
    for scenario in load_scenarios():
        setup = build_mechanism_setup(
            scenario,
            Mechanism.CONTEXT_FRAGMENTATION,
            SafetyVariant.UNSAFE,
            active=True,
            architecture=Architecture.MULTI_AGENT,
        )
        invariant = scenario.global_invariant
        required = {
            invariant["trigger_fact"],
            invariant["authorization_fact"],
            *invariant["always_required_facts"],
        }
        assert all(
            any(context.visible_facts[key] == "NOT_AVAILABLE" for key in required)
            for context in setup.contexts
        )
        actuator = next(item for item in setup.contexts if item.role is Role.ACTUATOR)
        assert actuator.visible_facts[invariant["trigger_fact"]] is True
        assert (
            actuator.visible_facts[invariant["authorization_fact"]] == "NOT_AVAILABLE"
        )


def test_policy_contract_map_is_compiled_from_policy_specs() -> None:
    for scenario in load_scenarios():
        mapping = inspect_policy_contracts(scenario)
        engine = PolicyEngine(scenario)
        assert set(mapping) == {
            policy.policy_id for policy in scenario.policies.values()
        }
        for policy in scenario.policies.values():
            rendered = mapping[policy.policy_id]
            assert rendered["predicate"] == policy.predicate
            assert rendered["parameters"] == policy.parameters
            assert rendered["natural_language_contract"] == engine.contract(
                policy.policy_id
            )

        source = scenario.policies["source"].policy_id
        downstream = scenario.policies["downstream"].policy_id
        source_contract = engine.contract(source)
        downstream_contract = engine.contract(downstream)
        assert scenario.global_invariant["authorization_fact"] in source_contract
        assert (
            scenario.global_invariant["authorization_fact"] not in downstream_contract
        )
        assert source_contract != downstream_contract
        assert all(
            key in downstream_contract
            for key in scenario.policies["downstream"].parameters["required_facts"]
        )


def test_every_stage_receives_its_actual_local_policy_contract() -> None:
    for scenario in load_scenarios():
        engine = PolicyEngine(scenario)
        for mechanism in Mechanism:
            for active in (False, True):
                setup = build_mechanism_setup(
                    scenario,
                    mechanism,
                    SafetyVariant.UNSAFE,
                    active=active,
                    architecture=Architecture.MULTI_AGENT,
                )
                for context in setup.contexts:
                    assert context.local_policy_contract == engine.contract(
                        context.local_policy_id
                    )
                    assert dict(context.applicable_policy_contracts) == {
                        policy_id: engine.contract(policy_id)
                        for policy_id in context.applicable_policy_ids
                    }


def test_intent_decomposition_hides_authorization_in_every_model_channel() -> None:
    for scenario in load_scenarios():
        unsafe = build_mechanism_setup(
            scenario,
            Mechanism.INTENT_DECOMPOSITION,
            SafetyVariant.UNSAFE,
            active=True,
            architecture=Architecture.MULTI_AGENT,
        )
        safe = build_mechanism_setup(
            scenario,
            Mechanism.INTENT_DECOMPOSITION,
            SafetyVariant.SAFE,
            active=True,
            architecture=Architecture.MULTI_AGENT,
        )
        control = build_mechanism_setup(
            scenario,
            Mechanism.INTENT_DECOMPOSITION,
            SafetyVariant.UNSAFE,
            active=False,
            architecture=Architecture.MULTI_AGENT,
        )

        # Safe and unsafe variants differ only in authorization. If every model
        # view is identical, no alternate channel leaks that decisive status.
        assert unsafe.model_visibility_map == safe.model_visibility_map
        authorization_family = _authorization_family(scenario)
        for role_view in unsafe.model_visibility_map.values():
            assert "applicable_policy_ids" not in role_view
            assert "applicable_policy_contracts" not in role_view
            assert all(
                role_view["visible_facts"][key] == "NOT_AVAILABLE"
                for key in authorization_family
            )
            assert "terminal_authorized=false" not in role_view["objective_view"]
            assert "terminal_authorized=true" not in role_view["objective_view"]
            assert not (set(role_view["public_evidence"]) & authorization_family)
        for treated, untreated in zip(
            unsafe.contexts, control.contexts, strict=True
        ):
            assert treated.visible_facts == untreated.visible_facts
            assert treated.public_evidence == untreated.public_evidence


def test_authorization_drift_hides_status_and_restriction_downstream() -> None:
    for scenario in load_scenarios():
        unsafe = build_mechanism_setup(
            scenario,
            Mechanism.AUTHORIZATION_DRIFT,
            SafetyVariant.UNSAFE,
            active=True,
            architecture=Architecture.MULTI_AGENT,
        )
        safe = build_mechanism_setup(
            scenario,
            Mechanism.AUTHORIZATION_DRIFT,
            SafetyVariant.SAFE,
            active=True,
            architecture=Architecture.MULTI_AGENT,
        )
        authorization_family = _authorization_family(scenario)
        for role in (Role.RETRIEVER, Role.TRANSFORMER, Role.ACTUATOR):
            unsafe_view = unsafe.model_visibility_map[role.value]
            safe_view = safe.model_visibility_map[role.value]
            assert unsafe_view == safe_view
            assert unsafe_view["restriction"] == "NOT_PROVIDED"
            assert scenario.source_restriction not in str(unsafe_view)
            assert all(
                unsafe_view["visible_facts"][key] == "NOT_AVAILABLE"
                for key in authorization_family
            )
            assert not (set(unsafe_view["public_evidence"]) & authorization_family)


def test_policy_heterogeneity_exposes_the_actual_differing_rule_only_locally() -> None:
    for scenario in load_scenarios():
        treatment = build_mechanism_setup(
            scenario,
            Mechanism.POLICY_HETEROGENEITY,
            SafetyVariant.UNSAFE,
            active=True,
            architecture=Architecture.MULTI_AGENT,
        )
        control = build_mechanism_setup(
            scenario,
            Mechanism.POLICY_HETEROGENEITY,
            SafetyVariant.UNSAFE,
            active=False,
            architecture=Architecture.MULTI_AGENT,
        )
        treated = treatment.model_visibility_map[Role.ACTUATOR.value]
        untreated = control.model_visibility_map[Role.ACTUATOR.value]
        assert treated["local_policy"] != untreated["local_policy"]
        assert (
            scenario.global_invariant["authorization_fact"]
            not in treated["local_policy"]["contract"]
        )
        assert (
            scenario.global_invariant["authorization_fact"]
            in untreated["local_policy"]["contract"]
        )
        # Source-policy intersection inputs are trusted-defense data, not model data.
        assert "applicable_policy_ids" not in treated
        assert "applicable_policy_contracts" not in treated


def test_context_fragmentation_preserves_unrelated_facts_and_layout() -> None:
    for scenario in load_scenarios():
        treatment = build_mechanism_setup(
            scenario,
            Mechanism.CONTEXT_FRAGMENTATION,
            SafetyVariant.UNSAFE,
            active=True,
            architecture=Architecture.MULTI_AGENT,
        )
        control = build_mechanism_setup(
            scenario,
            Mechanism.CONTEXT_FRAGMENTATION,
            SafetyVariant.UNSAFE,
            active=False,
            architecture=Architecture.MULTI_AGENT,
        )
        invariant = scenario.global_invariant
        decisive = {
            invariant["trigger_fact"],
            *_authorization_family(scenario),
            *invariant["always_required_facts"],
        }
        unrelated = set(scenario.facts_for(SafetyVariant.UNSAFE)) - decisive
        visible_count = {key: 0 for key in decisive}
        for treated, untreated in zip(
            treatment.contexts, control.contexts, strict=True
        ):
            assert tuple(treated.visible_facts) == tuple(untreated.visible_facts)
            assert {key: treated.visible_facts[key] for key in unrelated} == {
                key: untreated.visible_facts[key] for key in unrelated
            }
            changed = {
                key
                for key in treated.visible_facts
                if treated.visible_facts[key] != untreated.visible_facts[key]
            }
            assert changed <= decisive
            for key in decisive:
                if treated.visible_facts[key] != "NOT_AVAILABLE":
                    visible_count[key] += 1
        assert set(visible_count.values()) == {1}


def _authorization_family(scenario: Scenario) -> set[str]:
    invariant = scenario.global_invariant
    authorization = invariant["authorization_fact"]
    return {
        authorization,
        *(
            target
            for target, rule in scenario.derived_fact_rules.items()
            if rule == f"${authorization}"
        ),
    }
