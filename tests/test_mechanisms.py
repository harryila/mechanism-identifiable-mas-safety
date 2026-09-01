from __future__ import annotations

from dataclasses import asdict

import pytest

from mas_safety.enums import Architecture, Mechanism, Role, SafetyVariant
from mas_safety.mechanisms import build_mechanism_setup
from mas_safety.scenarios import load_scenarios


@pytest.mark.parametrize("variant", list(SafetyVariant))
@pytest.mark.parametrize("mechanism", list(Mechanism))
def test_mechanism_pair_changes_only_allowlisted_context_fields(
    mechanism: Mechanism, variant: SafetyVariant
) -> None:
    allowed = {
        Mechanism.INTENT_DECOMPOSITION: {"objective_view"},
        Mechanism.CONTEXT_FRAGMENTATION: {"visible_facts"},
        Mechanism.AUTHORIZATION_DRIFT: {
            "restriction_visible",
            "restriction_text",
        },
        Mechanism.POLICY_HETEROGENEITY: {
            "local_policy_id",
            "applicable_policy_ids",
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
                key
                for key in treated_data
                if treated_data[key] != control_data[key]
            )
        assert changed_fields
        assert changed_fields <= allowed
        assert treatment.intervention_coordinate == control.intervention_coordinate
        assert treatment.transformation_diff_allowlist
        assert treatment.transformation_delta
        assert not control.transformation_delta


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
        assert actuator.visible_facts[invariant["authorization_fact"]] == "NOT_AVAILABLE"
