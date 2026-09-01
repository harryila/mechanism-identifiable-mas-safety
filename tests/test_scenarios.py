from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from mas_safety.enums import PIPELINE_ROLES, Role, SafetyVariant
from mas_safety.scenarios import ScenarioValidationError, load_scenario, load_scenarios


def test_two_pilot_scenarios_validate() -> None:
    scenarios = load_scenarios()
    assert len(scenarios) == 2
    assert {scenario.domain for scenario in scenarios} == {
        "healthcare",
        "finance_procurement",
    }
    for scenario in scenarios:
        assert tuple(action.role for action in scenario.actions) == PIPELINE_ROLES
        assert [action.terminal for action in scenario.actions] == [
            False,
            False,
            False,
            True,
        ]


def test_safe_variant_changes_one_authoritative_fact_only() -> None:
    for scenario in load_scenarios():
        assert set(scenario.safe_fact_overrides) == {scenario.permissibility_fact}
        unsafe = scenario.facts_for(SafetyVariant.UNSAFE)
        safe = scenario.facts_for(SafetyVariant.SAFE)
        changed = {key for key in unsafe if unsafe[key] != safe[key]}
        assert changed == {
            scenario.permissibility_fact,
            "authorization_marker",
            "terminal_authorized",
        }
        assert scenario.permissibility_diff_path.endswith(scenario.permissibility_fact)


def test_scenarios_contain_only_simulated_terminal_targets() -> None:
    for scenario in load_scenarios():
        terminal = scenario.actions[-1]
        assert terminal.name.startswith(("send_simulated_", "issue_simulated_"))
        serialized = str(asdict(terminal))
        assert ".invalid" in serialized or "Vector-Supply" in serialized


def test_policy_relevant_ground_truth_must_be_boolean(tmp_path: Path) -> None:
    source = Path("scenarios/finance_unapproved_payment.json")
    raw = json.loads(source.read_text(encoding="utf-8"))
    raw["unsafe_facts"]["approval_token_valid"] = "false"
    malformed = tmp_path / "malformed.json"
    malformed.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ScenarioValidationError, match="must be (a )?boolean"):
        load_scenario(malformed)


def test_context_fragment_map_routes_only_decisive_facts_exactly_once() -> None:
    for scenario in load_scenarios():
        invariant = scenario.global_invariant
        decisive = {
            invariant["trigger_fact"],
            invariant["authorization_fact"],
            *invariant["always_required_facts"],
        }
        routed = [
            key for role in PIPELINE_ROLES for key in scenario.context_fragments[role]
        ]
        assert set(routed) == decisive
        assert len(routed) == len(set(routed))
        assert all(
            not (set(scenario.context_fragments[role]) - decisive) for role in Role
        )


def test_context_fragment_rejects_unrelated_fact_routing(tmp_path: Path) -> None:
    source = Path("scenarios/finance_unapproved_payment.json")
    raw = json.loads(source.read_text(encoding="utf-8"))
    raw["context_fragments"]["planner"].append("invoice_id")
    malformed = tmp_path / "unrelated_fragment.json"
    malformed.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ScenarioValidationError, match="only decisive facts"):
        load_scenario(malformed)


def test_authorization_aliases_must_share_the_authoritative_source(
    tmp_path: Path,
) -> None:
    source = Path("scenarios/healthcare_patient_summary.json")
    raw = json.loads(source.read_text(encoding="utf-8"))
    raw["derived_fact_rules"]["authorization_marker"] = "$recipient_authorized"
    malformed = tmp_path / "leaky_alias.json"
    malformed.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ScenarioValidationError, match="authorization_marker"):
        load_scenario(malformed)


def test_downstream_policy_must_be_a_distinct_non_authorization_rule(
    tmp_path: Path,
) -> None:
    source = Path("scenarios/finance_unapproved_payment.json")
    raw = json.loads(source.read_text(encoding="utf-8"))
    raw["policies"]["downstream"]["parameters"]["required_facts"].append(
        "approval_token_valid"
    )
    malformed = tmp_path / "homogeneous_policy.json"
    malformed.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ScenarioValidationError, match="non-authorization rule"):
        load_scenario(malformed)
