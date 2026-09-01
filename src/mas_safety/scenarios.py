from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .enums import PIPELINE_ROLES, Role
from .models import ActionSpec, PolicySpec, Scenario


class ScenarioValidationError(ValueError):
    """Raised when a scenario violates the executable schema contract."""


def default_scenario_dir() -> Path:
    packaged = Path(__file__).resolve().parent / "scenarios"
    if packaged.is_dir():
        return packaged
    return Path(__file__).resolve().parents[2] / "scenarios"


def load_scenario(path: str | Path) -> Scenario:
    source_path = Path(path)
    raw = json.loads(source_path.read_text(encoding="utf-8"))
    _validate_raw(raw, source_path)

    local_tasks = {Role(key): value for key, value in raw["local_tasks"].items()}
    actions = tuple(
        ActionSpec(
            role=Role(item["role"]),
            name=item["name"],
            terminal=bool(item["terminal"]),
            parameters=dict(item.get("parameters", {})),
        )
        for item in raw["actions"]
    )
    policies = {
        key: PolicySpec(
            policy_id=value["policy_id"],
            predicate=value["predicate"],
            parameters=dict(value.get("parameters", {})),
        )
        for key, value in raw["policies"].items()
    }
    context_fragments = {
        Role(key): tuple(value) for key, value in raw["context_fragments"].items()
    }
    public_evidence = {
        Role(key): dict(value)
        for key, value in raw["public_evidence_by_role"].items()
    }
    return Scenario(
        schema_version=raw["schema_version"],
        scenario_id=raw["scenario_id"],
        title=raw["title"],
        domain=raw["domain"],
        source_principal=raw["source_principal"],
        principals=tuple(dict(item) for item in raw["principals"]),
        authority_chain=tuple(dict(item) for item in raw["authority_chain"]),
        required_legitimate_work=raw["required_legitimate_work"],
        full_objective=raw["full_objective"],
        local_tasks=local_tasks,
        unsafe_facts=dict(raw["unsafe_facts"]),
        safe_fact_overrides=dict(raw["safe_fact_overrides"]),
        permissibility_fact=raw["permissibility_fact"],
        permissibility_diff_path=raw["permissibility_diff_path"],
        derived_fact_rules=dict(raw["derived_fact_rules"]),
        global_invariant=dict(raw["global_invariant"]),
        actions=actions,
        policies=policies,
        context_fragments=context_fragments,
        source_restriction=raw["source_restriction"],
        provenance_claim_keys=tuple(raw["provenance_claim_keys"]),
        public_evidence_by_role=public_evidence,
    )


def load_scenarios(directory: str | Path | None = None) -> list[Scenario]:
    scenario_dir = Path(directory) if directory else default_scenario_dir()
    paths = sorted(scenario_dir.glob("*.json"))
    if not paths:
        raise ScenarioValidationError(f"No scenario JSON files found in {scenario_dir}")
    scenarios = [load_scenario(path) for path in paths]
    ids = [item.scenario_id for item in scenarios]
    if len(ids) != len(set(ids)):
        raise ScenarioValidationError("Scenario identifiers must be unique")
    return scenarios


def _validate_raw(raw: dict[str, Any], path: Path) -> None:
    required = {
        "schema_version",
        "scenario_id",
        "title",
        "domain",
        "source_principal",
        "principals",
        "authority_chain",
        "required_legitimate_work",
        "full_objective",
        "local_tasks",
        "unsafe_facts",
        "safe_fact_overrides",
        "permissibility_fact",
        "permissibility_diff_path",
        "derived_fact_rules",
        "global_invariant",
        "actions",
        "policies",
        "context_fragments",
        "source_restriction",
        "provenance_claim_keys",
        "public_evidence_by_role",
    }
    missing = sorted(required - raw.keys())
    if missing:
        raise ScenarioValidationError(f"{path}: missing keys {missing}")
    principal_ids = [item.get("principal_id") for item in raw["principals"]]
    if (
        not principal_ids
        or len(principal_ids) != len(set(principal_ids))
        or raw["source_principal"] not in principal_ids
    ):
        raise ScenarioValidationError(
            f"{path}: principals must be unique and include source_principal"
        )
    for edge in raw["authority_chain"]:
        if edge.get("from_principal") not in principal_ids or edge.get(
            "to_principal"
        ) not in principal_ids:
            raise ScenarioValidationError(
                f"{path}: authority_chain refers to an unknown principal"
            )
        required_fact = edge.get("required_fact")
        if (
            required_fact not in raw["unsafe_facts"]
            or type(raw["unsafe_facts"][required_fact]) is not bool
        ):
            raise ScenarioValidationError(
                f"{path}: authority_chain required_fact must be a boolean ground-truth fact"
            )
    role_values = {role.value for role in PIPELINE_ROLES}
    for key in ("local_tasks", "context_fragments", "public_evidence_by_role"):
        supplied = set(raw[key])
        if supplied != role_values:
            raise ScenarioValidationError(
                f"{path}: {key} roles must be {sorted(role_values)}, got {sorted(supplied)}"
            )
    actions = raw["actions"]
    if [item.get("role") for item in actions] != [role.value for role in PIPELINE_ROLES]:
        raise ScenarioValidationError(f"{path}: actions must follow the fixed pipeline")
    if sum(bool(item.get("terminal")) for item in actions) != 1 or not actions[-1]["terminal"]:
        raise ScenarioValidationError(f"{path}: only the actuator action may be terminal")
    required_policies = {"intent", "context", "restriction", "source", "downstream", "single_agent"}
    if set(raw["policies"]) != required_policies:
        raise ScenarioValidationError(f"{path}: policies must be {sorted(required_policies)}")
    invariant = raw["global_invariant"]
    invariant_keys: Iterable[str] = (
        invariant["trigger_fact"],
        invariant["authorization_fact"],
        *invariant.get("always_required_facts", []),
    )
    missing_facts = sorted(key for key in invariant_keys if key not in raw["unsafe_facts"])
    if missing_facts:
        raise ScenarioValidationError(f"{path}: invariant refers to missing facts {missing_facts}")
    non_boolean_policy_facts = sorted(
        key for key in invariant_keys if type(raw["unsafe_facts"][key]) is not bool
    )
    if non_boolean_policy_facts:
        raise ScenarioValidationError(
            f"{path}: invariant facts must be boolean {non_boolean_policy_facts}"
        )
    unknown_overrides = sorted(set(raw["safe_fact_overrides"]) - set(raw["unsafe_facts"]))
    if unknown_overrides:
        raise ScenarioValidationError(f"{path}: safe overrides introduce facts {unknown_overrides}")
    if set(raw["safe_fact_overrides"]) != {raw["permissibility_fact"]}:
        raise ScenarioValidationError(
            f"{path}: matched safe variant must change only permissibility_fact"
        )
    if raw["permissibility_fact"] not in raw["unsafe_facts"]:
        raise ScenarioValidationError(f"{path}: permissibility_fact is not authoritative")
    if type(raw["safe_fact_overrides"][raw["permissibility_fact"]]) is not bool:
        raise ScenarioValidationError(f"{path}: safe permissibility override must be boolean")
    if invariant["terminal_action"] != actions[-1]["name"]:
        raise ScenarioValidationError(
            f"{path}: invariant terminal_action must match the actuator action"
        )
    for target, rule in raw["derived_fact_rules"].items():
        if not isinstance(rule, str) or not rule.startswith("$"):
            raise ScenarioValidationError(f"{path}: invalid derived rule for {target}")
        if rule[1:] not in raw["unsafe_facts"]:
            raise ScenarioValidationError(
                f"{path}: derived rule for {target} refers to missing fact {rule[1:]}"
            )
    for policy_name, policy in raw["policies"].items():
        for key in policy.get("parameters", {}).get("required_facts", []):
            if key not in raw["unsafe_facts"] or type(raw["unsafe_facts"][key]) is not bool:
                raise ScenarioValidationError(
                    f"{path}: policy {policy_name} requires non-boolean or missing fact {key}"
                )
    for role, keys in raw["context_fragments"].items():
        unknown = sorted(set(keys) - set(raw["unsafe_facts"]))
        if unknown:
            raise ScenarioValidationError(
                f"{path}: context fragment {role} refers to missing facts {unknown}"
            )
    missing_provenance = sorted(
        set(raw["provenance_claim_keys"]) - set(raw["unsafe_facts"])
    )
    if missing_provenance:
        raise ScenarioValidationError(
            f"{path}: provenance refers to missing facts {missing_provenance}"
        )


def resolve_evidence(template: dict[str, Any], facts: dict[str, Any]) -> dict[str, Any]:
    resolved: dict[str, Any] = {}
    for key, value in template.items():
        if isinstance(value, str) and value.startswith("$"):
            resolved[key] = facts[value[1:]]
        else:
            resolved[key] = value
    return resolved
