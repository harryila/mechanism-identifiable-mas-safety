#!/usr/bin/env python3
"""Offline, outcome-blind construction checks for the Stage 3 workflow set.

This program deliberately loads only the construction allowlist modules.  It does
not import the package initializer, runner, prior outputs, or result artifacts, and
it writes nothing.  A successful run prints a machine-readable validation and hash
summary to stdout.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import types
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
SCENARIO_DIR = ROOT / "scenarios" / "confirmatory"

SLOTS: dict[str, dict[str, str]] = {
    "h1_research_data_export.json": {
        "slot": "H1",
        "scenario_id": "confirmatory.h1_research_data_export",
        "domain": "healthcare",
        "terminal_class": "disclosure",
        "authority_structure": "dual_control_or_multi_principal_approval",
    },
    "h2_specialist_portal_access.json": {
        "slot": "H2",
        "scenario_id": "confirmatory.h2_specialist_portal_access",
        "domain": "healthcare",
        "terminal_class": "access_grant",
        "authority_structure": "role_based_or_hierarchical_delegation",
    },
    "e1_transcript_release.json": {
        "slot": "E1",
        "scenario_id": "confirmatory.e1_transcript_release",
        "domain": "education",
        "terminal_class": "disclosure",
        "authority_structure": "principal_specific_consent_or_mandate",
    },
    "e2_grade_correction.json": {
        "slot": "E2",
        "scenario_id": "confirmatory.e2_grade_correction",
        "domain": "education",
        "terminal_class": "state_mutation",
        "authority_structure": "dual_control_or_multi_principal_approval",
    },
    "p1_benefit_disbursement.json": {
        "slot": "P1",
        "scenario_id": "confirmatory.p1_benefit_disbursement",
        "domain": "public_services",
        "terminal_class": "payment",
        "authority_structure": "rule_or_threshold_derived_authority",
    },
    "p2_permit_access_grant.json": {
        "slot": "P2",
        "scenario_id": "confirmatory.p2_permit_access_grant",
        "domain": "public_services",
        "terminal_class": "access_grant",
        "authority_structure": "role_based_or_hierarchical_delegation",
    },
    "f1_claim_payment.json": {
        "slot": "F1",
        "scenario_id": "confirmatory.f1_claim_payment",
        "domain": "finance_procurement",
        "terminal_class": "payment",
        "authority_structure": "rule_or_threshold_derived_authority",
    },
    "f2_vendor_bank_update.json": {
        "slot": "F2",
        "scenario_id": "confirmatory.f2_vendor_bank_update",
        "domain": "finance_procurement",
        "terminal_class": "state_mutation",
        "authority_structure": "dual_control_or_multi_principal_approval",
    },
}

EXPECTED_COORDINATES = {
    "intent_decomposition": (
        "objective_projection_mode",
        {"objective_view"},
    ),
    "context_fragmentation": ("fact_routing_mode", {"visible_facts"}),
    "authorization_drift": (
        "authorization_information_forwarded",
        {
            "restriction_visible",
            "restriction_text",
            "visible_facts",
            "public_evidence",
        },
    ),
    "policy_heterogeneity": (
        "policy_assignment_by_role.actuator",
        {
            "local_policy_id",
            "local_policy_contract",
            "applicable_policy_ids",
            "applicable_policy_contracts",
        },
    ),
}

TERMINAL_CLASS_PREFIX = {
    "disclosure": "send_simulated_",
    "access_grant": "grant_simulated_",
    "payment": "issue_simulated_",
    "state_mutation": "update_simulated_",
}


def _load_allowlisted_modules() -> None:
    """Load the explicit source allowlist without reading mas_safety/__init__.py."""

    package = types.ModuleType("mas_safety")
    package.__path__ = [str(ROOT / "src" / "mas_safety")]
    sys.modules["mas_safety"] = package
    for name in (
        "enums",
        "models",
        "provenance",
        "scenarios",
        "policies",
        "mechanisms",
        "environment",
        "stage4_observability",
    ):
        path = ROOT / "src" / "mas_safety" / f"{name}.py"
        spec = importlib.util.spec_from_file_location(f"mas_safety.{name}", path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Cannot load allowlisted module {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)


_load_allowlisted_modules()

from mas_safety.enums import (  # noqa: E402
    PIPELINE_ROLES,
    Architecture,
    Defense,
    Mechanism,
    Role,
    SafetyVariant,
)
from mas_safety.environment import SimulatedEnvironment  # noqa: E402
from mas_safety.mechanisms import build_mechanism_setup  # noqa: E402
from mas_safety.models import StageContext  # noqa: E402
from mas_safety.policies import (  # noqa: E402
    PolicyEngine,
    inspect_policy_contracts,
    terminal_permitted,
)
from mas_safety.provenance import (  # noqa: E402
    DEVELOPMENT_KEY_ID,
    DEVELOPMENT_SIGNING_KEY,
    sign_claims,
)
from mas_safety.scenarios import load_scenario  # noqa: E402
from mas_safety.stage4_observability import (  # noqa: E402
    DECLARED_VIEW_KEYS,
    HistoryMonitorObservation,
    LocalOnlyObservation,
    OmniscientReferenceObservation,
    PolicyIntersectionObservation,
    ProvenanceCarryingObservation,
    SourceAnchoringObservation,
    project_stage4_defense_view,
)


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _hash_value(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _nested_mapping_keys(value: object) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        keys.update(str(key) for key in value)
        for item in value.values():
            keys.update(_nested_mapping_keys(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            keys.update(_nested_mapping_keys(item))
    return keys


def _assert_projection_boundary_sources() -> None:
    projector_source = (
        ROOT / "src" / "mas_safety" / "stage4_observability.py"
    ).read_text(encoding="utf-8")
    verifier_source = Path(__file__).read_text(encoding="utf-8")
    assert "from .defenses import" not in projector_source
    assert "from .policies import" not in projector_source
    forbidden_verifier_import = "from mas_safety." + "defenses import"
    forbidden_engine_call = "Defense" + "Engine("
    assert forbidden_verifier_import not in verifier_source
    assert forbidden_engine_call not in verifier_source


def _assert_malformed_projection_payloads_rejected() -> int:
    class RichObject:
        pass

    class DictSubclass(dict):
        pass

    class ListSubclass(list):
        pass

    class TupleSubclass(tuple):
        pass

    class StringSubclass(str):
        pass

    class IntegerSubclass(int):
        pass

    cycle_dict: dict[str, object] = {}
    cycle_dict["self"] = cycle_dict
    cycle_list: list[object] = []
    cycle_list.append(cycle_list)

    def provenance(claims: object, **overrides: object) -> object:
        values: dict[str, object] = {
            "artifact_id": "run:scenario:3",
            "origin_scenario": "confirmatory.synthetic",
            "signed_claims": claims,
            "signature": "hmac-sha256:synthetic",
            "signature_algorithm": "hmac-sha256",
            "signature_key_id": "synthetic-key",
        }
        values.update(overrides)
        return ProvenanceCarryingObservation(**values)

    malformed: list[tuple[Defense, object]] = [
        (Defense.HISTORY_MONITOR, HistoryMonitorObservation([{}])),
        (Defense.HISTORY_MONITOR, HistoryMonitorObservation(TupleSubclass(({},)))),
        (Defense.HISTORY_MONITOR, HistoryMonitorObservation(("scalar",))),
        (Defense.HISTORY_MONITOR, HistoryMonitorObservation((DictSubclass({"ok": 1}),))),
        (Defense.HISTORY_MONITOR, HistoryMonitorObservation(({"nested": RichObject()},))),
        (Defense.HISTORY_MONITOR, HistoryMonitorObservation(({"nested": ListSubclass([1])},))),
        (Defense.HISTORY_MONITOR, HistoryMonitorObservation((cycle_dict,))),
        (Defense.HISTORY_MONITOR, HistoryMonitorObservation(({"nested": (1, 2)},))),
        (Defense.HISTORY_MONITOR, HistoryMonitorObservation(({StringSubclass("key"): 1},))),
        (Defense.HISTORY_MONITOR, HistoryMonitorObservation(({"bad": float("nan")},))),
        (Defense.PROVENANCE_CARRYING, provenance("scalar")),
        (Defense.PROVENANCE_CARRYING, provenance(DictSubclass({"ok": True}))),
        (Defense.PROVENANCE_CARRYING, provenance({1: "bad-key"})),
        (Defense.PROVENANCE_CARRYING, provenance({"nested": RichObject()})),
        (Defense.PROVENANCE_CARRYING, provenance({"bad": float("inf")})),
        (Defense.PROVENANCE_CARRYING, provenance({"cycle": cycle_list})),
        (
            Defense.PROVENANCE_CARRYING,
            provenance({}, artifact_id=StringSubclass("run:scenario:3")),
        ),
        (
            Defense.PROVENANCE_CARRYING,
            provenance({}, signature_algorithm=" hmac-sha256"),
        ),
        (Defense.PROVENANCE_CARRYING, provenance({"bad": IntegerSubclass(1)})),
        (
            Defense.POLICY_INTERSECTION,
            PolicyIntersectionObservation(["policy.v1"], {}),
        ),
        (
            Defense.POLICY_INTERSECTION,
            PolicyIntersectionObservation(TupleSubclass(("policy.v1",)), {}),
        ),
        (Defense.POLICY_INTERSECTION, PolicyIntersectionObservation((), {})),
        (Defense.POLICY_INTERSECTION, PolicyIntersectionObservation(("",), {})),
        (
            Defense.POLICY_INTERSECTION,
            PolicyIntersectionObservation((" policy.v1",), {}),
        ),
        (
            Defense.POLICY_INTERSECTION,
            PolicyIntersectionObservation(("policy.v1", "policy.v1"), {}),
        ),
        (
            Defense.POLICY_INTERSECTION,
            PolicyIntersectionObservation((StringSubclass("policy.v1"),), {}),
        ),
        (
            Defense.POLICY_INTERSECTION,
            PolicyIntersectionObservation("policy.v1", {}),
        ),
        (
            Defense.POLICY_INTERSECTION,
            PolicyIntersectionObservation(("policy.v1",), "scalar"),
        ),
        (
            Defense.POLICY_INTERSECTION,
            PolicyIntersectionObservation(("policy.v1",), DictSubclass({"ok": True})),
        ),
        (
            Defense.POLICY_INTERSECTION,
            PolicyIntersectionObservation(("policy.v1",), {1: True}),
        ),
        (
            Defense.POLICY_INTERSECTION,
            PolicyIntersectionObservation(("policy.v1",), {"nested": RichObject()}),
        ),
        (
            Defense.POLICY_INTERSECTION,
            PolicyIntersectionObservation(("policy.v1",), {"bad": float("-inf")}),
        ),
        (
            Defense.POLICY_INTERSECTION,
            PolicyIntersectionObservation(("policy.v1",), {"nested": (1, 2)}),
        ),
        (
            Defense.POLICY_INTERSECTION,
            PolicyIntersectionObservation(("policy.v1",), cycle_dict),
        ),
        (
            Defense.POLICY_INTERSECTION,
            PolicyIntersectionObservation(("policy.v1",), {"nested": ListSubclass([1])}),
        ),
        (Defense.OMNISCIENT_REFERENCE, OmniscientReferenceObservation("scalar")),
        (
            Defense.OMNISCIENT_REFERENCE,
            OmniscientReferenceObservation(DictSubclass({"ok": True})),
        ),
        (Defense.OMNISCIENT_REFERENCE, OmniscientReferenceObservation({1: True})),
        (
            Defense.OMNISCIENT_REFERENCE,
            OmniscientReferenceObservation({"nested": RichObject()}),
        ),
        (Defense.OMNISCIENT_REFERENCE, OmniscientReferenceObservation(cycle_dict)),
        (
            Defense.OMNISCIENT_REFERENCE,
            OmniscientReferenceObservation({"nested": (1, 2)}),
        ),
        (
            Defense.OMNISCIENT_REFERENCE,
            OmniscientReferenceObservation({"bad": float("-inf")}),
        ),
        (
            Defense.OMNISCIENT_REFERENCE,
            OmniscientReferenceObservation({"nested": StringSubclass("value")}),
        ),
        (
            Defense.SOURCE_ANCHORING,
            SourceAnchoringObservation(1, True, False, "restriction"),
        ),
        (
            Defense.SOURCE_ANCHORING,
            SourceAnchoringObservation(True, "yes", False, "restriction"),
        ),
        (
            Defense.SOURCE_ANCHORING,
            SourceAnchoringObservation(True, True, None, "restriction"),
        ),
        (
            Defense.SOURCE_ANCHORING,
            SourceAnchoringObservation(
                True, True, False, StringSubclass("restriction")
            ),
        ),
        (
            Defense.SOURCE_ANCHORING,
            SourceAnchoringObservation(True, True, False, " padded "),
        ),
    ]

    for defense, observation in malformed:
        try:
            project_stage4_defense_view(defense, observation)
        except (TypeError, ValueError):
            continue
        raise AssertionError(
            f"Malformed payload was accepted for {defense.value}: "
            f"{type(observation).__name__}"
        )
    return len(malformed)


def _assert_slotted_observation_capabilities() -> Counter[str]:
    observations: tuple[tuple[Defense, object], ...] = (
        (Defense.LOCAL_ONLY, LocalOnlyObservation()),
        (
            Defense.HISTORY_MONITOR,
            HistoryMonitorObservation(({"workflow_stage": "planner"},)),
        ),
        (
            Defense.SOURCE_ANCHORING,
            SourceAnchoringObservation(True, True, False, "synthetic restriction"),
        ),
        (
            Defense.PROVENANCE_CARRYING,
            ProvenanceCarryingObservation(
                artifact_id="run:scenario:3",
                origin_scenario="confirmatory.synthetic",
                signed_claims={"authorized": True},
                signature="hmac-sha256:synthetic",
                signature_algorithm="hmac-sha256",
                signature_key_id="synthetic-key",
            ),
        ),
        (
            Defense.POLICY_INTERSECTION,
            PolicyIntersectionObservation(("policy.synthetic.v1",), {"ready": True}),
        ),
        (
            Defense.OMNISCIENT_REFERENCE,
            OmniscientReferenceObservation({"authorized": True}),
        ),
    )
    counts: Counter[str] = Counter()
    for defense, observation in observations:
        view = project_stage4_defense_view(defense, observation)
        assert set(view) == DECLARED_VIEW_KEYS[defense]
        counts["slotted_valid_projection_assertions"] += 1

        assert not hasattr(observation, "__dict__")
        counts["observation_without_dict_assertions"] += 1
        try:
            vars(observation)
        except TypeError:
            counts["vars_rejection_assertions"] += 1
        else:
            raise AssertionError(f"{type(observation).__name__} exposes vars()")

        try:
            setattr(observation, "undeclared_rich_state", {"rich": object()})
        except (AttributeError, TypeError):
            counts["undeclared_attribute_assignment_rejections"] += 1
        else:
            raise AssertionError(
                f"{type(observation).__name__} accepted undeclared assignment"
            )

        try:
            object.__setattr__(
                observation, "undeclared_rich_state", {"rich": object()}
            )
        except (AttributeError, TypeError):
            counts["object_setattr_injection_rejections"] += 1
        else:
            raise AssertionError(
                f"{type(observation).__name__} accepted object.__setattr__ injection"
            )
        assert not hasattr(observation, "undeclared_rich_state")
    assert len(observations) == 6
    return counts


def _assert_projection_defensive_copy(
    defense: Defense,
    observation: object,
    view: dict[str, object],
) -> int:
    baseline = _canonical(view)
    probe_key = "__stage4_defensive_copy_probe__"
    mutable_input: dict[str, object] | None = None
    if type(observation) is HistoryMonitorObservation:
        mutable_input = observation.shareable_history[0]
    elif type(observation) is ProvenanceCarryingObservation:
        mutable_input = observation.signed_claims
    elif type(observation) is PolicyIntersectionObservation:
        mutable_input = observation.gate_visible_facts
    elif type(observation) is OmniscientReferenceObservation:
        mutable_input = observation.ground_truth_facts

    input_copy_assertions = 0
    if mutable_input is not None:
        assert probe_key not in mutable_input
        mutable_input[probe_key] = {"nested": ["mutated-after-projection"]}
        try:
            assert _canonical(view) == baseline
        finally:
            del mutable_input[probe_key]
        input_copy_assertions = 1

    view[probe_key] = {"nested": ["mutated-return-value"]}
    try:
        assert _canonical(project_stage4_defense_view(defense, observation)) == baseline
    finally:
        del view[probe_key]
    return input_copy_assertions


def _context_for_policy(scenario: Any, policy_name: str, variant: SafetyVariant) -> Any:
    facts = scenario.facts_for(variant)
    policy = scenario.policies[policy_name]
    engine = PolicyEngine(scenario)
    return StageContext(
        role=Role.ACTUATOR,
        task=scenario.local_tasks[Role.ACTUATOR],
        objective_view=scenario.full_objective.format(
            terminal_authorized=str(bool(facts["terminal_authorized"])).lower()
        ),
        visible_facts=dict(facts),
        local_policy_id=policy.policy_id,
        local_policy_contract=engine.contract(policy.policy_id),
        restriction_visible=policy_name == "restriction",
        restriction_text=scenario.source_restriction,
        shareable_message=scenario.local_tasks[Role.ACTUATOR],
        public_evidence={},
        applicable_policy_ids=(policy.policy_id,),
        applicable_policy_contracts=((policy.policy_id, engine.contract(policy.policy_id)),),
    )


def _observation_from_ambient(
    defense: Defense, ambient: dict[str, object]
) -> object:
    """Select only the declared source fields for one capability-minimal input."""

    if defense is Defense.LOCAL_ONLY:
        return LocalOnlyObservation()
    if defense is Defense.HISTORY_MONITOR:
        history = ambient["shareable_history"]
        assert isinstance(history, tuple)
        return HistoryMonitorObservation(tuple(dict(item) for item in history))
    if defense is Defense.SOURCE_ANCHORING:
        anchor = ambient["source_anchor"]
        assert isinstance(anchor, dict)
        return SourceAnchoringObservation(
            restriction_present=anchor["restriction_present"],
            evaluation_complete=anchor["evaluation_complete"],
            restriction_active=anchor["restriction_active"],
            restriction_text=anchor["restriction_text"],
        )
    if defense is Defense.PROVENANCE_CARRYING:
        metadata = ambient["artifact_metadata"]
        assert isinstance(metadata, dict)
        return ProvenanceCarryingObservation(
            artifact_id=metadata["artifact_id"],
            origin_scenario=metadata["origin_scenario"],
            signed_claims=dict(metadata["signed_claims"]),
            signature=metadata["signature"],
            signature_algorithm=metadata["signature_algorithm"],
            signature_key_id=metadata["signature_key_id"],
        )
    if defense is Defense.POLICY_INTERSECTION:
        policy_ids = ambient["applicable_policy_ids"]
        gate_facts = ambient["gate_visible_facts"]
        assert isinstance(policy_ids, tuple) and isinstance(gate_facts, dict)
        return PolicyIntersectionObservation(
            applicable_policy_ids=policy_ids,
            gate_visible_facts=dict(gate_facts),
        )
    if defense is Defense.OMNISCIENT_REFERENCE:
        facts = ambient["ground_truth_facts"]
        assert isinstance(facts, dict)
        return OmniscientReferenceObservation(dict(facts))
    raise ValueError(defense)


def _counterfactual_ambient(
    defense: Defense, ambient: dict[str, object]
) -> dict[str, object]:
    """Vary every ambient field outside the selected defense's declaration."""

    declared_ambient_fields = {
        Defense.LOCAL_ONLY: frozenset(),
        Defense.HISTORY_MONITOR: frozenset({"shareable_history"}),
        Defense.SOURCE_ANCHORING: frozenset({"source_anchor"}),
        Defense.PROVENANCE_CARRYING: frozenset({"artifact_metadata"}),
        Defense.POLICY_INTERSECTION: frozenset(
            {"applicable_policy_ids", "gate_visible_facts"}
        ),
        Defense.OMNISCIENT_REFERENCE: frozenset({"ground_truth_facts"}),
    }[defense]
    changed: dict[str, object] = {}
    for key, value in ambient.items():
        if key in declared_ambient_fields:
            changed[key] = value
        elif type(value) is bool:
            changed[key] = not value
        elif isinstance(value, str):
            changed[key] = f"COUNTERFACTUAL_UNDECLARED::{key}"
        elif isinstance(value, tuple):
            changed[key] = ({"counterfactual_undeclared": key},)
        elif isinstance(value, dict):
            changed[key] = {"counterfactual_undeclared": key}
        elif isinstance(value, list):
            changed[key] = [{"counterfactual_undeclared": key}]
        else:
            changed[key] = {"counterfactual_undeclared": key}
    assert any(changed[key] != ambient[key] for key in set(ambient) - declared_ambient_fields)
    return changed


def _defense_view_projections_and_independence(
    scenario: Any,
) -> tuple[list[dict[str, object]], Counter[str]]:
    """Check pure declared projections without evaluating historical defenses."""

    matrices: list[dict[str, object]] = []
    counts: Counter[str] = Counter()
    run_id = "stage3-construction-verification"
    for mechanism in Mechanism:
        for active in (False, True):
            for variant in SafetyVariant:
                facts = scenario.facts_for(variant)
                setup = build_mechanism_setup(
                    scenario,
                    mechanism,
                    variant,
                    active=active,
                    architecture=Architecture.MULTI_AGENT,
                )
                context = setup.contexts[-1]
                history = tuple(dict(item.public_evidence) for item in setup.contexts)
                claims = {key: facts[key] for key in scenario.provenance_claim_keys}
                artifact_id = f"{run_id}:{scenario.scenario_id}:3"
                signature = sign_claims(
                    DEVELOPMENT_SIGNING_KEY,
                    scenario_id=scenario.scenario_id,
                    artifact_id=artifact_id,
                    claims=claims,
                )
                artifact_metadata = {
                    "artifact_id": artifact_id,
                    "origin_scenario": scenario.scenario_id,
                    "signed_claims": claims,
                    "signature": signature,
                    "signature_algorithm": "hmac-sha256",
                    "signature_key_id": DEVELOPMENT_KEY_ID,
                }
                ambient: dict[str, object] = {
                    "shareable_history": history,
                    "source_anchor": dict(setup.source_anchor),
                    "artifact_metadata": artifact_metadata,
                    "applicable_policy_ids": tuple(context.applicable_policy_ids),
                    "gate_visible_facts": dict(context.visible_facts),
                    "ground_truth_facts": dict(facts),
                    "task": context.task,
                    "objective_view": context.objective_view,
                    "restriction_visible": context.restriction_visible,
                    "restriction_text": context.restriction_text,
                    "delegation_message": context.shareable_message,
                    "local_policy_id": context.local_policy_id,
                    "local_policy_contract": context.local_policy_contract,
                    "applicable_policy_contracts": context.applicable_policy_contracts,
                    "artifact_body": "SYNTHETIC_UNDECLARED_ARTIFACT_BODY",
                    "tool_log": [{"synthetic_undeclared_tool_event": True}],
                }

                views: dict[str, dict[str, object]] = {}
                for defense in Defense:
                    observation = _observation_from_ambient(defense, ambient)
                    view = project_stage4_defense_view(defense, observation)
                    assert set(view) == DECLARED_VIEW_KEYS[defense]
                    counts["stage4_projected_views"] += 1

                    counterfactual = _counterfactual_ambient(defense, ambient)
                    counterfactual_observation = _observation_from_ambient(
                        defense, counterfactual
                    )
                    assert project_stage4_defense_view(
                        defense, counterfactual_observation
                    ) == view
                    counts[
                        "counterfactual_undeclared_input_independence_assertions"
                    ] += 1

                    try:
                        project_stage4_defense_view(defense, context)
                    except TypeError:
                        counts["rich_stage_context_rejection_assertions"] += 1
                    else:
                        raise AssertionError(
                            f"{defense.value} projector accepted a rich StageContext"
                        )
                    counts[
                        "mutable_input_defensive_copy_assertions"
                    ] += _assert_projection_defensive_copy(
                        defense, observation, view
                    )
                    counts["fresh_output_defensive_copy_assertions"] += 1
                    views[defense.value] = view

                hidden_sidecar_keys = {
                    "origin_scenario",
                    "signed_claims",
                    "signature",
                    "signature_algorithm",
                    "signature_key_id",
                }
                provenance_metadata = views[Defense.PROVENANCE_CARRYING.value][
                    "artifact_metadata"
                ]
                assert isinstance(provenance_metadata, dict)
                assert set(provenance_metadata) == {
                    "artifact_id",
                    *hidden_sidecar_keys,
                }
                assert all(
                    hidden_sidecar_keys.isdisjoint(_nested_mapping_keys(view))
                    for defense_name, view in views.items()
                    if defense_name != Defense.PROVENANCE_CARRYING.value
                )
                assert history == tuple(
                    dict(item.public_evidence) for item in setup.contexts
                )
                matrices.append(
                    {
                        "mechanism": mechanism.value,
                        "active": active,
                        "variant": variant.value,
                        "view_hashes": {
                            key: _hash_value(value) for key, value in views.items()
                        },
                    }
                )
                counts["stage4_defense_projection_matrices"] += 1
    return matrices, counts


def verify() -> dict[str, object]:
    schema_path = ROOT / "schemas" / "scenario.schema.json"
    trace_schema_path = ROOT / "schemas" / "trace.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    trace_schema = json.loads(trace_schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator.check_schema(trace_schema)
    validator = Draft202012Validator(schema)
    _assert_projection_boundary_sources()
    malformed_payload_rejections = _assert_malformed_projection_payloads_rejected()
    slotted_capability_counts = _assert_slotted_observation_capabilities()

    actual_files = sorted(path.name for path in SCENARIO_DIR.glob("*.json"))
    assert actual_files == sorted(SLOTS), (actual_files, sorted(SLOTS))

    loaded: list[tuple[Path, dict[str, Any], Any, dict[str, str]]] = []
    for filename, slot in SLOTS.items():
        path = SCENARIO_DIR / filename
        raw = json.loads(path.read_text(encoding="utf-8"))
        validator.validate(raw)
        scenario = load_scenario(path)
        assert scenario.scenario_id == slot["scenario_id"]
        assert scenario.domain == slot["domain"]
        loaded.append((path, raw, scenario, slot))

    assert len(loaded) == 8
    assert len({scenario.scenario_id for _, _, scenario, _ in loaded}) == 8
    assert Counter(slot["domain"] for slot in SLOTS.values()) == {
        "healthcare": 2,
        "education": 2,
        "public_services": 2,
        "finance_procurement": 2,
    }
    assert Counter(slot["terminal_class"] for slot in SLOTS.values()) == {
        "disclosure": 2,
        "access_grant": 2,
        "payment": 2,
        "state_mutation": 2,
    }
    authority_coverage = {
        slot["authority_structure"] for slot in SLOTS.values()
    }
    assert len(authority_coverage) == 4

    development_ids = {
        "healthcare.patient_summary_disclosure",
        "finance.unapproved_payment",
    }
    development_terminal_actions = {
        "send_simulated_document",
        "issue_simulated_payment",
    }
    terminal_names: set[str] = set()
    terminal_payloads: set[str] = set()
    source_policies: set[str] = set()
    routing_signatures: set[str] = set()
    authority_signatures: set[str] = set()
    restrictions: set[str] = set()
    package_hashes: dict[str, dict[str, str]] = {}
    projection_counts: Counter[str] = Counter()

    for path, raw, scenario, slot in loaded:
        assert scenario.scenario_id not in development_ids
        terminal = scenario.actions[-1]
        assert terminal.name.startswith(TERMINAL_CLASS_PREFIX[slot["terminal_class"]])
        assert terminal.name not in development_terminal_actions
        assert "simulated" in terminal.name
        assert raw["unsafe_facts"]["synthetic_fixture"] is True
        assert not any(
            marker in _canonical(asdict(action)).lower()
            for action in scenario.actions
            for marker in ("https://", "http://", "@gmail.", "@outlook.")
        )

        assert tuple(action.role for action in scenario.actions) == PIPELINE_ROLES
        assert [action.terminal for action in scenario.actions] == [False, False, False, True]
        assert scenario.global_invariant["terminal_action"] == terminal.name

        unsafe = scenario.facts_for(SafetyVariant.UNSAFE)
        safe = scenario.facts_for(SafetyVariant.SAFE)
        changed = {key for key in unsafe if unsafe[key] != safe[key]}
        assert changed == {
            scenario.permissibility_fact,
            "authorization_marker",
            "terminal_authorized",
        }
        assert set(scenario.safe_fact_overrides) == {scenario.permissibility_fact}
        assert scenario.permissibility_diff_path == f"/world/{scenario.permissibility_fact}"
        assert unsafe[scenario.permissibility_fact] is False
        assert safe[scenario.permissibility_fact] is True
        assert not terminal_permitted(unsafe, scenario.global_invariant)
        assert terminal_permitted(safe, scenario.global_invariant)

        unsafe_env = SimulatedEnvironment()
        safe_env = SimulatedEnvironment()
        unsafe_result = unsafe_env.execute(terminal)
        safe_result = safe_env.execute(terminal)
        assert unsafe_result.ok and safe_result.ok
        assert unsafe_env.snapshot()["terminal_action"] == terminal.name
        assert safe_env.snapshot()["terminal_action"] == terminal.name
        assert not terminal_permitted(unsafe, scenario.global_invariant)
        assert terminal_permitted(safe, scenario.global_invariant)

        principal_ids = {item["principal_id"] for item in scenario.principals}
        assert scenario.source_principal in principal_ids
        assert all(
            edge["from_principal"] in principal_ids
            and edge["to_principal"] in principal_ids
            and type(safe[edge["required_fact"]]) is bool
            and safe[edge["required_fact"]] is True
            for edge in scenario.authority_chain
        )
        assert any(
            unsafe[edge["required_fact"]] is False
            for edge in scenario.authority_chain
        )

        decisive = {
            scenario.global_invariant["trigger_fact"],
            scenario.global_invariant["authorization_fact"],
            *scenario.global_invariant["always_required_facts"],
        }
        routed = [
            key
            for role in PIPELINE_ROLES
            for key in scenario.context_fragments[role]
        ]
        assert set(routed) == decisive
        assert len(routed) == len(set(routed))
        assert scenario.global_invariant["trigger_fact"] in scenario.context_fragments[Role.ACTUATOR]
        assert scenario.global_invariant["authorization_fact"] not in scenario.context_fragments[Role.ACTUATOR]

        policy_map = inspect_policy_contracts(scenario)
        assert len(policy_map) == 6
        policy_engine = PolicyEngine(scenario)
        for variant in SafetyVariant:
            for policy_name, policy in scenario.policies.items():
                context = _context_for_policy(scenario, policy_name, variant)
                terminal_decision = policy_engine.evaluate(policy.policy_id, terminal, context)
                nonterminal_decision = policy_engine.evaluate(
                    policy.policy_id, scenario.actions[0], context
                )
                assert terminal_decision.predicate_id == policy.policy_id
                assert nonterminal_decision.allowed

        rendered_views: list[dict[str, object]] = []
        for mechanism in Mechanism:
            coordinate, allowed_fields = EXPECTED_COORDINATES[mechanism.value]
            for variant in SafetyVariant:
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
                assert treatment.intervention_coordinate == coordinate
                assert control.intervention_coordinate == coordinate
                assert treatment.transformation_delta
                assert not control.transformation_delta
                assert treatment.transformation_diff_allowlist == control.transformation_diff_allowlist
                changed_fields: set[str] = set()
                for treated_context, control_context in zip(
                    treatment.contexts, control.contexts, strict=True
                ):
                    treated_data = asdict(treated_context)
                    control_data = asdict(control_context)
                    changed_fields.update(
                        key
                        for key in treated_data
                        if treated_data[key] != control_data[key]
                    )
                assert changed_fields
                assert changed_fields <= allowed_fields
                if mechanism is Mechanism.INTENT_DECOMPOSITION:
                    assert changed_fields == {"objective_view"}
                assert all(
                    set(view) == {
                        "role",
                        "task",
                        "objective_view",
                        "visible_facts",
                        "local_policy",
                        "restriction",
                        "shareable_message",
                        "public_evidence",
                    }
                    for view in treatment.model_visibility_map.values()
                )
                rendered_views.extend(
                    (
                        {
                            "mechanism": mechanism.value,
                            "variant": variant.value,
                            "active": True,
                            "views": treatment.model_visibility_map,
                        },
                        {
                            "mechanism": mechanism.value,
                            "variant": variant.value,
                            "active": False,
                            "views": control.model_visibility_map,
                        },
                    )
                )

            if mechanism in {Mechanism.INTENT_DECOMPOSITION, Mechanism.AUTHORIZATION_DRIFT}:
                unsafe_setup = build_mechanism_setup(
                    scenario,
                    mechanism,
                    SafetyVariant.UNSAFE,
                    active=True,
                    architecture=Architecture.MULTI_AGENT,
                )
                safe_setup = build_mechanism_setup(
                    scenario,
                    mechanism,
                    SafetyVariant.SAFE,
                    active=True,
                    architecture=Architecture.MULTI_AGENT,
                )
                views_to_compare = (
                    tuple(unsafe_setup.model_visibility_map)
                    if mechanism is Mechanism.INTENT_DECOMPOSITION
                    else ("retriever", "transformer", "actuator")
                )
                for role_name in views_to_compare:
                    assert unsafe_setup.model_visibility_map[role_name] == safe_setup.model_visibility_map[role_name]
                    view = unsafe_setup.model_visibility_map[role_name]
                    assert view["visible_facts"][scenario.permissibility_fact] == "NOT_AVAILABLE"
                    assert "terminal_authorized=false" not in view["objective_view"]
                    assert "terminal_authorized=true" not in view["objective_view"]
                if mechanism is Mechanism.AUTHORIZATION_DRIFT:
                    for role_name in views_to_compare:
                        assert unsafe_setup.model_visibility_map[role_name]["restriction"] == "NOT_PROVIDED"

        projection_matrices, scenario_projection_counts = (
            _defense_view_projections_and_independence(scenario)
        )
        projection_counts.update(scenario_projection_counts)

        assert terminal.name not in terminal_names
        terminal_names.add(terminal.name)
        terminal_payload = _canonical(asdict(terminal))
        assert terminal_payload not in terminal_payloads
        terminal_payloads.add(terminal_payload)
        source_policy = scenario.policies["source"].policy_id
        assert source_policy not in source_policies
        source_policies.add(source_policy)
        routing_signature = _canonical(
            {role.value: scenario.context_fragments[role] for role in PIPELINE_ROLES}
        )
        assert routing_signature not in routing_signatures
        routing_signatures.add(routing_signature)
        authority_signature = _canonical(scenario.authority_chain)
        assert authority_signature not in authority_signatures
        authority_signatures.add(authority_signature)
        assert scenario.source_restriction not in restrictions
        restrictions.add(scenario.source_restriction)

        package_hashes[slot["slot"]] = {
            "scenario_file_sha256": _hash_file(path),
            "canonical_scenario_sha256": _hash_value(asdict(scenario)),
            "policy_bundle_sha256": _hash_value(
                {key: asdict(value) for key, value in scenario.policies.items()}
            ),
            "action_bundle_sha256": _hash_value([asdict(item) for item in scenario.actions]),
            "canonical_role_input_matrix_sha256": _hash_value(rendered_views),
            "stage4_defense_projection_matrix_sha256": _hash_value(
                projection_matrices
            ),
        }

    source_hashes = {
        name: _hash_file(ROOT / "src" / "mas_safety" / name)
        for name in (
            "scenarios.py",
            "models.py",
            "mechanisms.py",
            "policies.py",
            "defenses.py",
            "environment.py",
            "enums.py",
            "provenance.py",
            "stage4_observability.py",
        )
    }

    return {
        "status": "pass",
        "workflow_count": 8,
        "slot_order": ["H1", "H2", "E1", "E2", "P1", "P2", "F1", "F2"],
        "domain_counts": dict(sorted(Counter(slot["domain"] for slot in SLOTS.values()).items())),
        "terminal_class_counts": dict(
            sorted(Counter(slot["terminal_class"] for slot in SLOTS.values()).items())
        ),
        "authority_structure_coverage": sorted(authority_coverage),
        "validation_counts": {
            "scenario_instances_validated": 8,
            "mechanism_on_off_variant_pairs": 64,
            "policy_engine_construction_totality_evaluations": 192,
            "simulated_terminal_semantic_checks": 16,
            **dict(sorted(projection_counts.items())),
            **dict(sorted(slotted_capability_counts.items())),
            "malformed_or_rich_nested_payload_rejections": malformed_payload_rejections,
            "historical_defense_engine_decisions": 0,
        },
        "hard_checks": {
            "formal_scenario_schema": True,
            "formal_trace_schema_well_formed": True,
            "loader_contract": True,
            "exact_safe_unsafe_authoritative_diff": True,
            "unsafe_forbidden_and_safe_required_terminal_semantics": True,
            "total_policy_programs": True,
            "executable_authority_graphs": True,
            "mechanism_single_coordinate_pairs": True,
            "positive_and_negative_manipulation_checks": True,
            "decisive_fact_routing_exactly_once": True,
            "authorization_channel_masking": True,
            "stage4_defense_view_projection_contracts": True,
            "stage4_projection_counterfactual_independence": True,
            "stage4_projector_rejects_rich_context": True,
            "stage4_strict_recursive_json_validation": True,
            "stage4_malformed_nested_payload_rejection": True,
            "stage4_defensive_copying": True,
            "stage4_slotted_observation_capability_boundary": True,
            "historical_defense_engine_not_imported_or_called": True,
            "policy_engine_construction_totality_separate_from_defense_projection": True,
            "provenance_sidecar_isolation_between_projected_views": True,
            "simulated_only_synthetic_fixtures": True,
            "substantive_disjointness": True,
            "exact_slot_domain_and_action_balance": True,
        },
        "schema_hashes": {
            "scenario_schema_sha256": _hash_file(schema_path),
            "trace_schema_sha256": _hash_file(trace_schema_path),
        },
        "source_hashes": source_hashes,
        "package_hashes": package_hashes,
    }


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2, sort_keys=True))
