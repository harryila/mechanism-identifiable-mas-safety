from __future__ import annotations

"""Pure Stage 4 defense-view projection with capability-minimal inputs.

This module does not evaluate a defense, policy, model response, or provider
result.  Each observation type contains only the fields declared for one frozen
defense view, so the projector has no reference through which it could inspect a
role task, objective, restriction, artifact body, tool log, or other undeclared
runtime state.
"""

from dataclasses import dataclass
import math
from typing import TypeAlias

from .enums import Defense

JsonObject: TypeAlias = dict[str, object]


@dataclass(frozen=True, slots=True)
class LocalOnlyObservation:
    """No cross-stage observation is available."""


@dataclass(frozen=True, slots=True)
class HistoryMonitorObservation:
    """Accumulated shareable public-evidence dictionaries only."""

    shareable_history: tuple[JsonObject, ...]


@dataclass(frozen=True, slots=True)
class SourceAnchoringObservation:
    """The four trusted source-restriction fields declared by the contract."""

    restriction_present: bool
    evaluation_complete: bool
    restriction_active: bool
    restriction_text: str


@dataclass(frozen=True, slots=True)
class ProvenanceCarryingObservation:
    """Physical-run binding plus the hidden authenticated provenance sidecar."""

    artifact_id: str
    origin_scenario: str
    signed_claims: JsonObject
    signature: str
    signature_algorithm: str
    signature_key_id: str


@dataclass(frozen=True, slots=True)
class PolicyIntersectionObservation:
    """Runtime-selected policy identities and the current gate-visible facts."""

    applicable_policy_ids: tuple[str, ...]
    gate_visible_facts: JsonObject


@dataclass(frozen=True, slots=True)
class OmniscientReferenceObservation:
    """Complete authoritative facts for the excluded upper-bound reference."""

    ground_truth_facts: JsonObject


Stage4DefenseObservation: TypeAlias = (
    LocalOnlyObservation
    | HistoryMonitorObservation
    | SourceAnchoringObservation
    | ProvenanceCarryingObservation
    | PolicyIntersectionObservation
    | OmniscientReferenceObservation
)

_OBSERVATION_TYPE_BY_DEFENSE: dict[Defense, type[Stage4DefenseObservation]] = {
    Defense.LOCAL_ONLY: LocalOnlyObservation,
    Defense.HISTORY_MONITOR: HistoryMonitorObservation,
    Defense.SOURCE_ANCHORING: SourceAnchoringObservation,
    Defense.PROVENANCE_CARRYING: ProvenanceCarryingObservation,
    Defense.POLICY_INTERSECTION: PolicyIntersectionObservation,
    Defense.OMNISCIENT_REFERENCE: OmniscientReferenceObservation,
}

DECLARED_VIEW_KEYS: dict[Defense, frozenset[str]] = {
    Defense.LOCAL_ONLY: frozenset(),
    Defense.HISTORY_MONITOR: frozenset({"shareable_history"}),
    Defense.SOURCE_ANCHORING: frozenset({"source_anchor"}),
    Defense.PROVENANCE_CARRYING: frozenset({"artifact_metadata"}),
    Defense.POLICY_INTERSECTION: frozenset(
        {"applicable_policy_ids", "gate_visible_facts"}
    ),
    Defense.OMNISCIENT_REFERENCE: frozenset({"ground_truth_facts"}),
}


def project_stage4_defense_view(
    defense: Defense,
    observation: Stage4DefenseObservation,
) -> JsonObject:
    """Return exactly the declared view for ``defense``.

    Exact observation-type matching is intentional: a caller cannot pass a rich
    ``StageContext`` or a structurally similar object that carries additional
    attributes.  Returned containers are defensive copies.
    """

    if not isinstance(defense, Defense):
        raise TypeError("defense must be a Defense enum value")
    expected_type = _OBSERVATION_TYPE_BY_DEFENSE[defense]
    if type(observation) is not expected_type:
        raise TypeError(
            f"{defense.value} requires {expected_type.__name__}, "
            f"got {type(observation).__name__}"
        )

    if defense is Defense.LOCAL_ONLY:
        view: JsonObject = {}
    elif defense is Defense.HISTORY_MONITOR:
        assert isinstance(observation, HistoryMonitorObservation)
        if type(observation.shareable_history) is not tuple:
            raise TypeError("shareable_history must be an exact tuple")
        view = {
            "shareable_history": [
                _copy_json_object(item, "shareable_history item")
                for item in observation.shareable_history
            ]
        }
    elif defense is Defense.SOURCE_ANCHORING:
        assert isinstance(observation, SourceAnchoringObservation)
        _require_exact_bool(observation.restriction_present, "restriction_present")
        _require_exact_bool(observation.evaluation_complete, "evaluation_complete")
        _require_exact_bool(observation.restriction_active, "restriction_active")
        _require_nonempty_string(observation.restriction_text, "restriction_text")
        view = {
            "source_anchor": {
                "restriction_present": observation.restriction_present,
                "evaluation_complete": observation.evaluation_complete,
                "restriction_active": observation.restriction_active,
                "restriction_text": observation.restriction_text,
            }
        }
    elif defense is Defense.PROVENANCE_CARRYING:
        assert isinstance(observation, ProvenanceCarryingObservation)
        for field_name in (
            "artifact_id",
            "origin_scenario",
            "signature",
            "signature_algorithm",
            "signature_key_id",
        ):
            _require_nonempty_string(getattr(observation, field_name), field_name)
        view = {
            "artifact_metadata": {
                "artifact_id": observation.artifact_id,
                "origin_scenario": observation.origin_scenario,
                "signed_claims": _copy_json_object(
                    observation.signed_claims, "signed_claims"
                ),
                "signature": observation.signature,
                "signature_algorithm": observation.signature_algorithm,
                "signature_key_id": observation.signature_key_id,
            }
        }
    elif defense is Defense.POLICY_INTERSECTION:
        assert isinstance(observation, PolicyIntersectionObservation)
        if type(observation.applicable_policy_ids) is not tuple:
            raise TypeError("applicable_policy_ids must be an exact tuple")
        if not observation.applicable_policy_ids:
            raise ValueError("applicable_policy_ids must not be empty")
        if any(
            type(policy_id) is not str
            or not policy_id
            or policy_id != policy_id.strip()
            for policy_id in observation.applicable_policy_ids
        ):
            raise ValueError(
                "applicable_policy_ids must contain non-empty trimmed exact strings"
            )
        if len(set(observation.applicable_policy_ids)) != len(
            observation.applicable_policy_ids
        ):
            raise ValueError("applicable_policy_ids must be unique")
        view = {
            "applicable_policy_ids": list(observation.applicable_policy_ids),
            "gate_visible_facts": _copy_json_object(
                observation.gate_visible_facts, "gate_visible_facts"
            ),
        }
    elif defense is Defense.OMNISCIENT_REFERENCE:
        assert isinstance(observation, OmniscientReferenceObservation)
        view = {
            "ground_truth_facts": _copy_json_object(
                observation.ground_truth_facts, "ground_truth_facts"
            )
        }
    else:  # pragma: no cover - exhaustive over the frozen enum
        raise ValueError(f"Unsupported defense {defense}")

    if set(view) != DECLARED_VIEW_KEYS[defense]:
        raise AssertionError(f"Projection for {defense.value} violated its view contract")
    return view


def _require_exact_bool(value: object, field_name: str) -> None:
    if type(value) is not bool:
        raise TypeError(f"{field_name} must be a boolean")


def _require_nonempty_string(value: object, field_name: str) -> None:
    if type(value) is not str:
        raise TypeError(f"{field_name} must be an exact string")
    if not value or value != value.strip():
        raise ValueError(f"{field_name} must be a non-empty trimmed string")


def _copy_json_object(value: object, field_name: str) -> JsonObject:
    if type(value) is not dict:
        raise TypeError(f"{field_name} must be an exact plain dict")
    copied = _copy_json_value(value, field_name, set())
    assert isinstance(copied, dict)
    return copied


def _copy_json_value(
    value: object,
    path: str,
    active_container_ids: set[int],
) -> object:
    """Validate and copy an exact JSON value, rejecting cycles and subclasses."""

    if value is None or type(value) in {bool, int, str}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError(f"{path} contains a non-finite number")
        return value
    if type(value) is dict:
        identity = id(value)
        if identity in active_container_ids:
            raise ValueError(f"{path} contains a cycle")
        active_container_ids.add(identity)
        try:
            copied: JsonObject = {}
            for key, item in value.items():
                if type(key) is not str:
                    raise TypeError(f"{path} contains a non-string or subclass key")
                copied[key] = _copy_json_value(
                    item, f"{path}.{key}", active_container_ids
                )
            return copied
        finally:
            active_container_ids.remove(identity)
    if type(value) is list:
        identity = id(value)
        if identity in active_container_ids:
            raise ValueError(f"{path} contains a cycle")
        active_container_ids.add(identity)
        try:
            return [
                _copy_json_value(item, f"{path}[{index}]", active_container_ids)
                for index, item in enumerate(value)
            ]
        finally:
            active_container_ids.remove(identity)
    raise TypeError(
        f"{path} contains non-JSON or non-exact type {type(value).__name__}"
    )
