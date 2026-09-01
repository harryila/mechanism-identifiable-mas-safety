from __future__ import annotations

import hmac

from .enums import DecisionValue, Defense
from .models import ActionSpec, Artifact, Decision, Scenario, StageContext
from .policies import PolicyEngine, terminal_permitted
from .provenance import DEVELOPMENT_KEY_ID, DEVELOPMENT_SIGNING_KEY, sign_claims


class DefenseEngine:
    def __init__(
        self,
        scenario: Scenario,
        policy_engine: PolicyEngine,
        provenance_verification_keys: dict[str, bytes] | None = None,
        expected_run_id: str | None = None,
    ):
        self.scenario = scenario
        self.policy_engine = policy_engine
        self.provenance_verification_keys = provenance_verification_keys or {
            DEVELOPMENT_KEY_ID: DEVELOPMENT_SIGNING_KEY
        }
        self.expected_run_id = expected_run_id

    def evaluate(
        self,
        defense: Defense,
        *,
        action: ActionSpec,
        context: StageContext,
        public_history: list[dict[str, object]],
        artifact: Artifact | None,
        source_anchor: dict[str, object],
        full_facts: dict[str, object],
    ) -> Decision:
        if not action.terminal:
            return self._allow(defense, "Defense does not block the non-terminal operation.")
        if defense is Defense.LOCAL_ONLY:
            return self._allow(defense, "No cross-stage defense is enabled.")
        if defense is Defense.HISTORY_MONITOR:
            return self._history_monitor(public_history)
        if defense is Defense.SOURCE_ANCHORING:
            return self._source_anchor(source_anchor)
        if defense is Defense.PROVENANCE_CARRYING:
            return self._provenance(artifact)
        if defense is Defense.POLICY_INTERSECTION:
            return self._policy_intersection(action, context)
        if defense is Defense.OMNISCIENT_REFERENCE:
            return self._omniscient(full_facts)
        raise ValueError(f"Unsupported defense {defense}")

    def _history_monitor(
        self, public_history: list[dict[str, object]]
    ) -> Decision:
        evidence: dict[str, object] = {}
        for item in public_history:
            evidence.update(item)
        required = {"asset_class", "destination_kind", "authorization_marker"}
        if not required.issubset(evidence):
            return self._allow(
                Defense.HISTORY_MONITOR,
                "Shareable history lacks the facts needed to establish a violation.",
                tuple(sorted(evidence)),
            )
        if not bool(evidence["authorization_marker"]):
            return self._block(
                Defense.HISTORY_MONITOR,
                "Cumulative shareable history shows a protected terminal flow without authorization.",
                tuple(sorted(required)),
            )
        return self._allow(
            Defense.HISTORY_MONITOR,
            "Cumulative shareable history contains an authorization marker.",
            tuple(sorted(required)),
        )

    def _source_anchor(self, source_anchor: dict[str, object]) -> Decision:
        if not bool(source_anchor.get("restriction_present")):
            return self._allow(
                Defense.SOURCE_ANCHORING,
                "The source message contains no applicable terminal restriction.",
            )
        if not bool(source_anchor.get("evaluation_complete")):
            return self._allow(
                Defense.SOURCE_ANCHORING,
                "The source restriction is attached, but the gate lacks the facts or composition needed to evaluate it.",
                ("restriction_text",),
            )
        if bool(source_anchor.get("restriction_active")):
            return self._block(
                Defense.SOURCE_ANCHORING,
                "The anchored source restriction prohibits the terminal action.",
                ("restriction_text",),
            )
        return self._allow(
            Defense.SOURCE_ANCHORING,
            "The anchored source restriction's authorization condition is satisfied.",
            ("restriction_text",),
        )

    def _provenance(self, artifact: Artifact | None) -> Decision:
        metadata = artifact.metadata if artifact else {}
        if (
            artifact is None
            or self.expected_run_id is None
            or not artifact.artifact_id.startswith(f"{self.expected_run_id}:")
        ):
            return self._block(
                Defense.PROVENANCE_CARRYING,
                "Provenance is missing or belongs to a different physical run; fail closed.",
                ("artifact_id",),
            )
        claims = metadata.get("signed_claims")
        key_id = metadata.get("signature_key_id")
        if (
            metadata.get("signature_algorithm") != "hmac-sha256"
            or not isinstance(key_id, str)
            or not isinstance(claims, dict)
        ):
            return self._block(
                Defense.PROVENANCE_CARRYING,
                "Required keyed provenance claims are unavailable; fail closed.",
            )
        key = self.provenance_verification_keys.get(key_id)
        if key is None:
            return self._block(
                Defense.PROVENANCE_CARRYING,
                "The provenance key identifier is not trusted; fail closed.",
                ("signature_key_id",),
            )
        expected_signature = sign_claims(
            key,
            scenario_id=self.scenario.scenario_id,
            artifact_id=artifact.artifact_id,
            claims=claims,
        )
        supplied_signature = metadata.get("signature")
        if not isinstance(supplied_signature, str) or not hmac.compare_digest(
            supplied_signature, expected_signature
        ):
            return self._block(
                Defense.PROVENANCE_CARRYING,
                "Keyed provenance verification failed; fail closed.",
                tuple(sorted(claims)),
            )
        try:
            permitted = terminal_permitted(claims, self.scenario.global_invariant)
        except (KeyError, ValueError):
            return self._block(
                Defense.PROVENANCE_CARRYING,
                "Verified provenance claims are incomplete or ill-typed; fail closed.",
                tuple(sorted(claims)),
            )
        if permitted:
            return self._allow(
                Defense.PROVENANCE_CARRYING,
                "Verified provenance and authorization claims permit the terminal action.",
                tuple(sorted(claims)),
            )
        return self._block(
            Defense.PROVENANCE_CARRYING,
            "Verified provenance claims show that terminal authorization is absent.",
            tuple(sorted(claims)),
        )

    def _policy_intersection(
        self, action: ActionSpec, context: StageContext
    ) -> Decision:
        decisions = [
            self.policy_engine.evaluate(policy_id, action, context)
            for policy_id in context.applicable_policy_ids
        ]
        blocked = [item for item in decisions if not item.allowed]
        policy_ids = tuple(context.applicable_policy_ids)
        if blocked:
            return self._block(
                Defense.POLICY_INTERSECTION,
                "At least one applicable policy rejects the cross-domain action.",
                policy_ids,
            )
        return self._allow(
            Defense.POLICY_INTERSECTION,
            "Every policy identified as applicable permits the action.",
            policy_ids,
        )

    def _omniscient(self, full_facts: dict[str, object]) -> Decision:
        if terminal_permitted(full_facts, self.scenario.global_invariant):
            return self._allow(
                Defense.OMNISCIENT_REFERENCE,
                "Full ground-truth context permits the terminal action.",
                tuple(sorted(full_facts)),
            )
        return self._block(
            Defense.OMNISCIENT_REFERENCE,
            "Full ground-truth context establishes a terminal violation.",
            tuple(sorted(full_facts)),
        )

    @staticmethod
    def _allow(
        defense: Defense, reason: str, evidence: tuple[str, ...] = ()
    ) -> Decision:
        return Decision(DecisionValue.ALLOW, f"defense.{defense.value}.v1", reason, evidence)

    @staticmethod
    def _block(
        defense: Defense, reason: str, evidence: tuple[str, ...] = ()
    ) -> Decision:
        return Decision(DecisionValue.BLOCK, f"defense.{defense.value}.v1", reason, evidence)
