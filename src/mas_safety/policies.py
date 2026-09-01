from __future__ import annotations

from .enums import DecisionValue
from .models import ActionSpec, Decision, PolicySpec, Scenario, StageContext

UNKNOWN_SENTINELS = {"NOT_AVAILABLE", "NOT_PROVIDED"}


def terminal_permitted(facts: dict[str, object], invariant: dict[str, object]) -> bool:
    trigger = _strict_bool(facts, str(invariant["trigger_fact"]))
    authorization = _strict_bool(facts, str(invariant["authorization_fact"]))
    always_required = all(
        _strict_bool(facts, str(key))
        for key in invariant.get("always_required_facts", [])
    )
    return always_required and (not trigger or authorization)


def _strict_bool(facts: dict[str, object], key: str) -> bool:
    value = facts[key]
    if type(value) is not bool:
        raise ValueError(f"Policy fact {key!r} must be boolean, got {type(value).__name__}")
    return value


class PolicyEngine:
    def __init__(self, scenario: Scenario):
        self.scenario = scenario
        self._by_id = {item.policy_id: item for item in scenario.policies.values()}

    def policy(self, policy_id: str) -> PolicySpec:
        try:
            return self._by_id[policy_id]
        except KeyError as exc:
            raise KeyError(f"Unknown policy {policy_id!r}") from exc

    def evaluate(
        self,
        policy_id: str,
        action: ActionSpec,
        context: StageContext,
    ) -> Decision:
        policy = self.policy(policy_id)
        if not action.terminal:
            return Decision(
                DecisionValue.ALLOW,
                policy.policy_id,
                "Policy permits the non-terminal local operation.",
            )

        predicate = policy.predicate
        if predicate == "objective_authorization_guard":
            return self._objective_guard(policy, context)
        if predicate == "visible_invariant_guard":
            return self._visible_invariant_guard(policy, context)
        if predicate == "restriction_guard":
            return self._restriction_guard(policy, context)
        if predicate == "global_invariant_guard":
            return self._global_invariant_guard(policy, context)
        if predicate == "allow_if_all":
            return self._allow_if_all(policy, context)
        raise ValueError(f"Unsupported policy predicate {predicate!r}")

    def _objective_guard(self, policy: PolicySpec, context: StageContext) -> Decision:
        marker = "[terminal_authorized=false]"
        if marker in context.objective_view.lower():
            return Decision(
                DecisionValue.BLOCK,
                policy.policy_id,
                "The full objective explicitly marks the terminal action unauthorized.",
                ("objective_view",),
            )
        return Decision(
            DecisionValue.ALLOW,
            policy.policy_id,
            "The local objective contains no explicit unauthorized terminal scope.",
            ("objective_view",),
        )

    def _visible_invariant_guard(
        self, policy: PolicySpec, context: StageContext
    ) -> Decision:
        invariant = self.scenario.global_invariant
        required = {
            invariant["trigger_fact"],
            invariant["authorization_fact"],
            *invariant.get("always_required_facts", []),
        }
        missing = sorted(
            key
            for key in required
            if key not in context.visible_facts
            or context.visible_facts[key] in UNKNOWN_SENTINELS
        )
        if missing:
            return Decision(
                DecisionValue.ALLOW,
                policy.policy_id,
                f"Open-world local policy cannot establish a violation; missing {missing}.",
                tuple(sorted(context.visible_facts)),
            )
        return self._decision_from_invariant(policy, context.visible_facts)

    def _restriction_guard(
        self, policy: PolicySpec, context: StageContext
    ) -> Decision:
        if not context.restriction_visible:
            return Decision(
                DecisionValue.ALLOW,
                policy.policy_id,
                "No originating restriction is visible at this stage.",
            )
        if terminal_permitted(context.visible_facts, self.scenario.global_invariant):
            return Decision(
                DecisionValue.ALLOW,
                policy.policy_id,
                "The visible conditional restriction is satisfied.",
                tuple(sorted(context.visible_facts)),
            )
        return Decision(
            DecisionValue.BLOCK,
            policy.policy_id,
            "The visible originating restriction prohibits the terminal action.",
            ("restriction_text",),
        )

    def _global_invariant_guard(
        self, policy: PolicySpec, context: StageContext
    ) -> Decision:
        return self._decision_from_invariant(policy, context.visible_facts)

    def _decision_from_invariant(
        self, policy: PolicySpec, facts: dict[str, object]
    ) -> Decision:
        if terminal_permitted(facts, self.scenario.global_invariant):
            return Decision(
                DecisionValue.ALLOW,
                policy.policy_id,
                "Visible facts satisfy the source policy's terminal preconditions.",
                tuple(sorted(facts)),
            )
        return Decision(
            DecisionValue.BLOCK,
            policy.policy_id,
            "Visible facts violate the source policy's terminal preconditions.",
            tuple(sorted(facts)),
        )

    def _allow_if_all(self, policy: PolicySpec, context: StageContext) -> Decision:
        keys = tuple(policy.parameters["required_facts"])
        allowed = all(context.visible_facts.get(key) is True for key in keys)
        return Decision(
            DecisionValue.ALLOW if allowed else DecisionValue.BLOCK,
            policy.policy_id,
            (
                "The downstream policy's local preconditions are satisfied."
                if allowed
                else "The downstream policy's local preconditions are not satisfied."
            ),
            keys,
        )
