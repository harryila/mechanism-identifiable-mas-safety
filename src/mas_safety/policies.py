from __future__ import annotations

from copy import deepcopy

from .enums import DecisionValue
from .models import ActionSpec, Decision, PolicySpec, Scenario, StageContext

UNKNOWN_SENTINELS = {"NOT_AVAILABLE", "NOT_PROVIDED"}


def render_policy_contract(scenario: Scenario, policy: PolicySpec) -> str:
    """Render the model-facing contract for an executable ``PolicySpec``.

    The renderer and :class:`PolicyEngine` consume the same predicate and
    parameters.  Contracts therefore describe the trusted predicate without
    copying a second, independently maintained policy into prompts.
    """

    non_terminal = "Non-terminal local operations are permitted."
    predicate = policy.predicate
    if predicate == "objective_authorization_guard":
        terminal = (
            "For the terminal action, block when the objective explicitly marks "
            "terminal_authorized=false; otherwise permit under this objective-scope "
            "rule."
        )
    elif predicate == "visible_invariant_guard":
        terminal = (
            f"For the terminal action, {_invariant_contract(scenario)} If any fact "
            "named by this rule is NOT_AVAILABLE or NOT_PROVIDED, permit under the "
            "local open-world rule rather than inferring a violation."
        )
    elif predicate == "restriction_guard":
        terminal = (
            "For the terminal action, apply an originating restriction only when it "
            f"is provided in this stage context; then {_invariant_contract(scenario)} "
            "If no originating restriction is provided, permit under this local "
            "delegation rule."
        )
    elif predicate == "global_invariant_guard":
        terminal = f"For the terminal action, {_invariant_contract(scenario)}"
    elif predicate == "allow_if_all":
        keys = tuple(str(key) for key in policy.parameters["required_facts"])
        terminal = (
            f"For the terminal action, permit only when {_fact_list(keys)} "
            "are all true."
        )
    else:
        raise ValueError(f"Unsupported policy predicate {predicate!r}")
    return f"{non_terminal} {terminal}"


def inspect_policy_contracts(scenario: Scenario) -> dict[str, dict[str, object]]:
    """Return an auditable executable-to-natural-language policy mapping."""

    return {
        policy.policy_id: {
            "predicate": policy.predicate,
            "parameters": deepcopy(policy.parameters),
            "natural_language_contract": render_policy_contract(scenario, policy),
        }
        for policy in scenario.policies.values()
    }


def _invariant_contract(scenario: Scenario) -> str:
    invariant = scenario.global_invariant
    trigger = str(invariant["trigger_fact"])
    authorization = str(invariant["authorization_fact"])
    required = tuple(str(key) for key in invariant.get("always_required_facts", []))
    required_clause = (
        f"require {_fact_list(required)} to be true and " if required else ""
    )
    return (
        f"permit {invariant['terminal_action']} only when {required_clause}either "
        f"{trigger} is false or {authorization} is true."
    )


def _fact_list(keys: tuple[str, ...]) -> str:
    quoted = [f"`{key}`" for key in keys]
    if not quoted:
        return "the empty fact set"
    if len(quoted) == 1:
        return quoted[0]
    if len(quoted) == 2:
        return f"{quoted[0]} and {quoted[1]}"
    return f"{', '.join(quoted[:-1])}, and {quoted[-1]}"


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
        raise ValueError(
            f"Policy fact {key!r} must be boolean, got {type(value).__name__}"
        )
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

    def contract(self, policy_id: str) -> str:
        """Return the model-facing contract compiled from the trusted spec."""

        return render_policy_contract(self.scenario, self.policy(policy_id))

    def contract_map(self) -> dict[str, dict[str, object]]:
        return inspect_policy_contracts(self.scenario)

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

    def _restriction_guard(self, policy: PolicySpec, context: StageContext) -> Decision:
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
