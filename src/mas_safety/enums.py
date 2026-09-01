from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    """Python 3.10-compatible string enum."""

    def __str__(self) -> str:
        return self.value


class Role(StrEnum):
    PLANNER = "planner"
    RETRIEVER = "retriever"
    TRANSFORMER = "transformer"
    ACTUATOR = "actuator"


PIPELINE_ROLES: tuple[Role, ...] = (
    Role.PLANNER,
    Role.RETRIEVER,
    Role.TRANSFORMER,
    Role.ACTUATOR,
)


class Mechanism(StrEnum):
    INTENT_DECOMPOSITION = "intent_decomposition"
    CONTEXT_FRAGMENTATION = "context_fragmentation"
    AUTHORIZATION_DRIFT = "authorization_drift"
    POLICY_HETEROGENEITY = "policy_heterogeneity"


class Defense(StrEnum):
    LOCAL_ONLY = "local_only"
    HISTORY_MONITOR = "history_monitor"
    SOURCE_ANCHORING = "source_anchoring"
    PROVENANCE_CARRYING = "provenance_carrying"
    POLICY_INTERSECTION = "policy_intersection"
    OMNISCIENT_REFERENCE = "omniscient_reference"


PRIMARY_DEFENSES: tuple[Defense, ...] = (
    Defense.LOCAL_ONLY,
    Defense.HISTORY_MONITOR,
    Defense.SOURCE_ANCHORING,
    Defense.PROVENANCE_CARRYING,
    Defense.POLICY_INTERSECTION,
)


class SafetyVariant(StrEnum):
    UNSAFE = "unsafe"
    SAFE = "safe"


class Architecture(StrEnum):
    MULTI_AGENT = "multi_agent"
    SINGLE_AGENT_FULL_CONTEXT = "single_agent_full_context"


class DecisionMode(StrEnum):
    """The action-choice interface presented to an agent."""

    EXECUTION_DECISION = "execution_decision"
    FINITE_ACTION_SELECTION = "finite_action_selection"


class AgentDecisionKind(StrEnum):
    """Typed outcomes accepted from an agent backend."""

    EXECUTE = "execute"
    REFUSE = "refuse"
    ESCALATE = "escalate"


class DecisionValue(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"


class RunStatus(StrEnum):
    COMPLETED = "completed"
    MODEL_REFUSAL = "model_refusal"
    MODEL_ESCALATION = "model_escalation"
    ALTERNATIVE_ACTION = "alternative_action"
    LOCAL_BLOCK = "local_block"
    DEFENSE_BLOCK = "defense_block"
    CAPABILITY_FAILURE = "capability_failure"
