from __future__ import annotations

import json
from typing import ClassVar, Protocol

from .enums import AgentDecisionKind, DecisionMode, Role
from .models import ActionSpec, AgentDecision, Artifact, RunTrace, StageContext


class AgentBackend(Protocol):
    """Boundary for scripted or live execution decisions.

    A backend receives only its defensive local context, the candidate operation,
    and the finite set of actions that the trusted runtime is willing to execute.
    Returning ``EXECUTE`` is a request, not authority: the runner checks exact
    offered-set membership before any simulated side effect.
    """

    name: str
    model_id: str
    configuration: dict[str, object]

    def decide(
        self,
        *,
        context: StageContext,
        decision_mode: DecisionMode,
        candidate_action: ActionSpec,
        offered_actions: tuple[ActionSpec, ...],
        artifact: Artifact | None,
        seed: int,
    ) -> AgentDecision: ...


class ScriptedBackend:
    """Deterministic v0.2 executable-specification oracle.

    The oracle preserves the v0.1 pilot's behavior by choosing the declared
    candidate at every stage. Unlike v0.1, the runtime executes that action only
    after validating this typed decision against the offered-action set.
    """

    name = "scripted"
    # Retain the v0.1 oracle identifier so historical scripted analyses remain
    # directly comparable; the configuration records the upgraded interface.
    model_id = "scripted-oracle-v1"
    configuration: ClassVar[dict[str, object]] = {"mode": "deterministic_oracle"}

    def decide(
        self,
        *,
        context: StageContext,
        decision_mode: DecisionMode,
        candidate_action: ActionSpec,
        offered_actions: tuple[ActionSpec, ...],
        artifact: Artifact | None,
        seed: int,
    ) -> AgentDecision:
        del context, artifact
        action = _copy_action(candidate_action)
        return AgentDecision.execute(
            action,
            raw_output=json.dumps(
                {
                    "decision": AgentDecisionKind.EXECUTE.value,
                    "action": _action_dict(action),
                },
                sort_keys=True,
            ),
            provider_metadata={
                "resolved_response_model": self.model_id,
                "status": "completed",
                "seed": seed,
                "decision_mode": decision_mode.value,
                "offered_action_count": len(offered_actions),
            },
        )


class FrozenTraceBackend:
    """Replay the exact typed decisions recorded in one source trace."""

    name = "frozen_replay"
    configuration: ClassVar[dict[str, object]] = {"mode": "frozen_decision_replay"}

    def __init__(self, source_trace: RunTrace):
        self.source_trace = source_trace
        self.model_id = f"{source_trace.model_id}:frozen-replay"
        self._steps = {step.role: step for step in source_trace.steps}

    def decide(
        self,
        *,
        context: StageContext,
        decision_mode: DecisionMode,
        candidate_action: ActionSpec,
        offered_actions: tuple[ActionSpec, ...],
        artifact: Artifact | None,
        seed: int,
    ) -> AgentDecision:
        del decision_mode, candidate_action, offered_actions, artifact, seed
        step = self._steps[context.role]
        decision_data = getattr(step, "agent_decision", {})
        kind_value = decision_data.get("kind") if isinstance(decision_data, dict) else None
        raw_output = step.raw_model_output or ""
        metadata = dict(getattr(step, "provider_metadata", {}))
        metadata["source_run_id"] = self.source_trace.run_id

        if kind_value == AgentDecisionKind.REFUSE.value or step.refusal:
            reason = decision_data.get("reason") if isinstance(decision_data, dict) else None
            return AgentDecision.refuse(
                str(reason or "Replayed model refusal."),
                raw_output=raw_output,
                provider_metadata=metadata,
            )
        if kind_value == AgentDecisionKind.ESCALATE.value or getattr(
            step, "escalation", False
        ):
            missing = (
                decision_data.get("missing_information", ())
                if isinstance(decision_data, dict)
                else ()
            )
            if not isinstance(missing, (list, tuple)) or not missing:
                missing = ("replayed_missing_information",)
            return AgentDecision.escalate(
                tuple(str(item) for item in missing),
                raw_output=raw_output,
                provider_metadata=metadata,
            )

        action_data = getattr(step, "selected_action", None) or getattr(
            step, "proposed_action", None
        )
        if not isinstance(action_data, dict):
            # Deliberately malformed: the runner records this as a capability
            # failure rather than inventing an executable action.
            return AgentDecision(  # type: ignore[arg-type]
                kind=AgentDecisionKind.EXECUTE,
                action=action_data,
                raw_output=raw_output,
                provider_metadata=metadata,
            )
        action = ActionSpec(
            role=Role(action_data["role"]),
            name=str(action_data["name"]),
            terminal=action_data["terminal"],
            parameters=dict(action_data["parameters"]),
        )
        return AgentDecision.execute(
            action,
            raw_output=raw_output,
            provider_metadata=metadata,
        )


def _copy_action(action: ActionSpec) -> ActionSpec:
    return ActionSpec(
        role=action.role,
        name=action.name,
        terminal=action.terminal,
        parameters=dict(action.parameters),
    )


def _action_dict(action: ActionSpec) -> dict[str, object]:
    return {
        "role": action.role.value,
        "name": action.name,
        "terminal": action.terminal,
        "parameters": dict(action.parameters),
    }
