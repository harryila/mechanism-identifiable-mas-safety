from __future__ import annotations

import json
from dataclasses import dataclass
from typing import ClassVar, Protocol

from .models import ActionSpec, Artifact, RunTrace, StageContext


@dataclass(frozen=True)
class Proposal:
    action: ActionSpec
    raw_output: str
    input_tokens: int
    output_tokens: int
    latency_ms: float
    refusal: bool = False
    capability_failure: bool = False


class AgentBackend(Protocol):
    """Boundary for scripted or live action generation.

    Backends propose actions only. Executable policies and the terminal-state
    evaluator remain outside the model boundary.
    """

    name: str
    model_id: str
    configuration: dict[str, object]

    def propose(
        self,
        *,
        context: StageContext,
        declared_action: ActionSpec,
        artifact: Artifact | None,
        seed: int,
    ) -> Proposal: ...


class ScriptedBackend:
    """Deterministic executable-specification oracle.

    This backend is intentionally not a behavioral model. It always proposes the
    declared stage action so the experiment plumbing can be tested exactly.
    """

    name = "scripted"
    model_id = "scripted-oracle-v1"
    configuration: ClassVar[dict[str, object]] = {"mode": "deterministic_oracle"}

    def propose(
        self,
        *,
        context: StageContext,
        declared_action: ActionSpec,
        artifact: Artifact | None,
        seed: int,
    ) -> Proposal:
        del context, artifact, seed
        action = ActionSpec(
            role=declared_action.role,
            name=declared_action.name,
            terminal=declared_action.terminal,
            parameters=dict(declared_action.parameters),
        )
        return Proposal(
            action=action,
            raw_output=json.dumps(
                {"action": action.name, "parameters": action.parameters},
                sort_keys=True,
            ),
            input_tokens=0,
            output_tokens=0,
            latency_ms=0.0,
        )


class FrozenTraceBackend:
    """Replay the exact typed proposals recorded in one source trace."""

    name = "frozen_replay"
    configuration: ClassVar[dict[str, object]] = {"mode": "frozen_proposal_replay"}

    def __init__(self, source_trace: RunTrace):
        self.source_trace = source_trace
        self.model_id = f"{source_trace.model_id}:frozen-replay"
        self._steps = {step.role: step for step in source_trace.steps}

    def propose(
        self,
        *,
        context: StageContext,
        declared_action: ActionSpec,
        artifact: Artifact | None,
        seed: int,
    ) -> Proposal:
        del declared_action, artifact, seed
        step = self._steps[context.role]
        action_data = step.proposed_action
        action = ActionSpec(
            role=context.role,
            name=str(action_data["name"]),
            terminal=bool(action_data["terminal"]),
            parameters=dict(action_data["parameters"]),
        )
        return Proposal(
            action=action,
            raw_output=step.raw_model_output or "",
            input_tokens=0,
            output_tokens=0,
            latency_ms=0.0,
            refusal=step.refusal,
            capability_failure=step.capability_failure,
        )
