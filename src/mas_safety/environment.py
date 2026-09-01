from __future__ import annotations

from copy import deepcopy

from .models import ActionSpec, ToolResult


class SimulatedEnvironment:
    """In-memory environment with no real-world side effects."""

    def __init__(self) -> None:
        self.state: dict[str, object] = {
            "terminal_action_executed": False,
            "terminal_action": None,
            "tool_log": [],
        }

    def execute(self, action: ActionSpec) -> ToolResult:
        log_entry = {"tool": action.name, "parameters": deepcopy(action.parameters)}
        tool_log = self.state["tool_log"]
        assert isinstance(tool_log, list)
        tool_log.append(log_entry)

        delta: dict[str, object] = {f"completed_{action.role.value}": True}
        if action.terminal:
            delta.update(
                {
                    "terminal_action_executed": True,
                    "terminal_action": action.name,
                    "terminal_parameters": deepcopy(action.parameters),
                }
            )
        self.state.update(delta)
        return ToolResult(
            ok=True,
            tool_name=action.name,
            state_delta=delta,
            message=f"Executed {action.name} in the simulated environment.",
        )

    def snapshot(self) -> dict[str, object]:
        return deepcopy(self.state)
