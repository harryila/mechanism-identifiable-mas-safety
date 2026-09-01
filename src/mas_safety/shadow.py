from __future__ import annotations

import csv
import json
from collections import Counter
from collections.abc import Iterable, Sequence
from pathlib import Path

from .backends import FrozenTraceBackend
from .enums import PRIMARY_DEFENSES, Defense, RunStatus
from .models import RunTrace, Scenario
from .runner import ExperimentRunner, RunSpec


def write_shadow_replay(
    scenarios: Iterable[Scenario],
    traces: Sequence[RunTrace],
    output_dir: str | Path,
) -> dict[str, object]:
    """Evaluate every defense on frozen local-only proposals.

    Replay is an observability/coverage audit. It does not estimate closed-loop
    adaptation because defense decisions cannot change the frozen source trace.
    """

    scenario_items = list(scenarios)
    baselines = [
        trace
        for trace in traces
        if trace.cohort == "mechanism_on"
        and trace.defense is Defense.LOCAL_ONLY
        and all(step.proposal_status == "valid_proposal" for step in trace.steps)
    ]
    rows: list[dict[str, object]] = []
    for source in baselines:
        for defense in PRIMARY_DEFENSES:
            replay_runner = ExperimentRunner(
                scenario_items, backend=FrozenTraceBackend(source)
            )
            replay = replay_runner.run(
                RunSpec(
                    scenario_id=source.scenario_id,
                    mechanism=source.mechanism,
                    defense=defense,
                    safety_variant=source.safety_variant,
                    architecture=source.architecture,
                    mechanism_active=source.mechanism_active,
                    cohort="mechanism_on",
                    seed=source.seed,
                    invocation_id=source.invocation_id,
                )
            )
            blocked_steps = [
                step for step in replay.steps if not step.defense_decision.allowed
            ]
            rows.append(
                {
                    "source_run_id": source.run_id,
                    "condition_id": source.condition_id,
                    "model_id": source.model_id,
                    "invocation_id": source.invocation_id,
                    "seed": source.seed,
                    "scenario_id": source.scenario_id,
                    "mechanism": source.mechanism.value,
                    "safety_variant": source.safety_variant.value,
                    "defense": defense.value,
                    "source_terminal_status": source.terminal_status,
                    "source_global_violation": source.global_violation,
                    "defense_would_block": replay.status is RunStatus.DEFENSE_BLOCK,
                    "first_block_step": (
                        blocked_steps[0].step_index if blocked_steps else ""
                    ),
                    "first_block_reason": (
                        blocked_steps[0].defense_decision.reason if blocked_steps else ""
                    ),
                    "proposal_count": len(source.steps),
                }
            )
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "shadow_replay.csv"
    if rows:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    counts = Counter(
        (str(row["mechanism"]), str(row["defense"]))
        for row in rows
        if bool(row["defense_would_block"])
        and row["safety_variant"] == "unsafe"
    )
    summary = {
        "source_trace_count": len(baselines),
        "replay_evaluation_count": len(rows),
        "mode": "frozen_local_only_proposals",
        "interpretation": (
            "Coverage/observability audit only; not a closed-loop adaptation estimate."
        ),
        "unsafe_block_counts": {
            f"{mechanism}:{defense}": count
            for (mechanism, defense), count in sorted(counts.items())
        },
    }
    (destination / "shadow_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary
