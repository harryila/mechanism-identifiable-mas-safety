from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analysis import analyze_and_write
from .runner import ExperimentRunner, pilot_specs, write_traces
from .scenarios import load_scenarios
from .shadow import write_shadow_replay
from .validation import validate_output_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mas-safety",
        description="Run mechanism-identifiable compositional-safety experiments.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser(
        "run-pilot", help="Run the deterministic paired two-workflow pilot."
    )
    run_parser.add_argument("--output", type=Path, default=Path("outputs/pilot"))
    run_parser.add_argument("--scenario-dir", type=Path)
    run_parser.add_argument("--bootstrap-reps", type=int, default=2000)

    validate_parser = subparsers.add_parser(
        "validate", help="Independently validate a generated pilot directory."
    )
    validate_parser.add_argument("--input", type=Path, default=Path("outputs/pilot"))

    list_parser = subparsers.add_parser(
        "list-scenarios", help="List validated scenario identifiers."
    )
    list_parser.add_argument("--scenario-dir", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "run-pilot":
        scenarios = load_scenarios(args.scenario_dir)
        runner = ExperimentRunner(scenarios)
        traces = runner.run_many(pilot_specs(scenarios))
        write_traces(args.output / "traces.jsonl", traces)
        shadow_summary = write_shadow_replay(scenarios, traces, args.output)
        summary = analyze_and_write(
            traces,
            args.output,
            bootstrap_reps=args.bootstrap_reps,
            shadow_summary=shadow_summary,
        )
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    if args.command == "validate":
        report = validate_output_dir(args.input)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if not report["blocking_issue_count"] else 1
    if args.command == "list-scenarios":
        for scenario in load_scenarios(args.scenario_dir):
            print(f"{scenario.scenario_id}\t{scenario.title}")
        return 0
    raise AssertionError(f"Unhandled command {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
