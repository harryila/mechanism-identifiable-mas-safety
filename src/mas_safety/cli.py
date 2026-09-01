from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path

from .analysis import analyze_and_write
from .live import run_live_development
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

    live_parser = subparsers.add_parser(
        "run-live-development",
        help=(
            "Run the automatic two-call smoke and frozen 192-run, local-only "
            "v0.2.1 live micro-pilot under the shared USD 20 ceiling."
        ),
    )
    live_parser.add_argument(
        "--model",
        action="append",
        required=True,
        help="Explicit provider model/snapshot ID; pass exactly twice.",
    )
    live_parser.add_argument(
        "--output",
        type=Path,
        default=Path("outputs/private/live-development"),
        help="Private output directory for raw prompts, responses, traces, and report.",
    )
    live_parser.add_argument(
        "--provenance-key-id",
        help=(
            "Non-secret provenance key label. Defaults to "
            "MAS_SAFETY_PROVENANCE_KEY_ID or a one-way key fingerprint."
        ),
    )

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
    if args.command == "run-live-development":
        if len(args.model) != 2 or len(set(args.model)) != 2:
            raise SystemExit(
                "run-live-development requires exactly two distinct --model values"
            )
        if not os.environ.get("OPENAI_API_KEY"):
            raise SystemExit(
                "OPENAI_API_KEY is required in the process environment; never pass "
                "credentials as command-line arguments or commit them to the repository"
            )
        signing_key = _live_provenance_key()
        key_id = (
            args.provenance_key_id
            or os.environ.get("MAS_SAFETY_PROVENANCE_KEY_ID")
            or f"live-hmac-{hashlib.sha256(signing_key).hexdigest()[:12]}"
        )
        report = run_live_development(
            scenarios=load_scenarios(),
            model_ids=args.model,
            output_dir=args.output,
            provenance_signing_key=signing_key,
            provenance_key_id=key_id,
        )
        print(json.dumps(report, indent=2, sort_keys=True))
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


def _live_provenance_key() -> bytes:
    encoded = os.environ.get("MAS_SAFETY_PROVENANCE_KEY_B64")
    if not encoded:
        raise SystemExit(
            "MAS_SAFETY_PROVENANCE_KEY_B64 is required; set it to a private, random "
            "base64-encoded value of at least 32 bytes"
        )
    try:
        key = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SystemExit(
            "MAS_SAFETY_PROVENANCE_KEY_B64 is not valid base64"
        ) from exc
    if len(key) < 32:
        raise SystemExit(
            "MAS_SAFETY_PROVENANCE_KEY_B64 must decode to at least 32 bytes"
        )
    return key


if __name__ == "__main__":
    raise SystemExit(main())
