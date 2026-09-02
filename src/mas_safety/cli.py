from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import sys
from pathlib import Path

from .analysis import analyze_and_write
from .runner import ExperimentRunner, pilot_specs, write_traces
from .scenarios import load_scenarios
from .shadow import write_shadow_replay
from .stage2_cli import Stage2CLIError, configure_stage2_parser
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
    configure_stage2_parser(subparsers)
    stage4_parser = subparsers.add_parser(
        "run-stage4-confirmatory",
        help="Preflight or explicitly execute the frozen Stage 4 batch.",
    )
    stage4_mode = stage4_parser.add_mutually_exclusive_group(required=True)
    stage4_mode.add_argument("--preflight-only", action="store_true")
    stage4_mode.add_argument("--execute", action="store_true")
    stage4_parser.set_defaults(stage4_executor=_execute_stage4_lazy)
    return parser


def _execute_stage4_lazy(args: argparse.Namespace) -> dict[str, object]:
    """Load Stage 4 only after its explicit subcommand has been selected."""

    from .stage4_runtime import execute_stage4_command

    return execute_stage4_command(args)


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
        # Keep provider/OpenAI modules outside the import graph for every
        # deterministic command, especially the offline Stage 2 replay.
        from .live import run_live_development

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
    if args.command == "run-stage2-replay":
        try:
            report = args.stage2_executor(args)
        except Stage2CLIError as exc:
            # Stage2CLIError codes are deliberately redaction-safe. Never emit
            # exception messages, causes, paths, key material, or subprocess text.
            print(
                json.dumps(
                    {
                        "error": exc.code,
                        "schema_version": "stage2-cli-error-v1",
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 2
        except Exception:  # noqa: BLE001 - redact the private replay boundary
            # The production boundary must not turn an unexpected replay bug
            # into a disclosure of private archive values through a traceback.
            print(
                json.dumps(
                    {
                        "error": "stage2_unexpected_failure",
                        "schema_version": "stage2-cli-error-v1",
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 2
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    if args.command == "run-stage4-confirmatory":
        try:
            report = args.stage4_executor(args)
        except Exception as exc:  # noqa: BLE001 - redact execution boundary
            error_code = getattr(exc, "code", None)
            if not isinstance(error_code, str):
                error_code = "stage4_unexpected_preflight_failure"
            print(
                json.dumps(
                    {
                        "error": error_code,
                        "schema_version": "stage4-confirmatory-preflight-error-v1",
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 2
        destination = sys.stdout if report.get("pass") is True else sys.stderr
        print(json.dumps(report, indent=2, sort_keys=True), file=destination)
        return 0 if report.get("pass") is True else 2
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
