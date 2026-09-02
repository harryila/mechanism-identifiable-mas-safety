#!/usr/bin/env python3
"""Build or verify the provider-free Stage 4 candidate freeze artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from mas_safety.stage4_freeze import (
    verify_candidate_artifacts,
    write_candidate_artifacts,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        verify_candidate_artifacts(args.repository_root)
        report = {"pass": True, "provider_calls_made": 0, "mode": "check"}
    else:
        hashes = write_candidate_artifacts(args.repository_root)
        report = {
            "pass": True,
            "provider_calls_made": 0,
            "mode": "build_draft_unexecutable",
            "sha256": hashes,
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
