#!/usr/bin/env python3
"""Verify the public Git binding for the sealed Stage 3 construction package."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BINDING = (
    ROOT / "verification" / "stage3-confirmatory" / "repository_binding.json"
)
HEX_40 = re.compile(r"[0-9a-f]{40}")
HEX_64 = re.compile(r"[0-9a-f]{64}")
TAG_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")

EXPECTED_BINDING_KEYS = {
    "binding_version",
    "bound_at",
    "sealed_commit_sha",
    "sealed_commit_committed_at",
    "annotated_tag",
    "annotated_tag_object_sha",
    "annotated_tag_created_at",
    "selection_seal_file_sha256",
    "selection_record_sha256",
    "construction_verifier_sha256",
    "stage4_observability_projector_sha256",
    "ordered_workflow_manifest_sha256",
    "sealed_entry_count",
    "post_seal_provenance_note",
    "post_seal_provenance_note_sha256",
    "statement",
}

EXPECTED_SEALED_PATHS = {
    "verification/stage3-confirmatory/selection_record.json",
    "verification/stage3-confirmatory/verify_construction.py",
    "src/mas_safety/stage4_observability.py",
    "scenarios/confirmatory/h1_research_data_export.json",
    "scenarios/confirmatory/h2_specialist_portal_access.json",
    "scenarios/confirmatory/e1_transcript_release.json",
    "scenarios/confirmatory/e2_grade_correction.json",
    "scenarios/confirmatory/p1_benefit_disbursement.json",
    "scenarios/confirmatory/p2_permit_access_grant.json",
    "scenarios/confirmatory/f1_claim_payment.json",
    "scenarios/confirmatory/f2_vendor_bank_update.json",
}

SLOT_BY_PATH = {
    "scenarios/confirmatory/h1_research_data_export.json": "H1",
    "scenarios/confirmatory/h2_specialist_portal_access.json": "H2",
    "scenarios/confirmatory/e1_transcript_release.json": "E1",
    "scenarios/confirmatory/e2_grade_correction.json": "E2",
    "scenarios/confirmatory/p1_benefit_disbursement.json": "P1",
    "scenarios/confirmatory/p2_permit_access_grant.json": "P2",
    "scenarios/confirmatory/f1_claim_payment.json": "F1",
    "scenarios/confirmatory/f2_vendor_bank_update.json": "F2",
}


class BindingVerificationError(RuntimeError):
    pass


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise BindingVerificationError("duplicate_json_key")
        value[key] = item
    return value


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate
        )
    except BindingVerificationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BindingVerificationError("binding_json_unreadable") from exc
    if type(value) is not dict:
        raise BindingVerificationError("binding_root_invalid")
    return value


def _git_text(*args: str) -> str:
    result = subprocess.run(
        ("git", *args),
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if result.returncode != 0:
        raise BindingVerificationError(f"git_command_failed:{args[0]}")
    return result.stdout.strip()


def _git_bytes(commit: str, path: str) -> bytes:
    result = subprocess.run(
        ("git", "show", f"{commit}:{path}"),
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise BindingVerificationError(f"sealed_entry_missing:{path}")
    return result.stdout


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise BindingVerificationError(code)


def _require_current_bytes(path: Path, expected: bytes, *, label: str) -> None:
    _require(path.is_file(), f"current_{label}_missing")
    _require(path.read_bytes() == expected, f"current_{label}_drift")


def _parse_seal(value: bytes) -> dict[str, str]:
    try:
        lines = value.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise BindingVerificationError("selection_seal_not_utf8") from exc
    entries: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_./-]+)", line)
        _require(match is not None, "selection_seal_line_invalid")
        assert match is not None
        digest, path = match.groups()
        _require(path not in entries, "selection_seal_duplicate_path")
        entries[path] = digest
    _require(set(entries) == EXPECTED_SEALED_PATHS, "selection_seal_paths_mismatch")
    return entries


def verify_repository_binding(path: Path = DEFAULT_BINDING) -> dict[str, Any]:
    binding = _read_json(path)
    _require(set(binding) == EXPECTED_BINDING_KEYS, "binding_schema_mismatch")
    _require(
        binding["binding_version"] == "stage3-confirmatory-repository-binding-v1",
        "binding_version_mismatch",
    )
    for key in (
        "sealed_commit_sha",
        "annotated_tag_object_sha",
    ):
        _require(
            type(binding[key]) is str and HEX_40.fullmatch(binding[key]) is not None,
            f"{key}_invalid",
        )
    for key in (
        "selection_seal_file_sha256",
        "selection_record_sha256",
        "construction_verifier_sha256",
        "stage4_observability_projector_sha256",
        "ordered_workflow_manifest_sha256",
        "post_seal_provenance_note_sha256",
    ):
        _require(
            type(binding[key]) is str and HEX_64.fullmatch(binding[key]) is not None,
            f"{key}_invalid",
        )
    tag = binding["annotated_tag"]
    _require(type(tag) is str and TAG_NAME.fullmatch(tag) is not None, "tag_invalid")
    _require(type(binding["sealed_entry_count"]) is int, "sealed_entry_count_invalid")
    _require(binding["sealed_entry_count"] == 11, "sealed_entry_count_mismatch")
    for key in (
        "bound_at",
        "sealed_commit_committed_at",
        "annotated_tag_created_at",
        "post_seal_provenance_note",
        "statement",
    ):
        _require(type(binding[key]) is str and bool(binding[key]), f"{key}_invalid")

    commit = binding["sealed_commit_sha"]
    _require(_git_text("cat-file", "-t", tag) == "tag", "tag_not_annotated")
    _require(_git_text("rev-parse", tag) == binding["annotated_tag_object_sha"], "tag_object_mismatch")
    _require(_git_text("rev-parse", f"{tag}^{{}}") == commit, "tag_target_mismatch")
    _require(_git_text("show", "-s", "--format=%cI", commit) == binding["sealed_commit_committed_at"], "commit_time_mismatch")
    tag_metadata = _git_text(
        "for-each-ref", "--format=%(taggerdate:iso-strict)", f"refs/tags/{tag}"
    )
    _require(tag_metadata == binding["annotated_tag_created_at"], "tag_time_mismatch")
    _require(binding["bound_at"] == tag_metadata, "binding_time_mismatch")
    tag_message = _git_text("tag", "-l", tag, "--format=%(contents)")
    _require(binding["selection_seal_file_sha256"] in tag_message, "tag_missing_seal_hash")
    _require(binding["ordered_workflow_manifest_sha256"] in tag_message, "tag_missing_workflow_hash")

    seal_path = "verification/stage3-confirmatory/selection_seal.sha256"
    seal_bytes = _git_bytes(commit, seal_path)
    _require(_sha256(seal_bytes) == binding["selection_seal_file_sha256"], "selection_seal_hash_mismatch")
    _require_current_bytes(
        ROOT / seal_path,
        seal_bytes,
        label="selection_seal",
    )
    entries = _parse_seal(seal_bytes)
    for sealed_path, expected_digest in entries.items():
        committed = _git_bytes(commit, sealed_path)
        _require(_sha256(committed) == expected_digest, f"sealed_entry_hash_mismatch:{sealed_path}")
        current = ROOT / sealed_path
        _require(current.is_file(), f"current_sealed_entry_missing:{sealed_path}")
        _require(current.read_bytes() == committed, f"current_sealed_entry_drift:{sealed_path}")

    _require(
        entries["verification/stage3-confirmatory/selection_record.json"]
        == binding["selection_record_sha256"],
        "selection_record_binding_mismatch",
    )
    _require(
        entries["verification/stage3-confirmatory/verify_construction.py"]
        == binding["construction_verifier_sha256"],
        "construction_verifier_binding_mismatch",
    )
    _require(
        entries["src/mas_safety/stage4_observability.py"]
        == binding["stage4_observability_projector_sha256"],
        "projector_binding_mismatch",
    )

    workflow_hashes = {
        SLOT_BY_PATH[sealed_path]: digest
        for sealed_path, digest in entries.items()
        if sealed_path in SLOT_BY_PATH
    }
    workflow_manifest = json.dumps(
        workflow_hashes, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    _require(
        _sha256(workflow_manifest) == binding["ordered_workflow_manifest_sha256"],
        "workflow_manifest_binding_mismatch",
    )

    record = json.loads(
        _git_bytes(
            commit, "verification/stage3-confirmatory/selection_record.json"
        )
    )
    _require(record["seal_scope"]["repository_commit"] is None, "selection_record_sha_was_invented")
    _require(record["seal_scope"]["planned_annotated_tag"] == tag, "selection_record_tag_mismatch")
    _require(
        record["seal_scope"]["ordered_file_hash_manifest_sha256"]
        == binding["ordered_workflow_manifest_sha256"],
        "selection_record_workflow_hash_mismatch",
    )

    _require(
        binding["post_seal_provenance_note"]
        == "verification/stage3-confirmatory/post_seal_provenance_note.md",
        "post_seal_provenance_note_path_mismatch",
    )
    provenance_note = ROOT / binding["post_seal_provenance_note"]
    _require(provenance_note.is_file(), "post_seal_provenance_note_missing")
    _require(
        _sha256(provenance_note.read_bytes())
        == binding["post_seal_provenance_note_sha256"],
        "post_seal_provenance_note_hash_mismatch",
    )
    return {
        "pass": True,
        "annotated_tag": tag,
        "sealed_commit_sha": commit,
        "sealed_entries_verified": len(entries),
        "current_sealed_entries_unchanged": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the Stage 3 content seal's annotated Git binding."
    )
    parser.add_argument("binding", nargs="?", type=Path, default=DEFAULT_BINDING)
    args = parser.parse_args(argv)
    report = verify_repository_binding(args.binding)
    print(
        "PASS: Stage 3 repository binding is consistent "
        f"tag={report['annotated_tag']} "
        f"commit={report['sealed_commit_sha']} "
        f"sealed_entries_verified={report['sealed_entries_verified']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
