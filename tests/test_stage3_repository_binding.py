from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_stage3_repository_binding.py"
SPEC = importlib.util.spec_from_file_location("verify_stage3_repository_binding", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_stage3_repository_binding() -> None:
    if not (ROOT / ".git").exists():
        pytest.skip("repository binding requires Git object metadata")
    report = MODULE.verify_repository_binding()
    assert report == {
        "pass": True,
        "annotated_tag": "stage3-construction-seal-2026-09-01",
        "sealed_commit_sha": "3fec886a9fdd1fbcde66f7732f972ec51c33823e",
        "sealed_entries_verified": 11,
        "current_sealed_entries_unchanged": True,
    }


def test_stage3_repository_binding_rejects_provenance_note_hash_tamper(
    tmp_path: Path,
) -> None:
    if not (ROOT / ".git").exists():
        pytest.skip("repository binding requires Git object metadata")
    binding = json.loads(MODULE.DEFAULT_BINDING.read_text(encoding="utf-8"))
    binding["post_seal_provenance_note_sha256"] = "0" * 64
    tampered = tmp_path / "repository_binding.json"
    tampered.write_text(json.dumps(binding), encoding="utf-8")

    with pytest.raises(
        MODULE.BindingVerificationError,
        match="post_seal_provenance_note_hash_mismatch",
    ):
        MODULE.verify_repository_binding(tampered)


def test_stage3_repository_binding_rejects_current_seal_byte_drift(
    tmp_path: Path,
) -> None:
    current = tmp_path / "selection_seal.sha256"
    current.write_bytes(b"tagged seal bytes\nextra unbound entry\n")

    with pytest.raises(
        MODULE.BindingVerificationError,
        match="current_selection_seal_drift",
    ):
        MODULE._require_current_bytes(
            current,
            b"tagged seal bytes\n",
            label="selection_seal",
        )
