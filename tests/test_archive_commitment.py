from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "archive_commitment.py"
MODULE_SPEC = importlib.util.spec_from_file_location("archive_commitment", MODULE_PATH)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
archive_commitment = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = archive_commitment
MODULE_SPEC.loader.exec_module(archive_commitment)

ArchiveCommitmentError = archive_commitment.ArchiveCommitmentError
compute_commitment = archive_commitment.compute_commitment
verify_commitment = archive_commitment.verify_commitment


KNOWN_ROOT = "4e48085078ff24d8687756ccc178e4b2b38e3551ce7fbab04e4d28852adc9b79"


def _archive_fixture(root: Path, *, reverse: bool = False) -> None:
    operations = [
        lambda: (root / "alpha.txt").write_bytes(b"alpha\n"),
        lambda: (root / "empty").mkdir(),
        lambda: (root / "nested").mkdir(),
        lambda: (root / "nested" / "data.bin").write_bytes(b"\x00\x01"),
    ]
    if reverse:
        operations = [operations[1], operations[2], operations[3], operations[0]]
    for operation in operations:
        operation()


def test_archive_commitment_known_root_and_round_trip(tmp_path: Path) -> None:
    archive = tmp_path / "archive"
    archive.mkdir()
    _archive_fixture(archive)

    commitment = compute_commitment(archive)

    assert commitment["merkle_root_sha256"] == KNOWN_ROOT
    assert commitment["regular_file_count"] == 2
    assert commitment["directory_count"] == 2
    assert commitment["privacy"] == {
        "filenames_disclosed": False,
        "per_file_digests_disclosed": False,
        "per_file_sizes_disclosed": False,
    }
    manifest_path = tmp_path / "commitment.json"
    manifest_path.write_text(json.dumps(commitment), encoding="utf-8")
    assert verify_commitment(archive, manifest_path)["pass"] is True


def test_commitment_is_stable_across_creation_order_and_modes(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    _archive_fixture(first)
    _archive_fixture(second, reverse=True)

    for path in second.rglob("*"):
        path.chmod(0o500 if path.is_dir() else 0o400)

    assert compute_commitment(first) == compute_commitment(second)


@pytest.mark.parametrize("mutation", ["bytes", "add", "delete", "rename"])
def test_commitment_detects_content_and_layout_tampering(
    tmp_path: Path, mutation: str
) -> None:
    archive = tmp_path / "archive"
    archive.mkdir()
    _archive_fixture(archive)
    commitment = compute_commitment(archive)

    if mutation == "bytes":
        (archive / "alpha.txt").write_bytes(b"changed\n")
    elif mutation == "add":
        (archive / "added.txt").write_bytes(b"added")
    elif mutation == "delete":
        (archive / "alpha.txt").unlink()
    else:
        (archive / "alpha.txt").rename(archive / "renamed.txt")

    with pytest.raises(ArchiveCommitmentError, match="archive_commitment_mismatch"):
        verify_commitment(archive, commitment)


def test_commitment_rejects_symbolic_links_without_disclosing_name(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = tmp_path / "archive"
    archive.mkdir()
    target = tmp_path / "target"
    target.write_text("target", encoding="utf-8")
    sensitive_name = "private-response-identifier"
    try:
        (archive / sensitive_name).symlink_to(target)
    except OSError:
        pytest.skip("symbolic links unavailable")

    exit_code = archive_commitment.main(["compute", str(archive)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "symlink_rejected" in captured.err
    assert sensitive_name not in captured.err
    assert sensitive_name not in captured.out


def test_commitment_rejects_hardlinks(tmp_path: Path) -> None:
    archive = tmp_path / "archive"
    archive.mkdir()
    source = archive / "source.bin"
    source.write_bytes(b"same inode")
    try:
        os.link(source, archive / "alias.bin")
    except OSError:
        pytest.skip("hard links unavailable")

    with pytest.raises(ArchiveCommitmentError, match="hardlink_rejected"):
        compute_commitment(archive)


def test_commitment_rejects_special_files(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFOs unavailable")
    archive = tmp_path / "archive"
    archive.mkdir()
    try:
        os.mkfifo(archive / "pipe")
    except OSError:
        pytest.skip("FIFOs unavailable")

    with pytest.raises(ArchiveCommitmentError, match="special_file_rejected"):
        compute_commitment(archive)


def test_commitment_detects_change_between_complete_snapshots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "archive"
    archive.mkdir()
    payload = archive / "payload.bin"
    payload.write_bytes(b"before")
    real_snapshot = archive_commitment._take_snapshot
    calls = 0

    def snapshot_then_mutate(root: Path) -> archive_commitment.Snapshot:
        nonlocal calls
        calls += 1
        snapshot = real_snapshot(root)
        if calls == 1:
            payload.write_bytes(b"after")
        return snapshot

    monkeypatch.setattr(archive_commitment, "_take_snapshot", snapshot_then_mutate)
    with pytest.raises(
        ArchiveCommitmentError, match="archive_changed_between_snapshots"
    ):
        compute_commitment(archive)


def test_commitment_manifest_is_not_part_of_committed_tree(tmp_path: Path) -> None:
    archive = tmp_path / "archive"
    archive.mkdir()
    _archive_fixture(archive)

    exit_code = archive_commitment.main(
        ["compute", str(archive), "--output", str(archive / "commitment.json")]
    )

    assert exit_code == 2
    assert not (archive / "commitment.json").exists()


def test_copy_with_read_only_permissions_preserves_root(tmp_path: Path) -> None:
    source = tmp_path / "source"
    copied = tmp_path / "copied"
    source.mkdir()
    _archive_fixture(source)
    shutil.copytree(source, copied)
    expected = compute_commitment(source)

    for path in sorted(copied.rglob("*"), reverse=True):
        path.chmod(0o500 if path.is_dir() else 0o400)
    copied.chmod(0o500)

    assert verify_commitment(copied, expected)["pass"] is True
