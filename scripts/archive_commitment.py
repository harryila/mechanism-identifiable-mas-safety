from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import struct
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

SCHEMA_VERSION = "mas-private-archive-commitment-v1"
ALGORITHM = "sha256-rfc6962-domain-separated-tree-v1"
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
_CHUNK_SIZE = 1024 * 1024


class ArchiveCommitmentError(RuntimeError):
    """A redaction-safe archive validation failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Snapshot:
    merkle_root_sha256: str
    regular_file_count: int
    directory_count: int


def _u64(value: int) -> bytes:
    if not 0 <= value < 2**64:
        raise ArchiveCommitmentError("entry_too_large")
    return struct.pack(">Q", value)


def _encode_relative_path(parts: tuple[str, ...]) -> bytes:
    try:
        encoded_parts = [part.encode("utf-8", "strict") for part in parts]
    except UnicodeEncodeError as exc:
        raise ArchiveCommitmentError("non_utf8_path") from exc
    if any(not part or b"\x00" in part or b"/" in part for part in encoded_parts):
        raise ArchiveCommitmentError("noncanonical_path")
    return b"/".join(encoded_parts)


def _leaf_hash(record: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + record).digest()


def _merkle_tree_hash(leaves: tuple[bytes, ...]) -> bytes:
    """Return the RFC 6962 split-tree hash for already domain-separated leaves."""

    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    left = _merkle_tree_hash(leaves[:split])
    right = _merkle_tree_hash(leaves[split:])
    return hashlib.sha256(b"\x01" + left + right).digest()


def _hash_stream(handle: BinaryIO) -> tuple[bytes, int]:
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = handle.read(_CHUNK_SIZE)
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)
    return digest.digest(), total


def _hash_regular_file(path: Path, initial: os.stat_result) -> tuple[bytes, int]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ArchiveCommitmentError("file_open_failed") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ArchiveCommitmentError("entry_type_changed")
        if before.st_nlink != 1:
            raise ArchiveCommitmentError("hardlink_rejected")
        if (before.st_dev, before.st_ino) != (initial.st_dev, initial.st_ino):
            raise ArchiveCommitmentError("entry_changed_during_snapshot")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content_sha256, bytes_read = _hash_stream(handle)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    stable_fields_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        before.st_nlink,
    )
    stable_fields_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_nlink,
    )
    if stable_fields_before != stable_fields_after or bytes_read != after.st_size:
        raise ArchiveCommitmentError("file_changed_during_snapshot")
    return content_sha256, bytes_read


def _take_snapshot(root: Path) -> Snapshot:
    try:
        root_stat = os.lstat(root)
    except OSError as exc:
        raise ArchiveCommitmentError("archive_unavailable") from exc
    if not stat.S_ISDIR(root_stat.st_mode):
        raise ArchiveCommitmentError("archive_not_directory")

    entries: list[tuple[bytes, bytes]] = []
    canonical_paths: set[bytes] = set()
    file_count = 0
    directory_count = 0

    def visit(directory: Path, parts: tuple[str, ...]) -> None:
        nonlocal file_count, directory_count
        try:
            children = list(os.scandir(directory))
        except OSError as exc:
            raise ArchiveCommitmentError("directory_scan_failed") from exc
        children.sort(key=lambda item: os.fsencode(item.name))
        for child in children:
            child_parts = (*parts, child.name)
            relative_path = _encode_relative_path(child_parts)
            if relative_path in canonical_paths:
                raise ArchiveCommitmentError("canonical_path_collision")
            canonical_paths.add(relative_path)
            child_path = Path(child.path)
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise ArchiveCommitmentError("entry_stat_failed") from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise ArchiveCommitmentError("symlink_rejected")
            if stat.S_ISDIR(metadata.st_mode):
                record = b"D" + _u64(len(relative_path)) + relative_path
                entries.append((relative_path, _leaf_hash(record)))
                directory_count += 1
                visit(child_path, child_parts)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ArchiveCommitmentError("special_file_rejected")
            if metadata.st_nlink != 1:
                raise ArchiveCommitmentError("hardlink_rejected")
            content_sha256, size = _hash_regular_file(child_path, metadata)
            record = (
                b"F"
                + _u64(len(relative_path))
                + relative_path
                + _u64(size)
                + content_sha256
            )
            entries.append((relative_path, _leaf_hash(record)))
            file_count += 1

    visit(root, ())
    entries.sort(key=lambda item: item[0])
    leaves = tuple(leaf for _path, leaf in entries)
    return Snapshot(
        merkle_root_sha256=_merkle_tree_hash(leaves).hex(),
        regular_file_count=file_count,
        directory_count=directory_count,
    )


def _manifest(snapshot: Snapshot) -> dict[str, Any]:
    return {
        "algorithm": ALGORITHM,
        "archive_scope": {
            "entries": "all descendant directories and regular files",
            "exclusions": [],
            "metadata_committed": [
                "entry_type",
                "relative_posix_utf8_path",
                "regular_file_size",
                "regular_file_sha256",
            ],
            "metadata_excluded": [
                "mode",
                "uid",
                "gid",
                "mtime",
                "ctime",
                "xattrs",
            ],
            "special_files": "rejected",
            "symbolic_links": "rejected",
            "multiply_linked_regular_files": "rejected",
        },
        "directory_count": snapshot.directory_count,
        "merkle_root_sha256": snapshot.merkle_root_sha256,
        "privacy": {
            "filenames_disclosed": False,
            "per_file_digests_disclosed": False,
            "per_file_sizes_disclosed": False,
        },
        "regular_file_count": snapshot.regular_file_count,
        "schema_version": SCHEMA_VERSION,
    }


def compute_commitment(archive: str | Path) -> dict[str, Any]:
    root = Path(archive)
    first = _take_snapshot(root)
    second = _take_snapshot(root)
    if first != second:
        raise ArchiveCommitmentError("archive_changed_between_snapshots")
    return _manifest(first)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ArchiveCommitmentError("commitment_duplicate_key")
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    raise ArchiveCommitmentError("commitment_nonfinite_number")


def read_commitment(path: str | Path) -> dict[str, Any]:
    try:
        text = Path(path).read_text(encoding="utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except ArchiveCommitmentError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArchiveCommitmentError("commitment_unreadable") from exc
    if not isinstance(value, dict):
        raise ArchiveCommitmentError("commitment_not_object")
    root = value.get("merkle_root_sha256")
    if not isinstance(root, str) or _HEX_SHA256.fullmatch(root) is None:
        raise ArchiveCommitmentError("commitment_root_invalid")
    return value


def verify_commitment(
    archive: str | Path,
    commitment: str | Path | dict[str, Any],
) -> dict[str, Any]:
    supplied = read_commitment(commitment) if not isinstance(commitment, dict) else commitment
    observed = compute_commitment(archive)
    if supplied != observed:
        raise ArchiveCommitmentError("archive_commitment_mismatch")
    return {
        "directory_count": observed["directory_count"],
        "merkle_root_sha256": observed["merkle_root_sha256"],
        "pass": True,
        "regular_file_count": observed["regular_file_count"],
        "schema_version": SCHEMA_VERSION,
    }


def _path_is_within(candidate: Path, parent: Path) -> bool:
    try:
        candidate.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def _write_new_commitment(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        raise ArchiveCommitmentError("commitment_output_exists")
    if not path.parent.is_dir():
        raise ArchiveCommitmentError("commitment_output_parent_missing")
    payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".archive-commitment-",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except Exception:
        try:
            temporary_path.unlink()
        except OSError:
            pass
        raise


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compute or verify a redaction-safe private archive commitment."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    compute = subparsers.add_parser("compute")
    compute.add_argument("archive", type=Path)
    compute.add_argument("--output", type=Path)
    compute.add_argument("--quiet", action="store_true")

    verify = subparsers.add_parser("verify")
    verify.add_argument("archive", type=Path)
    verify.add_argument("commitment", type=Path)
    verify.add_argument("--json", action="store_true")
    verify.add_argument("--quiet", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "compute":
            if args.output is not None and _path_is_within(args.output, args.archive):
                raise ArchiveCommitmentError("commitment_output_inside_archive")
            value = compute_commitment(args.archive)
            if args.output is not None:
                _write_new_commitment(args.output, value)
            if args.quiet:
                print(value["merkle_root_sha256"])
            else:
                print(json.dumps(value, indent=2, sort_keys=True))
            return 0

        report = verify_commitment(args.archive, args.commitment)
        if not args.quiet:
            if args.json:
                print(json.dumps(report, indent=2, sort_keys=True))
            else:
                print("PASS: archive commitment matches")
                print(f"root_sha256={report['merkle_root_sha256']}")
                print(f"regular_files={report['regular_file_count']}")
                print(f"directories={report['directory_count']}")
        return 0
    except ArchiveCommitmentError as exc:
        print(f"archive commitment failed: {exc.code}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
