from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from .stage2_replay import (
    ARCHIVE_COMMITMENT_ALGORITHM,
    FROZEN_STAGE1_COMMITMENTS,
    PUBLIC_OUTPUT_NAMES,
    ArchiveRootAudit,
    Stage2FreezeCommitments,
    Stage2ReplayError,
    Stage2ReplayResult,
    replay_program_sha256,
    run_stage2_replay,
    stage2_amendment_sha256,
    validate_stage2_provenance_key,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE_DIR = Path("outputs/private/stage1-v0.2.1-readonly-copy")
DEFAULT_PUBLIC_STAGE1_DIR = Path("results/stage1-v0.2.1")
DEFAULT_OUTPUT_DIR = Path("outputs/private/stage2-v0.2.2-replay")
DEFAULT_AUTHORITY_DIR = Path("outputs/private/authorities/stage2-v0.2.2")
DEFAULT_FREEZE_MANIFEST = Path("manifests/stage2-v0.2.2-freeze.json")
DEFAULT_ARCHIVE_COMMITMENT = Path(
    "preservation/stage1-v0.2.1/archive-commitment.json"
)
PROVENANCE_KEY_ENV = "MAS_SAFETY_STAGE2_PROVENANCE_KEY_B64"
FREEZE_SCHEMA_VERSION = "stage2-replay-freeze-v1"
ARCHIVE_SCHEMA_VERSION = "mas-private-archive-commitment-v1"
FROZEN_PRIVATE_ARCHIVE_ROOT_SHA256 = (
    "1d22d2c571abb161470715b503a603e577314d60987348da775c09929ac52f51"
)
FROZEN_PRIVATE_ARCHIVE_REGULAR_FILE_COUNT = 1537
FROZEN_PRIVATE_ARCHIVE_DIRECTORY_COUNT = 6
FROZEN_CLAIM_BOUNDARY = (
    "Exact deterministic middleware audit on frozen live-agent decision paths; "
    "not closed-loop adaptation, learned defense effectiveness, deployment "
    "prevalence, or confirmatory evidence."
)

_FREEZE_FIELDS = frozenset(
    {
        "schema_version",
        "freeze_ref",
        "implementation_commit_sha",
        "commitments",
        "tracked_artifact_sha256",
        "claim_boundary",
    }
)
_COMMITMENT_FIELDS = frozenset(
    {
        "amendment_sha256",
        "replay_program_sha256",
        "private_archive_root_sha256",
        "private_archive_regular_file_count",
        "private_archive_directory_count",
        "source_dependency_root_sha256",
        "public_stage1_runs_sha256",
        "public_stage1_summary_sha256",
        "provenance_key_id",
        "provenance_key_sha256",
    }
)
_ARCHIVE_COMMITMENT_FIELDS = frozenset(
    {
        "algorithm",
        "archive_scope",
        "directory_count",
        "merkle_root_sha256",
        "privacy",
        "regular_file_count",
        "schema_version",
    }
)
_ARCHIVE_SCOPE_FIELDS = frozenset(
    {
        "entries",
        "exclusions",
        "metadata_committed",
        "metadata_excluded",
        "multiply_linked_regular_files",
        "special_files",
        "symbolic_links",
    }
)
_ARCHIVE_PRIVACY_FIELDS = frozenset(
    {
        "filenames_disclosed",
        "per_file_digests_disclosed",
        "per_file_sizes_disclosed",
    }
)
_MANDATORY_TRACKED_ARTIFACTS = frozenset(
    {
        "preservation/stage1-v0.2.1/archive-commitment.json",
        "protocols/v0.2.2-stage2-replay-amendment.md",
        "results/stage1-v0.2.1/runs.csv",
        "results/stage1-v0.2.1/summary.json",
        "scripts/archive_commitment.py",
        "src/mas_safety/stage2_cli.py",
        "src/mas_safety/stage2_metrics.py",
        "src/mas_safety/stage2_replay.py",
    }
)
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
_PREFIXED_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_COMMIT_SHA = re.compile(r"[0-9a-f]{40,64}")
_SAFE_ARTIFACT_PATH = re.compile(r"[A-Za-z0-9._/-]+")
_SAFE_FREEZE_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}")


class Stage2CLIError(RuntimeError):
    """Fail-closed command preparation error with no secret-bearing context."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise Stage2CLIError(code)


def configure_stage2_parser(subparsers: Any) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        "run-stage2-replay",
        help="Run the frozen, deterministic Stage 2 middleware replay exactly once.",
    )
    parser.add_argument(
        "--source",
        "--source-dir",
        dest="source_dir",
        type=Path,
        default=DEFAULT_SOURCE_DIR,
        help="Verified owner-readable, non-writable Stage 1 private-archive copy.",
    )
    parser.add_argument(
        "--public-stage1",
        "--public-stage1-dir",
        dest="public_stage1_dir",
        type=Path,
        default=DEFAULT_PUBLIC_STAGE1_DIR,
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--freeze-manifest", type=Path, default=DEFAULT_FREEZE_MANIFEST
    )
    parser.add_argument(
        "--archive-commitment", type=Path, default=DEFAULT_ARCHIVE_COMMITMENT
    )
    parser.set_defaults(
        authority_dir=DEFAULT_AUTHORITY_DIR,
        stage2_executor=execute_stage2_command,
    )
    return parser


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Stage2CLIError("json_duplicate_key")
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> None:
    raise Stage2CLIError("json_nonfinite_number")


def _strict_json_load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except Stage2CLIError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Stage2CLIError("json_input_invalid") from exc
    _require(isinstance(value, dict), "json_root_not_object")
    return value


def _is_bare_sha256(value: object) -> bool:
    return isinstance(value, str) and _HEX_SHA256.fullmatch(value) is not None


def _safe_relative_artifact_path(value: object) -> str:
    _require(isinstance(value, str), "tracked_artifact_path_invalid")
    _require(_SAFE_ARTIFACT_PATH.fullmatch(value) is not None, "tracked_artifact_path_invalid")
    candidate = PurePosixPath(value)
    _require(
        not candidate.is_absolute()
        and value == candidate.as_posix()
        and ".." not in candidate.parts
        and "." not in candidate.parts,
        "tracked_artifact_path_invalid",
    )
    return value


def load_stage2_freeze_manifest(path: str | Path) -> dict[str, Any]:
    manifest = _strict_json_load(Path(path))
    _require(set(manifest) == _FREEZE_FIELDS, "freeze_manifest_field_set_invalid")
    _require(
        manifest.get("schema_version") == FREEZE_SCHEMA_VERSION,
        "freeze_manifest_schema_invalid",
    )
    freeze_ref = manifest.get("freeze_ref")
    _require(
        isinstance(freeze_ref, str)
        and _SAFE_FREEZE_REF.fullmatch(freeze_ref) is not None
        and ".." not in freeze_ref
        and "//" not in freeze_ref
        and "@{" not in freeze_ref
        and not freeze_ref.endswith("."),
        "freeze_ref_invalid",
    )
    _require(
        isinstance(manifest.get("implementation_commit_sha"), str)
        and _COMMIT_SHA.fullmatch(manifest["implementation_commit_sha"]) is not None,
        "implementation_commit_invalid",
    )
    _require(
        manifest.get("claim_boundary") == FROZEN_CLAIM_BOUNDARY,
        "freeze_claim_boundary_invalid",
    )

    commitments = manifest.get("commitments")
    _require(isinstance(commitments, dict), "freeze_commitments_invalid")
    _require(set(commitments) == _COMMITMENT_FIELDS, "freeze_commitment_field_set_invalid")
    bare_digest_fields = (
        "amendment_sha256",
        "private_archive_root_sha256",
        "source_dependency_root_sha256",
        "public_stage1_runs_sha256",
        "public_stage1_summary_sha256",
        "provenance_key_sha256",
    )
    _require(
        all(_is_bare_sha256(commitments.get(field)) for field in bare_digest_fields),
        "freeze_digest_invalid",
    )
    _require(
        isinstance(commitments.get("replay_program_sha256"), str)
        and _PREFIXED_SHA256.fullmatch(commitments["replay_program_sha256"]) is not None,
        "freeze_replay_program_digest_invalid",
    )
    _require(
        type(commitments.get("private_archive_regular_file_count")) is int
        and type(commitments.get("private_archive_directory_count")) is int,
        "freeze_archive_counts_invalid",
    )
    key_id = commitments.get("provenance_key_id")
    _require(isinstance(key_id, str), "freeze_provenance_key_id_invalid")

    tracked = manifest.get("tracked_artifact_sha256")
    _require(isinstance(tracked, dict), "tracked_artifact_map_invalid")
    normalized: dict[str, str] = {}
    for raw_path, digest in tracked.items():
        artifact_path = _safe_relative_artifact_path(raw_path)
        _require(artifact_path not in normalized, "tracked_artifact_path_duplicate")
        _require(_is_bare_sha256(digest), "tracked_artifact_digest_invalid")
        normalized[artifact_path] = digest
    _require(
        _MANDATORY_TRACKED_ARTIFACTS.issubset(normalized),
        "mandatory_tracked_artifact_missing",
    )
    return manifest


def _resolve_from_repository(path: Path, repository: Path) -> Path:
    return path if path.is_absolute() else repository / path


def _lstat(path: Path, code: str) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        raise Stage2CLIError(code) from exc


def _require_regular_input(path: Path, code: str) -> None:
    metadata = _lstat(path, code)
    _require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1, code)


def _require_directory_input(path: Path, code: str) -> None:
    metadata = _lstat(path, code)
    _require(stat.S_ISDIR(metadata.st_mode), code)


def _verify_read_only_archive(path: Path) -> None:
    _require_directory_input(path, "source_archive_unsafe")
    try:
        for directory, directory_names, file_names in os.walk(path, followlinks=False):
            directory_path = Path(directory)
            directory_metadata = directory_path.lstat()
            _require(
                stat.S_ISDIR(directory_metadata.st_mode)
                and directory_metadata.st_mode & 0o222 == 0,
                "source_archive_not_read_only",
            )
            for name in (*directory_names, *file_names):
                entry = directory_path / name
                metadata = entry.lstat()
                _require(not stat.S_ISLNK(metadata.st_mode), "source_archive_unsafe")
                _require(
                    stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode),
                    "source_archive_unsafe",
                )
                _require(metadata.st_mode & 0o222 == 0, "source_archive_not_read_only")
                if stat.S_ISREG(metadata.st_mode):
                    _require(metadata.st_nlink == 1, "source_archive_unsafe")
    except Stage2CLIError:
        raise
    except OSError as exc:
        raise Stage2CLIError("source_archive_unsafe") from exc


def _canonical_path(path: Path) -> Path:
    try:
        return path.resolve(strict=False)
    except OSError as exc:
        raise Stage2CLIError("path_resolution_failed") from exc


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _verify_runtime_paths(
    *,
    source: Path,
    public_stage1: Path,
    output: Path,
    authority: Path,
    freeze_manifest: Path,
    archive_commitment: Path,
) -> None:
    _verify_read_only_archive(source)
    _require_directory_input(public_stage1, "public_stage1_directory_unsafe")
    _require_regular_input(
        public_stage1 / "runs.csv", "public_stage1_input_unsafe"
    )
    _require_regular_input(
        public_stage1 / "summary.json", "public_stage1_input_unsafe"
    )
    _require_regular_input(freeze_manifest, "freeze_manifest_unsafe")
    _require_regular_input(archive_commitment, "archive_commitment_unsafe")
    _require(not os.path.lexists(output), "stage2_output_already_exists")
    if os.path.lexists(authority):
        _require_directory_input(authority, "authority_directory_unsafe")
    source_resolved = _canonical_path(source)
    output_resolved = _canonical_path(output)
    authority_resolved = _canonical_path(authority)
    _require(
        not _paths_overlap(source_resolved, output_resolved),
        "source_output_path_overlap",
    )
    _require(
        not _paths_overlap(source_resolved, authority_resolved),
        "source_authority_path_overlap",
    )
    _require(
        not _paths_overlap(output_resolved, authority_resolved),
        "output_authority_path_overlap",
    )


def _git_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_")
        and key
        not in {
            PROVENANCE_KEY_ENV,
            "OPENAI_API_KEY",
        }
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
        }
    )
    return environment


def _git(
    repository: Path,
    arguments: list[str],
    *,
    check: bool = True,
) -> bytes:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=repository,
            env=_git_environment(),
            check=False,
            capture_output=True,
        )
    except OSError as exc:
        raise Stage2CLIError("git_command_unavailable") from exc
    if check and completed.returncode != 0:
        raise Stage2CLIError("git_verification_failed")
    return completed.stdout


def _git_returncode(repository: Path, arguments: list[str]) -> int:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=repository,
            env=_git_environment(),
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise Stage2CLIError("git_command_unavailable") from exc
    return completed.returncode


def _git_text(repository: Path, arguments: list[str]) -> str:
    try:
        return _git(repository, arguments).decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise Stage2CLIError("git_output_invalid") from exc


def _repository_relative(path: Path, repository: Path, code: str) -> str:
    try:
        relative = path.resolve(strict=True).relative_to(repository.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise Stage2CLIError(code) from exc
    value = relative.as_posix()
    _safe_relative_artifact_path(value)
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise Stage2CLIError("tracked_artifact_unreadable") from exc
    return digest.hexdigest()


def _verify_git_and_tracked_artifacts(
    repository: Path,
    freeze_manifest_path: Path,
    manifest: Mapping[str, Any],
) -> str:
    _require_directory_input(repository / ".git", "git_repository_missing")
    status = _git(repository, ["status", "--porcelain=v1", "--untracked-files=all"])
    _require(status == b"", "git_worktree_dirty")
    head = _git_text(repository, ["rev-parse", "--verify", "HEAD^{commit}"])
    _require(_COMMIT_SHA.fullmatch(head) is not None, "git_head_invalid")

    freeze_ref = str(manifest["freeze_ref"])
    tag_ref = f"refs/tags/{freeze_ref}"
    _git(repository, ["show-ref", "--verify", "--quiet", tag_ref])
    resolved_ref = _git_text(
        repository, ["rev-parse", "--verify", f"{tag_ref}^{{commit}}"]
    )
    _require(resolved_ref == head, "freeze_ref_not_head")

    implementation_commit = str(manifest["implementation_commit_sha"])
    _git(repository, ["cat-file", "-e", f"{implementation_commit}^{{commit}}"])
    ancestry_returncode = _git_returncode(
        repository,
        ["merge-base", "--is-ancestor", implementation_commit, head],
    )
    _require(ancestry_returncode == 0, "implementation_not_ancestor")
    parent_line = _git_text(repository, ["rev-list", "--parents", "-n", "1", head])
    parents = parent_line.split()[1:]
    _require(parents == [implementation_commit], "implementation_not_direct_parent")

    freeze_relative = _repository_relative(
        freeze_manifest_path, repository, "freeze_manifest_outside_repository"
    )
    _git(repository, ["ls-files", "--error-unmatch", "--", freeze_relative])
    manifest_at_head = _git(
        repository, ["show", f"{head}:{freeze_relative}"]
    )
    _require(
        manifest_at_head == freeze_manifest_path.read_bytes(),
        "freeze_manifest_differs_from_head",
    )

    tracked = manifest["tracked_artifact_sha256"]
    _require(isinstance(tracked, dict), "tracked_artifact_map_invalid")
    for relative, expected_digest in tracked.items():
        relative_path = _safe_relative_artifact_path(relative)
        working_path = repository / relative_path
        _require_regular_input(working_path, "tracked_artifact_unsafe")
        _git(repository, ["ls-files", "--error-unmatch", "--", relative_path])
        _require(
            _sha256_file(working_path) == expected_digest,
            "tracked_artifact_hash_mismatch",
        )
        implementation_bytes = _git(
            repository, ["show", f"{implementation_commit}:{relative_path}"]
        )
        _require(
            hashlib.sha256(implementation_bytes).hexdigest() == expected_digest,
            "implementation_artifact_hash_mismatch",
        )
        head_bytes = _git(repository, ["show", f"{head}:{relative_path}"])
        _require(
            hashlib.sha256(head_bytes).hexdigest() == expected_digest,
            "freeze_artifact_hash_mismatch",
        )
    return head


def _decode_stage2_provenance_key() -> bytes:
    encoded = os.environ.get(PROVENANCE_KEY_ENV)
    _require(isinstance(encoded, str) and bool(encoded), "stage2_provenance_key_missing")
    try:
        key = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise Stage2CLIError("stage2_provenance_key_invalid_base64") from exc
    _require(len(key) >= 32, "stage2_provenance_key_too_short")
    return key


def _validate_archive_commitment_file(
    path: Path, commitments: Mapping[str, Any]
) -> None:
    archive = _strict_json_load(path)
    _require(
        set(archive) == _ARCHIVE_COMMITMENT_FIELDS,
        "archive_commitment_field_set_invalid",
    )
    archive_scope = archive.get("archive_scope")
    privacy = archive.get("privacy")
    _require(
        isinstance(archive_scope, dict)
        and set(archive_scope) == _ARCHIVE_SCOPE_FIELDS,
        "archive_commitment_scope_invalid",
    )
    _require(
        archive_scope
        == {
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
            "multiply_linked_regular_files": "rejected",
            "special_files": "rejected",
            "symbolic_links": "rejected",
        },
        "archive_commitment_scope_invalid",
    )
    _require(
        isinstance(privacy, dict)
        and set(privacy) == _ARCHIVE_PRIVACY_FIELDS
        and privacy
        == {
            "filenames_disclosed": False,
            "per_file_digests_disclosed": False,
            "per_file_sizes_disclosed": False,
        },
        "archive_commitment_privacy_invalid",
    )
    _require(
        archive.get("schema_version") == ARCHIVE_SCHEMA_VERSION,
        "archive_commitment_schema_invalid",
    )
    _require(
        archive.get("algorithm") == ARCHIVE_COMMITMENT_ALGORITHM,
        "archive_commitment_algorithm_invalid",
    )
    _require(
        archive.get("merkle_root_sha256") == FROZEN_PRIVATE_ARCHIVE_ROOT_SHA256,
        "archive_commitment_root_invalid",
    )
    _require(
        archive.get("regular_file_count")
        == FROZEN_PRIVATE_ARCHIVE_REGULAR_FILE_COUNT
        and archive.get("directory_count") == FROZEN_PRIVATE_ARCHIVE_DIRECTORY_COUNT,
        "archive_commitment_counts_invalid",
    )
    _require(
        commitments["private_archive_root_sha256"]
        == archive["merkle_root_sha256"]
        and commitments["private_archive_regular_file_count"]
        == archive["regular_file_count"]
        and commitments["private_archive_directory_count"]
        == archive["directory_count"],
        "freeze_archive_commitment_mismatch",
    )


def _verify_manifest_commitments(
    manifest: Mapping[str, Any],
    *,
    repository: Path,
    public_stage1: Path,
    archive_commitment: Path,
    key: bytes,
) -> Stage2FreezeCommitments:
    commitments = manifest["commitments"]
    _require(isinstance(commitments, dict), "freeze_commitments_invalid")
    _validate_archive_commitment_file(archive_commitment, commitments)
    _require(
        commitments["amendment_sha256"] == stage2_amendment_sha256(),
        "amendment_hash_mismatch",
    )
    _require(
        commitments["replay_program_sha256"] == replay_program_sha256(),
        "replay_program_hash_mismatch",
    )
    _require(
        commitments["public_stage1_runs_sha256"]
        == _sha256_file(public_stage1 / "runs.csv")
        and commitments["public_stage1_summary_sha256"]
        == _sha256_file(public_stage1 / "summary.json"),
        "public_stage1_hash_mismatch",
    )
    key_id = commitments["provenance_key_id"]
    _require(isinstance(key_id, str), "freeze_provenance_key_id_invalid")
    try:
        key_fingerprint = validate_stage2_provenance_key(key, key_id)
    except ValueError as exc:
        raise Stage2CLIError("stage2_provenance_identity_invalid") from exc
    _require(
        hmac.compare_digest(key_fingerprint, commitments["provenance_key_sha256"]),
        "stage2_provenance_fingerprint_mismatch",
    )
    return Stage2FreezeCommitments(
        amendment_sha256=commitments["amendment_sha256"],
        freeze_commit_sha="",
        replay_program_sha256=commitments["replay_program_sha256"],
        private_archive_root_sha256=commitments["private_archive_root_sha256"],
        source_dependency_root_sha256=commitments["source_dependency_root_sha256"],
        public_stage1_runs_sha256=commitments["public_stage1_runs_sha256"],
        public_stage1_summary_sha256=commitments["public_stage1_summary_sha256"],
        provenance_key_id=key_id,
        provenance_key_sha256=key_fingerprint,
        private_archive_regular_file_count=commitments[
            "private_archive_regular_file_count"
        ],
        private_archive_directory_count=commitments[
            "private_archive_directory_count"
        ],
    )


def _run_archive_verifier(
    source: Path,
    commitment: Path,
    repository: Path,
) -> dict[str, Any]:
    verifier = repository / "scripts" / "archive_commitment.py"
    _require_regular_input(verifier, "archive_verifier_missing")
    try:
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.upper().startswith(("PYTHON", "_PYTHON"))
            and key.upper() not in {"__PYVENV_LAUNCHER__", "VIRTUAL_ENV"}
            and not key.upper().startswith(("LD_", "DYLD_"))
            and "PROVENANCE" not in key.upper()
            and not key.upper().startswith("OPENAI")
            and "BASE_URL" not in key.upper()
            and "CUSTOM_HEADER" not in key.upper()
            and "DEFAULT_HEADER" not in key.upper()
        }
        environment.update(
            {
                "PYTHONHASHSEED": "0",
                "PYTHONNOUSERSITE": "1",
                "PYTHONSAFEPATH": "1",
            }
        )
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(verifier),
                "verify",
                str(source),
                str(commitment),
                "--json",
            ],
            cwd=repository,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Stage2CLIError("archive_verifier_failed") from exc
    _require(completed.returncode == 0, "archive_verifier_failed")
    try:
        value = json.loads(
            completed.stdout,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except Stage2CLIError:
        raise
    except json.JSONDecodeError as exc:
        raise Stage2CLIError("archive_verifier_output_invalid") from exc
    _require(isinstance(value, dict), "archive_verifier_output_invalid")
    _require(
        set(value)
        == {
            "directory_count",
            "merkle_root_sha256",
            "pass",
            "regular_file_count",
            "schema_version",
        },
        "archive_verifier_output_invalid",
    )
    _require(
        value.get("schema_version") == ARCHIVE_SCHEMA_VERSION
        and value.get("pass") is True
        and value.get("merkle_root_sha256")
        == FROZEN_PRIVATE_ARCHIVE_ROOT_SHA256
        and value.get("regular_file_count")
        == FROZEN_PRIVATE_ARCHIVE_REGULAR_FILE_COUNT
        and value.get("directory_count") == FROZEN_PRIVATE_ARCHIVE_DIRECTORY_COUNT,
        "archive_verifier_result_mismatch",
    )
    return value


def _replace_freeze_head(
    freeze: Stage2FreezeCommitments, head: str
) -> Stage2FreezeCommitments:
    return Stage2FreezeCommitments(
        amendment_sha256=freeze.amendment_sha256,
        freeze_commit_sha=head,
        replay_program_sha256=freeze.replay_program_sha256,
        private_archive_root_sha256=freeze.private_archive_root_sha256,
        source_dependency_root_sha256=freeze.source_dependency_root_sha256,
        public_stage1_runs_sha256=freeze.public_stage1_runs_sha256,
        public_stage1_summary_sha256=freeze.public_stage1_summary_sha256,
        provenance_key_id=freeze.provenance_key_id,
        provenance_key_sha256=freeze.provenance_key_sha256,
        private_archive_regular_file_count=freeze.private_archive_regular_file_count,
        private_archive_directory_count=freeze.private_archive_directory_count,
    )


def _safe_replay_result(result: Stage2ReplayResult) -> dict[str, Any]:
    _require(isinstance(result, Stage2ReplayResult), "stage2_result_type_invalid")
    _require(_is_bare_sha256(result.authority_id), "stage2_authority_id_invalid")
    _require(isinstance(result.summary, dict), "stage2_summary_invalid")
    _require(
        set(result.checksums) == set(PUBLIC_OUTPUT_NAMES)
        and all(_is_bare_sha256(value) for value in result.checksums.values()),
        "stage2_checksums_invalid",
    )
    return {
        "archive_root_audit": {
            "directory_count": FROZEN_PRIVATE_ARCHIVE_DIRECTORY_COUNT,
            "merkle_root_sha256": FROZEN_PRIVATE_ARCHIVE_ROOT_SHA256,
            "pass": True,
            "regular_file_count": FROZEN_PRIVATE_ARCHIVE_REGULAR_FILE_COUNT,
        },
        "authority": {"consumed": True, "id": result.authority_id},
        "checksums": dict(sorted(result.checksums.items())),
        "model_or_provider_calls": 0,
        "schema_version": "stage2-cli-result-v1",
        "summary": result.summary,
    }


def execute_stage2_command(
    args: argparse.Namespace,
    *,
    replay_runner: Callable[..., Stage2ReplayResult] | None = None,
) -> dict[str, Any]:
    repository = REPOSITORY_ROOT
    _require(
        Path(args.authority_dir) == DEFAULT_AUTHORITY_DIR,
        "authority_directory_override_forbidden",
    )
    source = _resolve_from_repository(Path(args.source_dir), repository)
    public_stage1 = _resolve_from_repository(Path(args.public_stage1_dir), repository)
    output = _resolve_from_repository(Path(args.output), repository)
    authority = repository / DEFAULT_AUTHORITY_DIR
    freeze_manifest_path = _resolve_from_repository(
        Path(args.freeze_manifest), repository
    )
    archive_commitment = _resolve_from_repository(
        Path(args.archive_commitment), repository
    )
    _verify_runtime_paths(
        source=source,
        public_stage1=public_stage1,
        output=output,
        authority=authority,
        freeze_manifest=freeze_manifest_path,
        archive_commitment=archive_commitment,
    )
    manifest = load_stage2_freeze_manifest(freeze_manifest_path)
    key = _decode_stage2_provenance_key()
    head = _verify_git_and_tracked_artifacts(
        repository, freeze_manifest_path, manifest
    )
    prospective_freeze = _verify_manifest_commitments(
        manifest,
        repository=repository,
        public_stage1=public_stage1,
        archive_commitment=archive_commitment,
        key=key,
    )
    stage2_freeze = _replace_freeze_head(prospective_freeze, head)

    verified_archive = _run_archive_verifier(
        source, archive_commitment, repository
    )
    archive_audit = ArchiveRootAudit(
        algorithm=ARCHIVE_COMMITMENT_ALGORITHM,
        merkle_root_sha256=verified_archive["merkle_root_sha256"],
        regular_file_count=verified_archive["regular_file_count"],
        directory_count=verified_archive["directory_count"],
        passed=True,
    )
    runner = replay_runner or run_stage2_replay
    try:
        result = runner(
            source_dir=source,
            public_stage1_dir=public_stage1,
            output_dir=output,
            authority_dir=authority,
            provenance_signing_key=key,
            provenance_key_id=stage2_freeze.provenance_key_id,
            commitments=FROZEN_STAGE1_COMMITMENTS,
            stage2_freeze=stage2_freeze,
            archive_root_audit=archive_audit,
        )
    except (Stage2ReplayError, FileExistsError, ValueError, OSError):
        raise Stage2CLIError("stage2_replay_failed") from None
    return _safe_replay_result(result)
