from __future__ import annotations

"""Build the sanitized Stage 4 release from one COMPLETE hash-committed archive.

This is deliberately a one-way, provider-free boundary.  It hashes private
evidence in place, projects only the public verifier's outcome allowlist, and
never copies prompts, responses, traces, credentials, or ledger contents into
the public release.  A fresh destination is atomically published only after
the independent verifier accepts the staged four-file bundle as VERIFIED.
"""

import argparse
import ctypes
import errno
import hashlib
import importlib
import importlib.machinery
import importlib.util
import json
import math
import os
import re
import shutil
import stat
import sys
import sysconfig
import tempfile
import zipimport
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PRIVATE_ARCHIVE = ROOT / "outputs" / "private" / "stage4-v0.4-confirmatory"
DEFAULT_DESTINATION = ROOT / "results" / "stage4-v0.4"
DEFAULT_SCHEDULE = ROOT / "manifests" / "stage4_schedule.json"
DEFAULT_FREEZE = ROOT / "manifests" / "stage4_freeze.json"

ARCHIVE_SCHEMA_VERSION = "stage4-confirmatory-private-archive-v1"
EXECUTION_SCHEMA_VERSION = "stage4-confirmatory-execution-v1"
PRIVATE_RELEASE_SOURCE_SCHEMA_VERSION = "stage4-private-release-source-v1"
PRIVATE_OUTCOME_SCHEMA_VERSION = "stage4-confirmatory-outcomes-v1"
PRIVATE_DECISION_SCHEMA_VERSION = "stage4-confirmatory-decision-v1"
EXECUTION_COMMITMENT_SCHEMA_VERSION = "stage4-outcome-commitments-v1"
EXECUTION_EVENT_SCHEMA_VERSION = "stage4-confirmatory-execution-event-v1"
STAGE4_BUDGET_PHASE = "stage_4_confirmatory"
AUTHORITY_SCHEMA_VERSION = "stage4-confirmatory-authority-v1"
ARCHIVED_AUTHORITY_RECEIPT_NAME = "authority_receipt.json"

ARCHIVE_MANIFEST_NAME = "private_archive_manifest.json"
COMPLETE_MARKER_NAME = "execution_complete.json"
INCOMPLETE_MARKER_NAME = "execution_incomplete.json"
PUBLIC_FILES = ("README.md", "runs.json", "summary.json")
PUBLIC_ENTRY_SET = frozenset((*PUBLIC_FILES, "SHA256SUMS"))
ARCHIVE_EXCLUSIONS = [COMPLETE_MARKER_NAME, ARCHIVE_MANIFEST_NAME]
MANDATORY_PRIVATE_FILES = frozenset(
    {
        "attempted_records.jsonl",
        ARCHIVED_AUTHORITY_RECEIPT_NAME,
        "budget_ledger.jsonl",
        "decision.json",
        "execution_commitments.json",
        "execution_events.jsonl",
        "execution_started.json",
        "outcomes.json",
        "private_release_source.json",
    }
)
EXECUTION_STARTED_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "freeze_commit_sha",
        "freeze_manifest_sha256",
        "schedule_hash",
        "batch_id",
        "provider_calls_at_creation",
        "injected_test_backend",
        "encrypted_storage_attestation_sha256",
        "immutable_archive_attestation_sha256",
    }
)
AUTHORITY_FIELDS = frozenset(
    {
        "schema_version",
        "created_at_utc",
        "scope",
        "freeze_commit_sha",
        "freeze_manifest_sha256",
        "schedule_hash",
        "batch_id",
        "authorized_ceiling_nano_usd",
        "credential_id",
        "credential_fingerprint_sha256",
        "provenance_key_id",
        "provenance_key_fingerprint_sha256",
        "output_path_sha256",
        "encrypted_storage_attestation_sha256",
        "immutable_archive_attestation_sha256",
        "rerun_under_same_authority",
        "contains_secret_material",
    }
)

ARCHIVE_FIELDS = frozenset(
    {
        "schema_version",
        "contains_raw_private_provider_material",
        "contains_credential_or_provenance_key_material",
        "immutable_archive_attestation",
        "immutable_archive_attestation_sha256",
        "completion_marker_policy",
        "coverage_exclusions",
        "file_count",
        "files",
        "archive_commitment_sha256",
    }
)
ARCHIVE_FILE_FIELDS = frozenset({"path", "sha256", "bytes"})
COMPLETE_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "decision",
        "scheduled_run_count",
        "provider_call_count",
        "outcomes_sha256",
        "decision_sha256",
        "private_archive_manifest_sha256",
        "private_release_source_sha256",
        "terminal_event_sha256",
    }
)
PRIVATE_RELEASE_SOURCE_FIELDS = frozenset(
    {
        "schema_version",
        "private_only",
        "public_release_emitted",
        "freeze_commit_sha",
        "freeze_manifest_sha256",
        "schedule_hash",
        "schedule_file_sha256",
        "prompt_commitments_file_sha256",
        "run_bindings_sha256",
        "execution_commitments_sha256",
        "execution_commitments_file_sha256",
        "attempted_records_file_sha256",
        "traces_file_sha256",
        "budget_ledger_file_sha256",
        "outcomes_file_sha256",
        "decision_file_sha256",
    }
)
PRIVATE_OUTCOMES_DOCUMENT_FIELDS = frozenset(
    {
        "schema_version",
        "schedule_hash",
        "run_bindings_sha256",
        "execution_commitments_sha256",
        "outcomes",
    }
)
PRIVATE_OUTCOME_FIELDS = frozenset(
    {
        "sequence_index",
        "run_id",
        "pair_id",
        "scenario_id",
        "domain",
        "mechanism",
        "mechanism_on",
        "safety_variant",
        "repetition",
        "model_id",
        "seed",
        "invocation_id",
        "batch_id",
        "condition_id",
        "scheduled_workflow_run_order",
        "model_workflow_run_order",
        "local_lgh",
        "safe_completion",
        "run_completed",
        "refusal",
        "escalation",
        "attempted_agent_calls",
        "valid_structured_decisions",
        "noncompletion_reason",
        "failure_reason",
        "source_kind",
        "source_record_commitment_sha256",
        "call_audit_sha256",
        "component_hashes_sha256",
        "backend_configuration_sha256",
        "protocol_commit_sha",
        "protocol_sha256",
        "provenance_key_id",
        "backend_name",
        "replacement_attempted",
    }
)
PRIVATE_DECISION_FIELDS = frozenset(
    {
        "schema_version",
        "schedule_hash",
        "decision",
        "design_complete",
        "mechanism_off_unsafe_lgh",
        "safe_completion",
        "valid_structured_decisions",
        "nonexecution_not_overwhelming",
        "qualifying_mechanisms",
        "refusal_escalation_arms",
        "models_with_nondominant_mechanism_on_unsafe_arm",
        "mechanism_assessments",
        "qualifying_mechanism_ids",
        "noncompletion_reason_counts",
        "provider_failure_runs",
        "schema_failure_runs",
        "outcome_analysis",
        "interpretation",
    }
)
ATTEMPTED_RECORD_FIELDS = frozenset(
    {"scheduled_run_id", "source_kind", "source_sha256", "calls"}
)
CALL_AUDIT_FIELDS = frozenset(
    {
        "step_index",
        "provider_call_order",
        "decision_status",
        "structured_output_valid",
        "requested_model",
        "local_pairing_seed",
        "scheduled_workflow_run_order",
        "model_workflow_run_order",
        "repetition",
        "condition_id",
        "invocation_id",
        "scenario_id",
        "mechanism",
        "mechanism_active",
        "safety_variant",
        "protocol_commit_sha",
        "protocol_sha256",
        "batch_id",
        "raw_log_record",
        "provider_request_sha256",
        "request_record_sha256",
        "result_record_sha256",
        "result_record_kind",
        "ledger_reservation_id",
        "ledger_reservation_event_sha256",
        "ledger_terminal_event_sha256",
        "provider_native_refusal",
        "retry_count",
    }
)
EXECUTION_COMMITMENT_FIELDS = frozenset(
    {
        "schema_version",
        "run_bindings_sha256",
        "protocol_commit_sha",
        "protocol_sha256",
        "provenance_key_id",
        "backend_name",
        "run_artifacts",
    }
)
RUN_ARTIFACT_FIELDS = frozenset(
    {
        "scheduled_run_id",
        "component_hashes_sha256",
        "backend_configuration_sha256",
    }
)

RAW_REQUEST_FIELDS = frozenset(
    {
        "record_version",
        "attempted_at_utc",
        "provider_call_order",
        "local_pairing_seed",
        "prompt_sha256",
        "provider_request_sha256",
        "run_metadata",
        "budget_reservation",
        "provider_request",
    }
)
RAW_RESPONSE_FIELDS = frozenset(
    {
        "record_version",
        "received_at_utc",
        "transport_request_id",
        "latency_ms",
        "budget_event",
        "provider_response",
    }
)
RAW_ERROR_FIELDS = frozenset(
    {
        "record_version",
        "recorded_at_utc",
        "error_type",
        "transport_request_id",
        "provider_error_response",
        "latency_ms",
        "budget_event",
    }
)
RAW_RUN_METADATA_FIELDS = frozenset(
    {
        "scheduled_workflow_run_order",
        "model_workflow_run_order",
        "repetition",
        "condition_id",
        "invocation_id",
        "scenario_id",
        "mechanism",
        "mechanism_active",
        "safety_variant",
        "protocol_commit_sha",
        "protocol_sha256",
        "batch_id",
    }
)
BUDGET_RESERVATION_FIELDS = frozenset(
    {
        "reservation_id",
        "phase",
        "model_id",
        "call_stem",
        "request_sha256",
        "request_utf8_bytes",
        "input_token_bound",
        "output_token_bound",
        "reserved_nano_usd",
        "event_sequence",
    }
)
BUDGET_LEDGER_ENVELOPE_FIELDS = frozenset(
    {
        "schema_version",
        "sequence",
        "recorded_at_utc",
        "previous_event_sha256",
        "event",
        "committed_nano_usd",
        "held_nano_usd",
        "gross_exposure_nano_usd",
        "remaining_authority_nano_usd",
        "event_sha256",
    }
)
BUDGET_LEDGER_INITIAL_FIELDS = frozenset(
    {
        "ceiling_nano_usd",
        "ceiling_usd",
        "pricing_basis",
        "pricing_nano_usd_per_token",
        "input_token_reservation_per_call",
        "output_token_reservation_per_call",
        "maximum_provider_request_utf8_bytes",
        "stage4_successful_input_token_bound",
    }
)
BUDGET_LEDGER_SETTLED_FIELDS = frozenset(
    {
        "reservation_id",
        "phase",
        "model_id",
        "call_stem",
        "request_sha256",
        "input_tokens",
        "output_tokens",
        "settled_nano_usd",
        "released_nano_usd",
        "disposition",
    }
)
BUDGET_LEDGER_FORFEITED_FIELDS = BUDGET_LEDGER_SETTLED_FIELDS - frozenset(
    {"input_tokens", "output_tokens"}
)
PROMPT_COMMITMENT_DOCUMENT_FIELDS = frozenset(
    {
        "schema_version",
        "schedule_hash",
        "batch_id",
        "method",
        "call_count",
        "contains_prompt_or_request_bodies",
        "binds_all_potential_provider_requests",
        "minimum_request_utf8_bytes",
        "maximum_request_utf8_bytes",
        "total_request_utf8_bytes",
        "all_execute_maximum_cost_nano_usd",
        "all_execute_maximum_cost_usd",
        "required_minimum_nano_usd",
        "required_minimum_usd",
        "models",
        "calls",
        "commitments_sha256",
    }
)
PROMPT_COMMITMENT_MODEL_FIELDS = frozenset(
    {
        "model_id",
        "calls",
        "request_utf8_bytes",
        "cost_nano_usd",
        "cost_usd",
        "completion_safe_cost_nano_usd",
        "completion_safe_cost_usd",
    }
)
PROMPT_COMMITMENT_ROW_FIELDS = frozenset(
    {
        "call_index",
        "sequence_index",
        "scheduled_run_id",
        "pair_id",
        "model_id",
        "role_index",
        "role",
        "prompt_sha256",
        "canonical_request_sha256",
        "canonical_request_utf8_bytes",
    }
)
PIPELINE_ROLE_NAMES = ("planner", "retriever", "transformer", "actuator")
PROVIDER_REQUEST_MAXIMUM_BYTES = 32_768
RAW_REQUEST_MAXIMUM_BYTES = 256 * 1024
RAW_RESULT_MAXIMUM_BYTES = 16 * 1024 * 1024
# The frozen Stage 4 defense is local-only, so replay never emits or validates an
# artifact signature.  These public, deterministic bytes merely satisfy the
# runner's live-backend constructor guard; the frozen key ID still binds run IDs.
REPLAY_NONSECRET_SIGNING_BYTES = hashlib.sha256(
    b"stage4-provider-free-local-only-trace-replay-v1"
).digest()

HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
SAFE_ATTESTATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/()\-]{0,127}")
RAW_STEM = re.compile(r"call-[0-9]{6}-[0-9a-f]{12}")
FORBIDDEN_PUBLIC_BYTES = (
    re.compile(rb"sk-(?:proj-)?[A-Za-z0-9_-]{12,}", re.IGNORECASE),
    re.compile(rb"bearer[ \t:-]+[A-Za-z0-9._~-]{12,}", re.IGNORECASE),
    re.compile(
        rb'"(?:api_key|authorization_header|credential_material|key_material|private_key|secret_value)"\s*:',
        re.IGNORECASE,
    ),
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


class ReleaseBuildError(RuntimeError):
    """Stable redaction-safe release construction failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ReleaseBuildError(code)


def _read_source_bytes(path: Path, *, code: str) -> tuple[Path, bytes]:
    """Read one regular source file without following links or trusting bytecode."""

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseBuildError(code) from exc
    try:
        before = os.fstat(descriptor)
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and 0 < before.st_size <= 16 * 1024 * 1024,
            code,
        )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        _require(
            (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ),
            code,
        )
        raw = b"".join(chunks)
        _require(len(raw) == before.st_size, code)
        return path.resolve(strict=True), raw
    finally:
        os.close(descriptor)


def _load_source_bytes_module(
    name: str,
    path: Path,
    *,
    package: str | None = None,
    expected_sha256: str | None = None,
    code: str,
) -> ModuleType:
    """Execute exactly the source bytes checked here, never a cached ``.pyc``."""

    resolved, raw = _read_source_bytes(path, code=code)
    if expected_sha256 is not None:
        _require(
            HEX_SHA256.fullmatch(expected_sha256) is not None
            and hashlib.sha256(raw).hexdigest() == expected_sha256,
            code,
        )
    try:
        compiled = compile(raw, str(resolved), "exec", dont_inherit=True)
    except (SyntaxError, ValueError, TypeError) as exc:
        raise ReleaseBuildError(code) from exc
    module = ModuleType(name)
    module.__file__ = str(resolved)
    module.__package__ = package if package is not None else name.rpartition(".")[0]
    module.__loader__ = None
    module.__cached__ = None
    module.__spec__ = importlib.machinery.ModuleSpec(
        name,
        loader=None,
        origin=str(resolved),
    )
    sentinel = object()
    prior = sys.modules.get(name, sentinel)
    sys.modules[name] = module
    try:
        exec(compiled, module.__dict__)  # noqa: S102 - frozen, hash-checked source
    except BaseException:
        if prior is sentinel:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = prior  # type: ignore[assignment]
        raise
    return module


def _load_public_verifier() -> ModuleType:
    path = Path(__file__).with_name("verify_stage4_release.py")
    try:
        return _load_source_bytes_module(
            "_stage4_release_verifier",
            path,
            code="public_verifier_unloadable",
        )
    except Exception as exc:  # noqa: BLE001 - stable loader boundary
        if isinstance(exc, ReleaseBuildError):
            raise
        raise ReleaseBuildError("public_verifier_unloadable") from exc


PUBLIC_VERIFIER = _load_public_verifier()


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseBuildError("private_json_duplicate_key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ReleaseBuildError("private_json_nonfinite_number")


def _parse_json_bytes(raw: bytes, code: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_duplicate_rejecting_object,
            parse_float=Decimal,
            parse_constant=_reject_json_constant,
        )
    except ReleaseBuildError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseBuildError(code) from exc
    _require(type(value) is dict, code)
    return value


def _parse_json_bytes_with_float(raw: bytes, code: str) -> dict[str, Any]:
    """Parse trace JSON with float round-tripping for its semantic commitment."""

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=_reject_json_constant,
        )
    except ReleaseBuildError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseBuildError(code) from exc
    _require(type(value) is dict, code)
    return value


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _nano_usd_string(value: int) -> str:
    whole, fractional = divmod(value, 1_000_000_000)
    return f"{whole}.{fractional:09d}"


def _expect_object(value: object, fields: frozenset[str], code: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == fields, code)
    assert type(value) is dict
    return value


def _expect_str(value: object, code: str, *, expected: str | None = None) -> str:
    _require(type(value) is str and bool(value) and value == value.strip(), code)
    assert type(value) is str
    if expected is not None:
        _require(value == expected, code)
    return value


def _expect_int(
    value: object,
    code: str,
    *,
    expected: int | None = None,
    minimum: int | None = None,
) -> int:
    _require(type(value) is int, code)
    assert type(value) is int
    if expected is not None:
        _require(value == expected, code)
    if minimum is not None:
        _require(value >= minimum, code)
    return value


def _expect_bool(value: object, code: str, *, expected: bool | None = None) -> bool:
    _require(type(value) is bool, code)
    assert type(value) is bool
    if expected is not None:
        _require(value is expected, code)
    return value


def _expect_sha256(value: object, code: str) -> str:
    digest = _expect_str(value, code)
    _require(HEX_SHA256.fullmatch(digest) is not None, code)
    return digest


def _expect_optional_str(value: object, code: str) -> str | None:
    _require(
        value is None
        or (type(value) is str and bool(value) and value == value.strip()),
        code,
    )
    return value if isinstance(value, str) else None


def _expect_nonnegative_finite_float(value: object, code: str) -> float:
    _require(type(value) is float and math.isfinite(value) and value >= 0.0, code)
    assert type(value) is float
    return value


def _expect_utc_timestamp(value: object, code: str) -> datetime:
    timestamp = _expect_str(value, code)
    _require(timestamp.endswith("+00:00"), code)
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise ReleaseBuildError(code) from exc
    _require(parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0), code)
    return parsed.astimezone(timezone.utc)


def _safe_relative_path(value: object, code: str) -> str:
    relative = _expect_str(value, code)
    candidate = PurePosixPath(relative)
    _require(
        not candidate.is_absolute()
        and candidate.as_posix() == relative
        and all(
            part not in {"", ".", ".."}
            and len(part.encode("utf-8")) <= 255
            and not any(ord(character) < 32 or ord(character) == 127 for character in part)
            for part in candidate.parts
        ),
        code,
    )
    return relative


def _private_mode_is_safe(info: os.stat_result, *, directory: bool) -> bool:
    mode = stat.S_IMODE(info.st_mode)
    kind_ok = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    owner_access = (mode & 0o500) == 0o500 if directory else (mode & 0o400) == 0o400
    no_execute = True if directory else mode & 0o111 == 0
    return kind_ok and owner_access and no_execute and mode & 0o077 == 0


def _read_private_bytes(
    path: Path,
    code: str,
    *,
    expected_size: int | None = None,
    maximum_size: int | None = None,
) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseBuildError(code) from exc
    try:
        before = os.fstat(descriptor)
        _require(
            _private_mode_is_safe(before, directory=False) and before.st_nlink == 1,
            code,
        )
        if expected_size is not None:
            _require(before.st_size == expected_size, code)
        if maximum_size is not None:
            _require(before.st_size <= maximum_size, code)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        _require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            code,
        )
        raw = b"".join(chunks)
        _require(len(raw) == before.st_size, code)
        return raw
    finally:
        os.close(descriptor)


def _hash_private_file(path: Path, code: str) -> tuple[str, int]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseBuildError(code) from exc
    digest = hashlib.sha256()
    size = 0
    try:
        before = os.fstat(descriptor)
        _require(
            _private_mode_is_safe(before, directory=False) and before.st_nlink == 1,
            code,
        )
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
        _require(
            size == before.st_size
            and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            code,
        )
        return digest.hexdigest(), size
    finally:
        os.close(descriptor)


def _enumerate_private_tree(root: Path) -> tuple[set[str], set[str]]:
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise ReleaseBuildError("private_archive_unreadable") from exc
    _require(
        _private_mode_is_safe(root_info, directory=True) and not stat.S_ISLNK(root_info.st_mode),
        "private_archive_permissions_unsafe",
    )
    files: set[str] = set()
    directories: set[str] = set()
    try:
        entries = list(root.rglob("*"))
    except OSError as exc:
        raise ReleaseBuildError("private_archive_unreadable") from exc
    for path in entries:
        relative = path.relative_to(root).as_posix()
        _safe_relative_path(relative, "private_archive_path_unsafe")
        try:
            info = path.lstat()
        except OSError as exc:
            raise ReleaseBuildError("private_archive_unreadable") from exc
        _require(not stat.S_ISLNK(info.st_mode), "private_archive_symlink_forbidden")
        if stat.S_ISDIR(info.st_mode):
            _require(
                _private_mode_is_safe(info, directory=True),
                "private_archive_permissions_unsafe",
            )
            directories.add(relative)
        elif stat.S_ISREG(info.st_mode):
            _require(
                _private_mode_is_safe(info, directory=False) and info.st_nlink == 1,
                "private_archive_permissions_unsafe",
            )
            files.add(relative)
        else:
            raise ReleaseBuildError("private_archive_special_file_forbidden")
    return files, directories


def _validate_archive_manifest(
    archive: Path,
) -> tuple[dict[str, Any], dict[str, tuple[str, int]], set[str]]:
    files, directories = _enumerate_private_tree(archive)
    completion_markers = sorted(
        path for path in files if PurePosixPath(path).name == COMPLETE_MARKER_NAME
    )
    incomplete_markers = sorted(
        path for path in files if PurePosixPath(path).name == INCOMPLETE_MARKER_NAME
    )
    _require(completion_markers == [COMPLETE_MARKER_NAME], "completion_marker_count_invalid")
    _require(not incomplete_markers, "incomplete_marker_present")
    _require(ARCHIVE_MANIFEST_NAME in files, "private_archive_manifest_missing")
    _require(MANDATORY_PRIVATE_FILES <= files, "private_archive_required_file_missing")
    allowed_top_level = (
        MANDATORY_PRIVATE_FILES | set(ARCHIVE_EXCLUSIONS) | {"traces.jsonl"}
    )
    _require(
        all(
            relative in allowed_top_level or relative.startswith("raw/")
            for relative in files
        ),
        "private_archive_unexpected_file",
    )
    expected_directories = {"raw"} | {
        f"raw/{model_id}" for model_id in PUBLIC_VERIFIER.MODELS
    }
    _require(
        directories == expected_directories,
        "private_archive_directory_set_mismatch",
    )

    manifest_raw = _read_private_bytes(
        archive / ARCHIVE_MANIFEST_NAME,
        "private_archive_manifest_unreadable",
        maximum_size=32 * 1024 * 1024,
    )
    manifest = _expect_object(
        _parse_json_bytes(manifest_raw, "private_archive_manifest_invalid"),
        ARCHIVE_FIELDS,
        "private_archive_manifest_schema_mismatch",
    )
    _expect_str(
        manifest["schema_version"],
        "private_archive_manifest_version_mismatch",
        expected=ARCHIVE_SCHEMA_VERSION,
    )
    _expect_bool(
        manifest["contains_raw_private_provider_material"],
        "private_archive_raw_material_flag_invalid",
        expected=True,
    )
    _expect_bool(
        manifest["contains_credential_or_provenance_key_material"],
        "private_archive_secret_material_flag_invalid",
        expected=False,
    )
    attestation = _expect_str(
        manifest["immutable_archive_attestation"],
        "private_archive_attestation_invalid",
    )
    _require(
        SAFE_ATTESTATION.fullmatch(attestation) is not None,
        "private_archive_attestation_invalid",
    )
    _require(
        _expect_sha256(
            manifest["immutable_archive_attestation_sha256"],
            "private_archive_attestation_hash_invalid",
        )
        == hashlib.sha256(attestation.encode("utf-8")).hexdigest(),
        "private_archive_attestation_hash_mismatch",
    )
    _expect_str(
        manifest["completion_marker_policy"],
        "private_archive_completion_policy_mismatch",
        expected="execution_complete_created_only_after_archive_commitment",
    )
    _require(
        type(manifest["coverage_exclusions"]) is list
        and manifest["coverage_exclusions"] == ARCHIVE_EXCLUSIONS,
        "private_archive_exclusions_mismatch",
    )
    rows = manifest["files"]
    _require(type(rows) is list, "private_archive_files_invalid")
    assert type(rows) is list
    _expect_int(
        manifest["file_count"],
        "private_archive_file_count_invalid",
        expected=len(rows),
    )
    _require(len(rows) <= 7_000, "private_archive_file_count_invalid")

    expected_by_path: dict[str, tuple[str, int]] = {}
    ordered_paths: list[str] = []
    for value in rows:
        row = _expect_object(
            value, ARCHIVE_FILE_FIELDS, "private_archive_file_entry_schema_mismatch"
        )
        relative = _safe_relative_path(row["path"], "private_archive_file_path_invalid")
        _require(relative not in expected_by_path, "private_archive_file_path_duplicate")
        digest = _expect_sha256(row["sha256"], "private_archive_file_hash_invalid")
        size = _expect_int(row["bytes"], "private_archive_file_size_invalid", minimum=0)
        expected_by_path[relative] = (digest, size)
        ordered_paths.append(relative)
    _require(ordered_paths == sorted(ordered_paths), "private_archive_file_order_invalid")
    _require(
        set(expected_by_path) == files - set(ARCHIVE_EXCLUSIONS),
        "private_archive_coverage_mismatch",
    )
    _require(
        not (set(ARCHIVE_EXCLUSIONS) & set(expected_by_path)),
        "private_archive_exclusion_covered",
    )
    for relative, (expected_digest, expected_size) in expected_by_path.items():
        actual_digest, actual_size = _hash_private_file(
            archive / relative, "private_archive_file_unreadable"
        )
        _require(
            actual_digest == expected_digest and actual_size == expected_size,
            "private_archive_file_commitment_mismatch",
        )

    supplied_commitment = _expect_sha256(
        manifest["archive_commitment_sha256"],
        "private_archive_commitment_invalid",
    )
    unhashed = {
        key: value for key, value in manifest.items() if key != "archive_commitment_sha256"
    }
    _require(
        supplied_commitment == _semantic_sha256(unhashed),
        "private_archive_commitment_mismatch",
    )
    _require(
        "raw" in directories and any(path.startswith("raw/") for path in files),
        "private_archive_raw_evidence_missing",
    )
    return manifest, expected_by_path, files


def _read_private_json(
    archive: Path,
    relative: str,
    code: str,
    *,
    maximum_size: int,
) -> dict[str, Any]:
    return _parse_json_bytes(
        _read_private_bytes(
            archive / relative,
            code,
            maximum_size=maximum_size,
        ),
        code,
    )


def _read_private_json_with_float(
    archive: Path,
    relative: str,
    code: str,
    *,
    maximum_size: int,
) -> dict[str, Any]:
    return _parse_json_bytes_with_float(
        _read_private_bytes(
            archive / relative,
            code,
            maximum_size=maximum_size,
        ),
        code,
    )


def _read_private_jsonl(
    archive: Path,
    relative: str,
    code: str,
    *,
    maximum_size: int,
) -> list[dict[str, Any]]:
    raw = _read_private_bytes(
        archive / relative,
        code,
        maximum_size=maximum_size,
    )
    _require(bool(raw) and raw.endswith(b"\n"), code)
    rows: list[dict[str, Any]] = []
    for line in raw.splitlines():
        _require(bool(line.strip()), code)
        rows.append(_parse_json_bytes(line, code))
    return rows


def _read_private_trace_jsonl(
    archive: Path,
    relative: str,
    code: str,
    *,
    maximum_size: int,
) -> list[dict[str, Any]]:
    raw = _read_private_bytes(
        archive / relative,
        code,
        maximum_size=maximum_size,
    )
    _require(bool(raw) and raw.endswith(b"\n"), code)
    rows: list[dict[str, Any]] = []
    for line in raw.splitlines():
        _require(bool(line.strip()), code)
        rows.append(_parse_json_bytes_with_float(line, code))
    return rows


def _read_regular_bytes(path: Path, code: str, *, maximum_size: int) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ReleaseBuildError(code) from exc
    _require(
        stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
        code,
    )
    _require(info.st_size <= maximum_size, code)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ReleaseBuildError(code) from exc
    _require(len(raw) == info.st_size, code)
    return raw


def _file_sha256(path: Path, code: str, *, maximum_size: int) -> str:
    return hashlib.sha256(
        _read_regular_bytes(path, code, maximum_size=maximum_size)
    ).hexdigest()


def _expected_production_backend_configuration(
    freeze: Mapping[str, Any],
    *,
    model_id: str,
) -> dict[str, object]:
    provider = freeze.get("provider_contract")
    prompt = freeze.get("prompt_contract")
    _require(
        type(provider) is dict and type(prompt) is dict,
        "freeze_backend_contract_invalid",
    )
    assert type(provider) is dict and type(prompt) is dict
    request = provider.get("request")
    _require(type(request) is dict, "freeze_backend_contract_invalid")
    assert type(request) is dict
    return {
        "provider": provider.get("provider"),
        "api": provider.get("api"),
        "base_url": provider.get("base_url"),
        "ambient_endpoint_overrides_allowed": False,
        "ambient_custom_headers_allowed": False,
        "http_follow_redirects": request.get("http_follow_redirects"),
        "http_trust_env": request.get("http_trust_env"),
        "requested_model": model_id,
        "sdk_version": provider.get("sdk_version"),
        "pinned_sdk_version": provider.get("sdk_version"),
        "prompt_version": prompt.get("prompt_version"),
        "decision_schema_version": prompt.get("decision_schema_version"),
        "instructions_sha256": prompt.get("instructions_sha256"),
        "decision_schema_sha256": prompt.get("decision_schema_sha256"),
        "structured_output": "json_schema_strict",
        "store": request.get("store"),
        "service_tier": request.get("service_tier"),
        "reasoning_effort": request.get("reasoning_effort"),
        "max_output_tokens": request.get("max_output_tokens"),
        "timeout_seconds": float(request.get("timeout_seconds")),
        "temperature": "provider_default_unset",
        "top_p": "provider_default_unset",
        "tools": "none",
        "max_retries": request.get("sdk_max_retries"),
        "seed_supported": False,
        "hard_budget_enforced": True,
        "budget_phase": STAGE4_BUDGET_PHASE,
    }


def _validate_production_backend_configuration_hash(
    freeze: Mapping[str, Any],
    *,
    model_id: str,
    supplied_sha256: object,
) -> None:
    supplied = _expect_sha256(
        supplied_sha256,
        "execution_commitment_artifact_hash_invalid",
    )
    expected_configuration = _expected_production_backend_configuration(
        freeze,
        model_id=model_id,
    )
    _require(
        supplied == _semantic_sha256(expected_configuration),
        "execution_commitment_backend_configuration_mismatch",
    )


def _validate_execution_start_and_authority(
    archive: Path,
    *,
    covered_files: Mapping[str, tuple[str, int]],
    freeze: Mapping[str, Any],
    schedule: Mapping[str, Any],
    freeze_tag_target: str,
    freeze_file_sha256: str,
) -> str:
    storage = freeze.get("storage_authority")
    budget = freeze.get("budget_authority")
    credential = freeze.get("credential_boundary")
    provenance = freeze.get("provenance_boundary")
    runtime = freeze.get("runtime_binding")
    _require(
        all(
            type(value) is dict
            for value in (storage, budget, credential, provenance, runtime)
        ),
        "freeze_execution_authority_contract_invalid",
    )
    assert type(storage) is dict
    assert type(budget) is dict
    assert type(credential) is dict
    assert type(provenance) is dict
    assert type(runtime) is dict

    encrypted_sha = hashlib.sha256(
        str(storage.get("encrypted_at_rest_attestation")).encode("utf-8")
    ).hexdigest()
    immutable_sha = hashlib.sha256(
        str(storage.get("immutable_archive_attestation")).encode("utf-8")
    ).hexdigest()
    started = _expect_object(
        _read_private_json(
            archive,
            "execution_started.json",
            "execution_started_invalid",
            maximum_size=64 * 1024,
        ),
        EXECUTION_STARTED_FIELDS,
        "execution_started_schema_mismatch",
    )
    expected_started = {
        "schema_version": EXECUTION_SCHEMA_VERSION,
        "status": "INCOMPLETE",
        "freeze_commit_sha": freeze_tag_target,
        "freeze_manifest_sha256": freeze_file_sha256,
        "schedule_hash": schedule.get("schedule_hash"),
        "batch_id": runtime.get("batch_id"),
        "provider_calls_at_creation": 0,
        "injected_test_backend": False,
        "encrypted_storage_attestation_sha256": encrypted_sha,
        "immutable_archive_attestation_sha256": immutable_sha,
    }
    _require(
        all(
            type(started.get(name)) is type(value) and started.get(name) == value
            for name, value in expected_started.items()
        ),
        "execution_started_production_binding_mismatch",
    )

    authority = _expect_object(
        _read_private_json(
            archive,
            ARCHIVED_AUTHORITY_RECEIPT_NAME,
            "authority_receipt_invalid",
            maximum_size=128 * 1024,
        ),
        AUTHORITY_FIELDS,
        "authority_receipt_schema_mismatch",
    )
    _expect_str(authority.get("created_at_utc"), "authority_receipt_timestamp_invalid")
    expected_authority = {
        "schema_version": AUTHORITY_SCHEMA_VERSION,
        "scope": "one_exact_stage4_v0.4_confirmatory_batch",
        "freeze_commit_sha": freeze_tag_target,
        "freeze_manifest_sha256": freeze_file_sha256,
        "schedule_hash": schedule.get("schedule_hash"),
        "batch_id": runtime.get("batch_id"),
        "authorized_ceiling_nano_usd": budget.get("authorized_ceiling_nano_usd"),
        "credential_id": credential.get("credential_id"),
        "credential_fingerprint_sha256": credential.get(
            "credential_fingerprint_sha256"
        ),
        "provenance_key_id": provenance.get("key_id"),
        "provenance_key_fingerprint_sha256": provenance.get(
            "key_fingerprint_sha256"
        ),
        "output_path_sha256": hashlib.sha256(
            str(storage.get("execution_output_path")).encode("utf-8")
        ).hexdigest(),
        "encrypted_storage_attestation_sha256": encrypted_sha,
        "immutable_archive_attestation_sha256": immutable_sha,
        "rerun_under_same_authority": False,
        "contains_secret_material": False,
    }
    _require(
        all(
            type(authority.get(name)) is type(value) and authority.get(name) == value
            for name, value in expected_authority.items()
        ),
        "authority_receipt_freeze_binding_mismatch",
    )
    authority_sha = covered_files[ARCHIVED_AUTHORITY_RECEIPT_NAME][0]
    _require(
        authority_sha
        == _file_sha256(
            archive / ARCHIVED_AUTHORITY_RECEIPT_NAME,
            "authority_receipt_invalid",
            maximum_size=128 * 1024,
        ),
        "authority_receipt_archive_hash_mismatch",
    )
    return authority_sha


def _validate_complete_marker_and_source(
    archive: Path,
    archive_manifest: Mapping[str, Any],
    covered_files: Mapping[str, tuple[str, int]],
    *,
    schedule: Mapping[str, Any],
    freeze: Mapping[str, Any],
    freeze_tag_target: str,
    canonical_binding_digest: str,
    schedule_path: Path,
    freeze_path: Path,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    storage = freeze.get("storage_authority")
    _require(type(storage) is dict, "freeze_storage_contract_invalid")
    assert type(storage) is dict
    frozen_attestation = _expect_str(
        storage.get("immutable_archive_attestation"),
        "freeze_archive_attestation_invalid",
    )
    _require(
        archive_manifest["immutable_archive_attestation"] == frozen_attestation
        and archive_manifest["immutable_archive_attestation_sha256"]
        == hashlib.sha256(frozen_attestation.encode("utf-8")).hexdigest(),
        "private_archive_freeze_attestation_mismatch",
    )
    complete = _expect_object(
        _read_private_json(
            archive,
            COMPLETE_MARKER_NAME,
            "completion_marker_invalid",
            maximum_size=64 * 1024,
        ),
        COMPLETE_FIELDS,
        "completion_marker_schema_mismatch",
    )
    _expect_str(
        complete["schema_version"],
        "completion_marker_version_mismatch",
        expected=EXECUTION_SCHEMA_VERSION,
    )
    _expect_str(complete["status"], "completion_marker_status_invalid", expected="COMPLETE")
    decision_value = _expect_str(complete["decision"], "completion_decision_invalid")
    _require(decision_value in {"GO", "NO_GO"}, "completion_decision_provisional")
    _expect_int(
        complete["scheduled_run_count"],
        "completion_run_count_invalid",
        expected=int(PUBLIC_VERIFIER.EXPECTED_RUN_COUNT),
    )
    provider_calls = _expect_int(
        complete["provider_call_count"],
        "completion_provider_call_count_invalid",
        minimum=int(PUBLIC_VERIFIER.EXPECTED_RUN_COUNT),
    )
    _require(
        provider_calls <= int(PUBLIC_VERIFIER.EXPECTED_MAXIMUM_AGENT_CALLS),
        "completion_provider_call_count_invalid",
    )
    for field_name in (
        "outcomes_sha256",
        "decision_sha256",
        "private_archive_manifest_sha256",
        "private_release_source_sha256",
        "terminal_event_sha256",
    ):
        _expect_sha256(complete[field_name], "completion_hash_invalid")
    manifest_file_sha = hashlib.sha256(
        _read_private_bytes(
            archive / ARCHIVE_MANIFEST_NAME,
            "private_archive_manifest_unreadable",
            maximum_size=32 * 1024 * 1024,
        )
    ).hexdigest()
    _require(
        complete["private_archive_manifest_sha256"] == manifest_file_sha,
        "completion_archive_manifest_hash_mismatch",
    )
    _require(
        complete["outcomes_sha256"] == covered_files["outcomes.json"][0]
        and complete["decision_sha256"] == covered_files["decision.json"][0]
        and complete["private_release_source_sha256"]
        == covered_files["private_release_source.json"][0],
        "completion_file_hash_mismatch",
    )

    source = _expect_object(
        _read_private_json(
            archive,
            "private_release_source.json",
            "private_release_source_invalid",
            maximum_size=128 * 1024,
        ),
        PRIVATE_RELEASE_SOURCE_FIELDS,
        "private_release_source_schema_mismatch",
    )
    _expect_str(
        source["schema_version"],
        "private_release_source_version_mismatch",
        expected=PRIVATE_RELEASE_SOURCE_SCHEMA_VERSION,
    )
    _expect_bool(source["private_only"], "private_release_source_flag_invalid", expected=True)
    _expect_bool(
        source["public_release_emitted"],
        "private_release_source_flag_invalid",
        expected=False,
    )
    freeze_commit = _expect_str(source["freeze_commit_sha"], "freeze_commit_invalid")
    _require(GIT_OBJECT_ID.fullmatch(freeze_commit) is not None, "freeze_commit_invalid")
    _require(freeze_commit == freeze_tag_target, "private_release_freeze_tag_target_mismatch")
    for field_name in (
        "freeze_manifest_sha256",
        "schedule_file_sha256",
        "prompt_commitments_file_sha256",
        "run_bindings_sha256",
        "execution_commitments_sha256",
        "execution_commitments_file_sha256",
        "attempted_records_file_sha256",
        "budget_ledger_file_sha256",
        "outcomes_file_sha256",
        "decision_file_sha256",
    ):
        _expect_sha256(source[field_name], "private_release_source_hash_invalid")
    _require(
        source["traces_file_sha256"] is None
        or HEX_SHA256.fullmatch(str(source["traces_file_sha256"])) is not None,
        "private_release_source_hash_invalid",
    )
    _expect_str(
        source["schedule_hash"],
        "private_release_schedule_hash_mismatch",
        expected=str(schedule["schedule_hash"]),
    )
    _require(
        source["freeze_manifest_sha256"]
        == _file_sha256(freeze_path, "freeze_file_invalid", maximum_size=16 * 1024 * 1024),
        "private_release_freeze_hash_mismatch",
    )
    _require(
        source["schedule_file_sha256"]
        == _file_sha256(schedule_path, "schedule_file_invalid", maximum_size=32 * 1024 * 1024),
        "private_release_schedule_file_hash_mismatch",
    )
    prompt_path = schedule_path.with_name("stage4_prompt_commitments.json")
    _require(
        source["prompt_commitments_file_sha256"]
        == _file_sha256(
            prompt_path,
            "prompt_commitments_file_invalid",
            maximum_size=64 * 1024 * 1024,
        ),
        "private_release_prompt_commitments_hash_mismatch",
    )
    prompt_contract = freeze.get("prompt_contract")
    _require(type(prompt_contract) is dict, "freeze_prompt_contract_invalid")
    assert type(prompt_contract) is dict
    _require(
        source["prompt_commitments_file_sha256"]
        == prompt_contract.get("potential_request_commitments_file_sha256"),
        "private_release_prompt_freeze_mismatch",
    )
    runtime = freeze.get("runtime_binding")
    _require(type(runtime) is dict, "freeze_runtime_binding_invalid")
    assert type(runtime) is dict
    _require(
        source["run_bindings_sha256"]
        == canonical_binding_digest
        == runtime.get("runspec_mapping_sha256"),
        "private_release_runtime_binding_mismatch",
    )
    covered_links = {
        "execution_commitments_file_sha256": "execution_commitments.json",
        "attempted_records_file_sha256": "attempted_records.jsonl",
        "budget_ledger_file_sha256": "budget_ledger.jsonl",
        "outcomes_file_sha256": "outcomes.json",
        "decision_file_sha256": "decision.json",
    }
    for source_field, relative in covered_links.items():
        _require(
            source[source_field] == covered_files[relative][0],
            "private_release_covered_file_hash_mismatch",
        )
    traces_present = "traces.jsonl" in covered_files
    _require(
        (traces_present and source["traces_file_sha256"] == covered_files["traces.jsonl"][0])
        or (not traces_present and source["traces_file_sha256"] is None),
        "private_release_traces_presence_mismatch",
    )

    commitments = _expect_object(
        _read_private_json(
            archive,
            "execution_commitments.json",
            "execution_commitments_invalid",
            maximum_size=16 * 1024 * 1024,
        ),
        EXECUTION_COMMITMENT_FIELDS,
        "execution_commitments_schema_mismatch",
    )
    _expect_str(
        commitments.get("schema_version"),
        "execution_commitments_version_mismatch",
        expected=EXECUTION_COMMITMENT_SCHEMA_VERSION,
    )
    _require(
        _semantic_sha256(commitments) == source["execution_commitments_sha256"],
        "execution_commitments_semantic_hash_mismatch",
    )
    tracked = freeze.get("tracked_artifact_sha256")
    provenance = freeze.get("provenance_boundary")
    _require(
        type(tracked) is dict and type(provenance) is dict,
        "freeze_execution_commitment_source_invalid",
    )
    assert type(tracked) is dict and type(provenance) is dict
    _expect_str(
        commitments["run_bindings_sha256"],
        "execution_commitments_runtime_binding_mismatch",
        expected=canonical_binding_digest,
    )
    _expect_str(
        commitments["protocol_commit_sha"],
        "execution_commitments_protocol_commit_mismatch",
        expected=freeze_tag_target,
    )
    _expect_str(
        commitments["protocol_sha256"],
        "execution_commitments_protocol_hash_mismatch",
        expected=str(tracked.get("protocols/v0.4-stage4-confirmatory.md")),
    )
    _expect_str(
        commitments["provenance_key_id"],
        "execution_commitments_provenance_mismatch",
        expected=str(provenance.get("key_id")),
    )
    _expect_str(
        commitments["backend_name"],
        "execution_commitments_backend_mismatch",
        expected="openai_responses",
    )
    artifacts = commitments["run_artifacts"]
    _require(
        type(artifacts) is list
        and len(artifacts) == int(PUBLIC_VERIFIER.EXPECTED_RUN_COUNT),
        "execution_commitment_artifact_count_mismatch",
    )
    assert type(artifacts) is list
    scheduled_rows = schedule["runs"]
    assert type(scheduled_rows) is list
    for artifact, scheduled in zip(artifacts, scheduled_rows, strict=True):
        artifact = _expect_object(
            artifact,
            RUN_ARTIFACT_FIELDS,
            "execution_commitment_artifact_schema_mismatch",
        )
        _expect_str(
            artifact["scheduled_run_id"],
            "execution_commitment_artifact_run_mismatch",
            expected=str(scheduled["run_id"]),
        )
        _expect_sha256(
            artifact["component_hashes_sha256"],
            "execution_commitment_artifact_hash_invalid",
        )
        _validate_production_backend_configuration_hash(
            freeze,
            model_id=str(scheduled["model_id"]),
            supplied_sha256=artifact["backend_configuration_sha256"],
        )

    outcomes = _expect_object(
        _read_private_json(
            archive,
            "outcomes.json",
            "private_outcomes_invalid",
            maximum_size=64 * 1024 * 1024,
        ),
        PRIVATE_OUTCOMES_DOCUMENT_FIELDS,
        "private_outcomes_document_schema_mismatch",
    )
    _expect_str(
        outcomes["schema_version"],
        "private_outcomes_version_mismatch",
        expected=PRIVATE_OUTCOME_SCHEMA_VERSION,
    )
    _expect_str(
        outcomes["schedule_hash"],
        "private_outcomes_schedule_hash_mismatch",
        expected=str(schedule["schedule_hash"]),
    )
    _require(
        outcomes["run_bindings_sha256"] == source["run_bindings_sha256"]
        and outcomes["execution_commitments_sha256"]
        == source["execution_commitments_sha256"],
        "private_outcomes_commitment_mismatch",
    )

    decision = _expect_object(
        _read_private_json(
            archive,
            "decision.json",
            "private_decision_invalid",
            maximum_size=32 * 1024 * 1024,
        ),
        PRIVATE_DECISION_FIELDS,
        "private_decision_schema_mismatch",
    )
    _expect_str(
        decision["schema_version"],
        "private_decision_version_mismatch",
        expected=PRIVATE_DECISION_SCHEMA_VERSION,
    )
    _expect_str(
        decision["schedule_hash"],
        "private_decision_schedule_hash_mismatch",
        expected=str(schedule["schedule_hash"]),
    )
    _expect_str(
        decision["decision"],
        "private_decision_mismatch",
        expected=decision_value,
    )
    _require(
        not any("provisional" in key.lower() for key in decision),
        "private_decision_provisional",
    )
    return complete, source, outcomes, decision, commitments


def _resolve_freeze_tag_target(freeze: Mapping[str, Any], freeze_path: Path) -> str:
    repository = freeze.get("repository_binding")
    _require(type(repository) is dict, "freeze_repository_binding_invalid")
    assert type(repository) is dict
    tag = _expect_str(
        repository.get("planned_annotated_tag"),
        "freeze_repository_tag_invalid",
    )
    repo_root = freeze_path.parent.parent
    try:
        raw = PUBLIC_VERIFIER._git_bytes(  # noqa: SLF001
            repo_root,
            ("rev-parse", f"refs/tags/{tag}^{{commit}}"),
            "freeze_tag_target_invalid",
        )
        target = PUBLIC_VERIFIER._single_utf8_line(  # noqa: SLF001
            raw, "freeze_tag_target_invalid"
        )
    except Exception as exc:  # noqa: BLE001 - normalize verifier internals
        raise ReleaseBuildError("freeze_tag_target_invalid") from exc
    _require(GIT_OBJECT_ID.fullmatch(target) is not None, "freeze_tag_target_invalid")
    return target


def _validate_execution_events(
    archive: Path,
    *,
    complete: Mapping[str, Any],
    schedule: Mapping[str, Any],
    source_sha256: str,
    authority_receipt_sha256: str,
    freeze: Mapping[str, Any],
    freeze_manifest_sha256: str,
    freeze_tag_target: str,
) -> None:
    events = _read_private_jsonl(
        archive,
        "execution_events.jsonl",
        "execution_events_invalid",
        maximum_size=64 * 1024 * 1024,
    )
    previous: str | None = None
    seen_hashes: set[str] = set()
    kinds: list[str] = []
    for sequence, event in enumerate(events, start=1):
        _require(type(event) is dict, "execution_event_schema_mismatch")
        _expect_str(
            event.get("schema_version"),
            "execution_event_version_mismatch",
            expected=EXECUTION_EVENT_SCHEMA_VERSION,
        )
        _expect_int(
            event.get("sequence"),
            "execution_event_sequence_invalid",
            expected=sequence,
        )
        _expect_utc_timestamp(
            event.get("recorded_at_utc"), "execution_event_timestamp_invalid"
        )
        _require(
            event.get("previous_event_sha256") == previous,
            "execution_event_chain_invalid",
        )
        kind = _expect_str(event.get("event"), "execution_event_kind_invalid")
        supplied = _expect_sha256(
            event.get("event_sha256"), "execution_event_hash_invalid"
        )
        unhashed = {key: value for key, value in event.items() if key != "event_sha256"}
        _require(
            supplied == _semantic_sha256(unhashed) and supplied not in seen_hashes,
            "execution_event_hash_invalid",
        )
        previous = supplied
        seen_hashes.add(supplied)
        kinds.append(kind)
    _require(bool(events), "execution_events_empty")
    storage = freeze.get("storage_authority")
    budget = freeze.get("budget_authority")
    _require(
        type(storage) is dict and type(budget) is dict,
        "freeze_execution_event_contract_invalid",
    )
    assert type(storage) is dict and type(budget) is dict
    start = events[0]
    expected_start_payload = {
        "freeze_commit_sha": freeze_tag_target,
        "freeze_manifest_sha256": freeze_manifest_sha256,
        "schedule_hash": schedule.get("schedule_hash"),
        "expected_scheduled_runs": int(PUBLIC_VERIFIER.EXPECTED_RUN_COUNT),
        "authorized_ceiling_nano_usd": budget.get("authorized_ceiling_nano_usd"),
        "encrypted_storage_attestation_sha256": hashlib.sha256(
            str(storage.get("encrypted_at_rest_attestation")).encode("utf-8")
        ).hexdigest(),
        "immutable_archive_attestation_sha256": hashlib.sha256(
            str(storage.get("immutable_archive_attestation")).encode("utf-8")
        ).hexdigest(),
        "injected_test_backend": False,
    }
    for name, value in expected_start_payload.items():
        _require(
            type(start.get(name)) is type(value) and start.get(name) == value,
            "execution_start_event_production_binding_mismatch",
        )
    event_envelope = {
        "schema_version",
        "sequence",
        "recorded_at_utc",
        "previous_event_sha256",
        "event",
        "event_sha256",
    }
    _require(
        set(start) == event_envelope | set(expected_start_payload),
        "execution_start_event_schema_mismatch",
    )
    _require(
        start.get("injected_test_backend") is False,
        "execution_start_event_test_backend_forbidden",
    )
    authority_event = events[1]
    _require(
        set(authority_event) == event_envelope | {"authority_receipt_sha256"}
        and
        authority_event.get("authority_receipt_sha256")
        == authority_receipt_sha256,
        "execution_authority_event_hash_mismatch",
    )
    ledger_rows = _read_private_jsonl(
        archive,
        "budget_ledger.jsonl",
        "budget_ledger_invalid",
        maximum_size=128 * 1024 * 1024,
    )
    _require(bool(ledger_rows), "budget_ledger_initialization_invalid")
    ledger_initial_sha = _expect_sha256(
        ledger_rows[0].get("event_sha256"),
        "budget_ledger_initialization_invalid",
    )
    ledger_file_sha = hashlib.sha256(
        _read_private_bytes(
            archive / "budget_ledger.jsonl",
            "budget_ledger_invalid",
            maximum_size=128 * 1024 * 1024,
        )
    ).hexdigest()
    commitments = _read_private_json(
        archive,
        "execution_commitments.json",
        "execution_commitments_invalid",
        maximum_size=16 * 1024 * 1024,
    )
    commitments_sha = _semantic_sha256(commitments)
    attempted = _read_private_jsonl(
        archive,
        "attempted_records.jsonl",
        "attempted_records_invalid",
        maximum_size=256 * 1024 * 1024,
    )
    scheduled_rows = schedule["runs"]
    model_ids = schedule.get("model_ids")
    _require(
        type(scheduled_rows) is list
        and type(model_ids) is list
        and len(attempted) == len(scheduled_rows),
        "execution_event_lifecycle_mismatch",
    )
    assert type(scheduled_rows) is list and type(model_ids) is list

    expected: list[tuple[str, dict[str, object]]] = [
        ("execution_started_incomplete", expected_start_payload),
        (
            "one_shot_authority_consumed",
            {"authority_receipt_sha256": authority_receipt_sha256},
        ),
        (
            "budget_ledger_initialized",
            {
                "ledger_initial_event_sha256": ledger_initial_sha,
                "ceiling_nano_usd": budget.get("authorized_ceiling_nano_usd"),
            },
        ),
        ("provider_clients_constructed", {"model_ids": model_ids}),
        (
            "execution_commitments_frozen",
            {"execution_commitments_sha256": commitments_sha},
        ),
    ]
    model_orders: Counter[str] = Counter()
    for scheduled, attempted_record in zip(scheduled_rows, attempted, strict=True):
        _require(type(attempted_record) is dict, "attempted_record_schema_mismatch")
        calls = attempted_record.get("calls")
        _require(type(calls) is list and bool(calls), "attempted_record_calls_invalid")
        model_id = str(scheduled["model_id"])
        model_orders[model_id] += 1
        expected.extend(
            (
                (
                    "scheduled_run_started",
                    {
                        "sequence_index": scheduled["sequence_index"],
                        "scheduled_run_id": scheduled["run_id"],
                        "model_id": scheduled["model_id"],
                        "model_workflow_run_order": model_orders[model_id],
                    },
                ),
                (
                    "scheduled_run_retained",
                    {
                        "sequence_index": scheduled["sequence_index"],
                        "scheduled_run_id": scheduled["run_id"],
                        "source_kind": attempted_record.get("source_kind"),
                        "attempted_provider_calls": len(calls),
                    },
                ),
            )
        )
    expected.extend(
        (
            (
                "provisional_confirmatory_decision_computed",
                {
                    "decision": complete["decision"],
                    "scheduled_run_count": complete["scheduled_run_count"],
                    "provider_call_count": complete["provider_call_count"],
                    "budget_ledger_sha256": ledger_file_sha,
                },
            ),
            (
                "private_release_source_committed",
                {"private_release_source_sha256": source_sha256},
            ),
        )
    )
    _require(len(events) == len(expected), "execution_event_lifecycle_mismatch")
    expected_kinds = [kind for kind, _payload in expected]
    _require(kinds == expected_kinds, "execution_event_lifecycle_mismatch")
    for event, (expected_kind, payload) in zip(events, expected, strict=True):
        _require(
            event.get("event") == expected_kind
            and set(event) == event_envelope | set(payload)
            and all(
                type(event.get(name)) is type(value) and event.get(name) == value
                for name, value in payload.items()
            ),
            "execution_event_payload_mismatch",
        )
    _require(
        kinds[-1] == "private_release_source_committed"
        and previous == complete["terminal_event_sha256"],
        "execution_event_terminal_mismatch",
    )


def _load_budget_auditor() -> Callable[[str | Path], dict[str, object]]:
    return _load_budget_auditor_bound(None)


def _project_module_source(module: object, *, code: str) -> Path:
    origin = getattr(module, "__file__", None)
    _require(isinstance(origin, str), code)
    path = Path(origin).resolve()
    if path.suffix in {".pyc", ".pyo"}:
        try:
            path = Path(importlib.util.source_from_cache(str(path))).resolve()
        except (NotImplementedError, ValueError) as exc:
            raise ReleaseBuildError(code) from exc
    _require(path.is_file(), code)
    return path


def _assert_frozen_project_module_origins(
    freeze: Mapping[str, Any] | None,
) -> None:
    package_root = (ROOT / "src" / "mas_safety").resolve()
    tracked = freeze.get("tracked_artifact_sha256") if freeze is not None else None
    if freeze is not None:
        _require(type(tracked) is dict, "builder_frozen_import_binding_invalid")
    for name, module in tuple(sys.modules.items()):
        if name != "mas_safety" and not name.startswith("mas_safety."):
            continue
        path = _project_module_source(module, code="builder_project_import_origin_invalid")
        try:
            relative = path.relative_to(package_root)
        except ValueError as exc:
            raise ReleaseBuildError("builder_project_import_origin_invalid") from exc
        if tracked is not None:
            repository_relative = (Path("src") / "mas_safety" / relative).as_posix()
            expected = tracked.get(repository_relative)
            _require(
                isinstance(expected, str)
                and HEX_SHA256.fullmatch(expected) is not None
                and hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                "builder_frozen_import_binding_invalid",
            )


def _standard_path_hooks() -> list[object]:
    loader_details = (
        (
            importlib.machinery.ExtensionFileLoader,
            importlib.machinery.EXTENSION_SUFFIXES,
        ),
        (importlib.machinery.SourceFileLoader, importlib.machinery.SOURCE_SUFFIXES),
        (
            importlib.machinery.SourcelessFileLoader,
            importlib.machinery.BYTECODE_SUFFIXES,
        ),
    )
    return [
        zipimport.zipimporter,
        importlib.machinery.FileFinder.path_hook(*loader_details),
    ]


@contextmanager
def _restricted_project_import_state():
    source_root = (ROOT / "src").resolve()
    configured = sysconfig.get_paths()
    trusted_entries: list[Path] = [source_root]
    for name in ("stdlib", "platstdlib", "purelib", "platlib"):
        candidate = Path(configured[name]).resolve()
        if candidate not in trusted_entries:
            trusted_entries.append(candidate)
    stdlib = Path(configured["stdlib"]).resolve()
    standard_zip = (
        stdlib.parent
        / f"python{sys.version_info.major}{sys.version_info.minor}.zip"
    ).resolve()
    trusted_entries.insert(1, standard_zip)
    prior_path = list(sys.path)
    prior_meta_path = list(sys.meta_path)
    prior_path_hooks = list(sys.path_hooks)
    prior_importer_cache = dict(sys.path_importer_cache)
    sys.path[:] = [str(path) for path in trusted_entries]
    sys.meta_path[:] = [
        importlib.machinery.BuiltinImporter,
        importlib.machinery.FrozenImporter,
        importlib.machinery.PathFinder,
    ]
    sys.path_hooks[:] = _standard_path_hooks()
    sys.path_importer_cache.clear()
    try:
        yield
    finally:
        sys.path[:] = prior_path
        sys.meta_path[:] = prior_meta_path
        sys.path_hooks[:] = prior_path_hooks
        sys.path_importer_cache.clear()
        sys.path_importer_cache.update(prior_importer_cache)


def _load_budget_auditor_bound(
    freeze: Mapping[str, Any] | None,
) -> Callable[[str | Path], dict[str, object]]:
    modules = (
        _load_frozen_replay_modules(freeze)
        if freeze is not None
        else _load_project_source_modules(
            None,
            namespace="_stage4_release_current_runtime",
        )
    )
    module = modules["live_budget"]
    audit_budget_ledger = getattr(module, "audit_budget_ledger", None)
    _require(callable(audit_budget_ledger), "budget_auditor_unavailable")
    return audit_budget_ledger


def _load_project_source_modules(
    freeze: Mapping[str, Any] | None,
    *,
    namespace: str,
) -> dict[str, ModuleType]:
    """Load a fresh namespaced runtime from exact, directly compiled source bytes.

    Replay deliberately never imports or constructs a provider SDK client.  The
    separate package namespace prevents both earlier monkeypatches and this
    verifier from mutating the application's canonical imported class identities.
    Its empty package search path also makes an omitted project dependency fail
    closed instead of falling back to a bytecode-aware import loader.
    """

    package_root = (ROOT / "src" / "mas_safety").resolve()
    names = (
        "mas_safety.enums",
        "mas_safety.models",
        "mas_safety.provenance",
        "mas_safety.policies",
        "mas_safety.environment",
        "mas_safety.scenarios",
        "mas_safety.mechanisms",
        "mas_safety.defenses",
        "mas_safety.backends",
        "mas_safety.live_budget",
        "mas_safety.live_backends",
        "mas_safety.runner",
        "mas_safety.stage4_live",
        "mas_safety.stage4_runtime",
        "mas_safety.stage4_freeze",
    )
    _assert_frozen_project_module_origins(freeze)
    try:
        with _restricted_project_import_state():
            for loaded_name in tuple(sys.modules):
                if loaded_name == namespace or loaded_name.startswith(
                    f"{namespace}."
                ):
                    del sys.modules[loaded_name]
            package = ModuleType(namespace)
            package.__file__ = str(package_root / "__init__.py")
            package.__package__ = namespace
            package.__path__ = []  # type: ignore[attr-defined]
            package.__spec__ = importlib.util.spec_from_loader(
                namespace, loader=None, is_package=True
            )
            sys.modules[namespace] = package
            importlib.invalidate_caches()
            loaded: dict[str, ModuleType] = {}
            tracked = (
                freeze.get("tracked_artifact_sha256") if freeze is not None else None
            )
            if freeze is not None:
                _require(
                    type(tracked) is dict,
                    "builder_frozen_import_binding_invalid",
                )
                assert type(tracked) is dict
            for canonical_name in names:
                short_name = canonical_name.rsplit(".", 1)[-1]
                path = package_root / f"{short_name}.py"
                expected = (
                    tracked.get(f"src/mas_safety/{short_name}.py")
                    if tracked is not None
                    else None
                )
                if tracked is not None:
                    _require(
                        isinstance(expected, str),
                        "builder_frozen_import_binding_invalid",
                    )
                module = _load_source_bytes_module(
                    f"{namespace}.{short_name}",
                    path,
                    package=namespace,
                    expected_sha256=expected,
                    code=(
                        "builder_frozen_import_binding_invalid"
                        if tracked is not None
                        else "builder_project_import_origin_invalid"
                    ),
                )
                loaded[short_name] = module
            return loaded
    except Exception as exc:  # noqa: BLE001 - stable, redaction-safe boundary
        if isinstance(exc, ReleaseBuildError):
            raise
        raise ReleaseBuildError("frozen_local_replay_import_failed") from exc


def _load_frozen_replay_modules(
    freeze: Mapping[str, Any],
) -> dict[str, ModuleType]:
    return _load_project_source_modules(
        freeze,
        namespace="_stage4_release_frozen_runtime",
    )


def _validate_prompt_commitment_corpus(
    *,
    schedule: Mapping[str, Any],
    freeze: Mapping[str, Any],
    schedule_path: Path,
    modules: Mapping[str, ModuleType],
) -> dict[tuple[int, int, str], dict[str, Any]]:
    prompt_path = schedule_path.with_name("stage4_prompt_commitments.json")
    document = _parse_json_bytes(
        _read_regular_bytes(
            prompt_path,
            "prompt_commitments_file_invalid",
            maximum_size=64 * 1024 * 1024,
        ),
        "prompt_commitments_file_invalid",
    )
    document = _expect_object(
        document,
        PROMPT_COMMITMENT_DOCUMENT_FIELDS,
        "prompt_commitment_document_schema_mismatch",
    )
    prompt_contract = freeze.get("prompt_contract")
    budget_contract = freeze.get("budget_authority")
    _require(
        type(prompt_contract) is dict and type(budget_contract) is dict,
        "freeze_prompt_contract_invalid",
    )
    assert type(prompt_contract) is dict and type(budget_contract) is dict
    expected_semantic = _expect_sha256(
        document["commitments_sha256"], "prompt_commitment_semantic_hash_invalid"
    )
    semantic_payload = {
        name: value for name, value in document.items() if name != "commitments_sha256"
    }
    _require(
        _semantic_sha256(semantic_payload) == expected_semantic
        and expected_semantic
        == prompt_contract.get("potential_request_commitments_sha256"),
        "prompt_commitment_semantic_hash_mismatch",
    )
    exact_header = {
        "schema_version": prompt_contract.get(
            "potential_request_commitments_schema_version"
        ),
        "schedule_hash": schedule.get("schedule_hash"),
        "batch_id": freeze.get("runtime_binding", {}).get("batch_id")
        if type(freeze.get("runtime_binding")) is dict
        else None,
        "call_count": int(PUBLIC_VERIFIER.EXPECTED_MAXIMUM_AGENT_CALLS),
        "contains_prompt_or_request_bodies": False,
        "binds_all_potential_provider_requests": True,
        "required_minimum_nano_usd": budget_contract.get(
            "required_minimum_nano_usd"
        ),
        "required_minimum_usd": budget_contract.get("required_minimum_usd"),
        "all_execute_maximum_cost_nano_usd": budget_contract.get(
            "all_execute_maximum_cost_nano_usd"
        ),
        "all_execute_maximum_cost_usd": budget_contract.get(
            "all_execute_maximum_cost_usd"
        ),
    }
    _require(
        all(
            type(document.get(name)) is type(value) and document.get(name) == value
            for name, value in exact_header.items()
        ),
        "prompt_commitment_header_mismatch",
    )
    for name in (
        "minimum_request_utf8_bytes",
        "maximum_request_utf8_bytes",
        "total_request_utf8_bytes",
    ):
        _expect_int(document[name], "prompt_commitment_aggregate_invalid", minimum=1)
    _expect_str(document["method"], "prompt_commitment_method_invalid")

    models = document["models"]
    calls = document["calls"]
    _require(
        type(models) is list
        and type(calls) is list
        and len(models) == len(schedule.get("model_ids", []))
        and len(calls) == int(PUBLIC_VERIFIER.EXPECTED_MAXIMUM_AGENT_CALLS),
        "prompt_commitment_cardinality_mismatch",
    )
    assert type(models) is list and type(calls) is list
    for value, model_id in zip(models, schedule["model_ids"], strict=True):
        row = _expect_object(
            value,
            PROMPT_COMMITMENT_MODEL_FIELDS,
            "prompt_commitment_model_schema_mismatch",
        )
        _expect_str(
            row["model_id"], "prompt_commitment_model_order_mismatch", expected=model_id
        )
        for name in (
            "calls",
            "request_utf8_bytes",
            "cost_nano_usd",
            "completion_safe_cost_nano_usd",
        ):
            _expect_int(row[name], "prompt_commitment_model_aggregate_invalid", minimum=1)
        for name in ("cost_usd", "completion_safe_cost_usd"):
            _expect_str(row[name], "prompt_commitment_model_aggregate_invalid")

    index: dict[tuple[int, int, str], dict[str, Any]] = {}
    scheduled_rows = schedule["runs"]
    assert type(scheduled_rows) is list
    sizes: list[int] = []
    for call_index, value in enumerate(calls):
        row = _expect_object(
            value,
            PROMPT_COMMITMENT_ROW_FIELDS,
            "prompt_commitment_row_schema_mismatch",
        )
        sequence_index = call_index // 4
        role_index = call_index % 4 + 1
        scheduled = scheduled_rows[sequence_index]
        _expect_int(
            row["call_index"], "prompt_commitment_call_order_mismatch", expected=call_index
        )
        _expect_int(
            row["sequence_index"],
            "prompt_commitment_call_order_mismatch",
            expected=sequence_index,
        )
        _expect_int(
            row["role_index"],
            "prompt_commitment_role_order_mismatch",
            expected=role_index,
        )
        exact = {
            "scheduled_run_id": scheduled["run_id"],
            "pair_id": scheduled["pair_id"],
            "model_id": scheduled["model_id"],
            "role": PIPELINE_ROLE_NAMES[role_index - 1],
        }
        _require(
            all(row.get(name) == expected for name, expected in exact.items()),
            "prompt_commitment_schedule_binding_mismatch",
        )
        _expect_sha256(row["prompt_sha256"], "prompt_commitment_hash_invalid")
        _expect_sha256(
            row["canonical_request_sha256"], "prompt_commitment_hash_invalid"
        )
        size = _expect_int(
            row["canonical_request_utf8_bytes"],
            "prompt_commitment_request_size_invalid",
            minimum=1,
        )
        _require(size <= PROVIDER_REQUEST_MAXIMUM_BYTES, "prompt_commitment_request_size_invalid")
        sizes.append(size)
        key = (sequence_index, role_index, str(scheduled["model_id"]))
        _require(key not in index, "prompt_commitment_row_duplicate")
        index[key] = row
    _require(
        min(sizes) == document["minimum_request_utf8_bytes"]
        and max(sizes) == document["maximum_request_utf8_bytes"]
        and sum(sizes) == document["total_request_utf8_bytes"],
        "prompt_commitment_size_aggregate_mismatch",
    )

    stage4_freeze = modules.get("stage4_freeze")
    _require(stage4_freeze is not None, "frozen_prompt_rebuilder_unavailable")
    try:
        rebuilt = stage4_freeze.build_prompt_commitment_artifact(  # type: ignore[attr-defined]
            ROOT,
            schedule_manifest=dict(schedule),
        )
    except Exception as exc:  # noqa: BLE001 - no provider client exists on this path
        raise ReleaseBuildError("frozen_prompt_commitment_rebuild_failed") from exc
    _require(
        _canonical_json_bytes(rebuilt) == _canonical_json_bytes(document),
        "prompt_commitment_rebuild_mismatch",
    )
    return index


def _validate_budget_ledger(
    archive: Path,
    *,
    complete: Mapping[str, Any],
    freeze: Mapping[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], Counter[str]]:
    rows = _read_private_jsonl(
        archive,
        "budget_ledger.jsonl",
        "budget_ledger_invalid",
        maximum_size=128 * 1024 * 1024,
    )
    audit = _load_budget_auditor_bound(freeze)(archive / "budget_ledger.jsonl")
    _require(
        type(audit) is dict and audit.get("pass") is True,
        "budget_ledger_audit_failed",
    )
    budget = freeze.get("budget_authority")
    _require(type(budget) is dict, "freeze_budget_contract_invalid")
    assert type(budget) is dict
    ceiling = _expect_int(
        budget.get("authorized_ceiling_nano_usd"),
        "freeze_budget_ceiling_invalid",
        minimum=1,
    )
    _require(
        audit.get("ceiling_nano_usd") == ceiling
        and audit.get("active_reservations") == 0
        and audit.get("held_nano_usd") == 0,
        "budget_ledger_terminal_state_invalid",
    )
    _require(
        rows[0].get("event") == "ledger_initialized"
        and rows[0].get("ceiling_nano_usd") == ceiling,
        "budget_ledger_initialization_invalid",
    )
    held_by_id: dict[str, dict[str, Any]] = {}
    terminal_by_id: dict[str, dict[str, Any]] = {}
    model_counts: Counter[str] = Counter()
    event_hashes: set[str] = set()
    previous: str | None = None
    allowed_events = {"ledger_initialized", "reservation_held", "reservation_settled", "reservation_forfeited"}
    for sequence, event in enumerate(rows, start=1):
        kind = _expect_str(event.get("event"), "budget_ledger_event_invalid")
        _require(kind in allowed_events, "budget_ledger_nonconfirmatory_event")
        payload_fields = (
            BUDGET_LEDGER_INITIAL_FIELDS
            if kind == "ledger_initialized"
            else BUDGET_RESERVATION_FIELDS
            if kind == "reservation_held"
            else BUDGET_LEDGER_SETTLED_FIELDS
            if kind == "reservation_settled"
            else BUDGET_LEDGER_FORFEITED_FIELDS
        )
        _require(
            set(event) == BUDGET_LEDGER_ENVELOPE_FIELDS | payload_fields,
            "budget_ledger_event_schema_mismatch",
        )
        _expect_str(
            event.get("schema_version"),
            "budget_ledger_version_mismatch",
            expected="0.2.1",
        )
        _expect_int(event.get("sequence"), "budget_ledger_sequence_invalid", expected=sequence)
        _expect_utc_timestamp(
            event.get("recorded_at_utc"), "budget_ledger_timestamp_invalid"
        )
        _require(event.get("previous_event_sha256") == previous, "budget_ledger_chain_invalid")
        supplied = _expect_sha256(event.get("event_sha256"), "budget_ledger_hash_invalid")
        unhashed = {name: value for name, value in event.items() if name != "event_sha256"}
        _require(
            supplied == _semantic_sha256(unhashed) and supplied not in event_hashes,
            "budget_ledger_hash_duplicate_or_invalid",
        )
        for name in (
            "committed_nano_usd",
            "held_nano_usd",
            "gross_exposure_nano_usd",
            "remaining_authority_nano_usd",
        ):
            _expect_int(event.get(name), "budget_ledger_state_type_invalid", minimum=0)
        previous = supplied
        event_hashes.add(supplied)
        if kind == "ledger_initialized":
            expected_initial = {
                "ceiling_nano_usd": ceiling,
                "ceiling_usd": _nano_usd_string(ceiling),
                "pricing_basis": "standard_service_tier_full_uncached_list_price",
                "pricing_nano_usd_per_token": PUBLIC_VERIFIER.MODEL_PRICING,
                "input_token_reservation_per_call": PUBLIC_VERIFIER.INPUT_RESERVATION_TOKENS,
                "output_token_reservation_per_call": PUBLIC_VERIFIER.OUTPUT_RESERVATION_TOKENS,
                "maximum_provider_request_utf8_bytes": PROVIDER_REQUEST_MAXIMUM_BYTES,
                "stage4_successful_input_token_bound": "canonical_request_utf8_bytes",
                "committed_nano_usd": 0,
                "held_nano_usd": 0,
                "gross_exposure_nano_usd": 0,
                "remaining_authority_nano_usd": ceiling,
            }
            _require(
                sequence == 1
                and all(event.get(name) == value for name, value in expected_initial.items()),
                "budget_ledger_initialization_invalid",
            )
            continue
        reservation_id = _expect_str(
            event.get("reservation_id"), "budget_ledger_reservation_invalid"
        )
        _expect_str(
            event.get("phase"),
            "budget_ledger_phase_invalid",
            expected=STAGE4_BUDGET_PHASE,
        )
        if kind == "reservation_held":
            _require(
                reservation_id not in held_by_id,
                "budget_ledger_reservation_duplicate",
            )
            model_id = _expect_str(event.get("model_id"), "budget_ledger_model_invalid")
            _require(model_id in PUBLIC_VERIFIER.MODELS, "budget_ledger_model_invalid")
            request_bytes = _expect_int(
                event.get("request_utf8_bytes"),
                "budget_ledger_request_size_invalid",
                minimum=1,
            )
            _require(
                reservation_id == f"budget-{len(held_by_id) + 1:06d}"
                and event.get("event_sequence") == sequence
                and RAW_STEM.fullmatch(
                    _expect_str(event.get("call_stem"), "budget_ledger_call_stem_invalid")
                )
                is not None
                and request_bytes <= PROVIDER_REQUEST_MAXIMUM_BYTES
                and event.get("input_token_bound")
                == PUBLIC_VERIFIER.INPUT_RESERVATION_TOKENS
                and event.get("output_token_bound")
                == PUBLIC_VERIFIER.OUTPUT_RESERVATION_TOKENS
                and event.get("reserved_nano_usd")
                == (
                    PUBLIC_VERIFIER.INPUT_RESERVATION_TOKENS
                    * PUBLIC_VERIFIER.MODEL_PRICING[model_id]["input"]
                    + PUBLIC_VERIFIER.OUTPUT_RESERVATION_TOKENS
                    * PUBLIC_VERIFIER.MODEL_PRICING[model_id]["output"]
                ),
                "budget_ledger_reservation_payload_invalid",
            )
            _expect_sha256(
                event.get("request_sha256"), "budget_ledger_request_hash_invalid"
            )
            held_by_id[reservation_id] = event
            model_counts[model_id] += 1
        else:
            _require(
                reservation_id in held_by_id and reservation_id not in terminal_by_id,
                "budget_ledger_terminal_duplicate_or_orphan",
            )
            held = held_by_id[reservation_id]
            _require(
                event.get("model_id") == held.get("model_id")
                and event.get("call_stem") == held.get("call_stem")
                and event.get("request_sha256") == held.get("request_sha256"),
                "budget_ledger_terminal_payload_invalid",
            )
            settled = _expect_int(
                event.get("settled_nano_usd"),
                "budget_ledger_terminal_payload_invalid",
                minimum=0,
            )
            released = _expect_int(
                event.get("released_nano_usd"),
                "budget_ledger_terminal_payload_invalid",
                minimum=0,
            )
            if kind == "reservation_settled":
                input_tokens = _expect_int(
                    event.get("input_tokens"),
                    "budget_ledger_terminal_payload_invalid",
                    minimum=0,
                )
                output_tokens = _expect_int(
                    event.get("output_tokens"),
                    "budget_ledger_terminal_payload_invalid",
                    minimum=0,
                )
                model_id = str(held["model_id"])
                expected_settled = (
                    input_tokens * PUBLIC_VERIFIER.MODEL_PRICING[model_id]["input"]
                    + output_tokens * PUBLIC_VERIFIER.MODEL_PRICING[model_id]["output"]
                )
                _require(
                    event.get("disposition")
                    == "usage_settled_full_uncached_rates"
                    and settled == expected_settled
                    and released == int(held["reserved_nano_usd"]) - settled,
                    "budget_ledger_terminal_payload_invalid",
                )
            else:
                _require(
                    event.get("disposition")
                    == "provider_exception_usage_unavailable"
                    and settled == held.get("reserved_nano_usd")
                    and released == 0,
                    "budget_ledger_terminal_payload_invalid",
                )
            terminal_by_id[reservation_id] = event
    provider_calls = int(complete["provider_call_count"])
    _require(
        len(held_by_id) == provider_calls
        and len(terminal_by_id) == provider_calls
        and set(held_by_id) == set(terminal_by_id)
        and len(rows) == 1 + 2 * provider_calls,
        "budget_ledger_call_count_mismatch",
    )
    return held_by_id, terminal_by_id, model_counts


def _raw_evidence_maps(
    files: set[str],
) -> tuple[dict[tuple[str, str], str], dict[tuple[str, str], tuple[str, str]]]:
    request_paths: dict[tuple[str, str], str] = {}
    result_paths: dict[tuple[str, str], tuple[str, str]] = {}
    for relative in sorted(path for path in files if path.startswith("raw/")):
        parts = PurePosixPath(relative).parts
        _require(len(parts) == 3 and parts[0] == "raw", "raw_archive_path_invalid")
        model_id, filename = parts[1], parts[2]
        _require(model_id in PUBLIC_VERIFIER.MODELS, "raw_archive_model_invalid")
        if filename.endswith(".request.json"):
            stem = filename.removesuffix(".request.json")
            _require(RAW_STEM.fullmatch(stem) is not None, "raw_archive_stem_invalid")
            key = (model_id, stem)
            _require(key not in request_paths, "raw_archive_request_duplicate")
            request_paths[key] = relative
        elif filename.endswith(".response.json"):
            stem = filename.removesuffix(".response.json")
            _require(RAW_STEM.fullmatch(stem) is not None, "raw_archive_stem_invalid")
            key = (model_id, stem)
            _require(key not in result_paths, "raw_archive_result_duplicate")
            result_paths[key] = (relative, "response")
        elif filename.endswith(".error.json"):
            stem = filename.removesuffix(".error.json")
            _require(RAW_STEM.fullmatch(stem) is not None, "raw_archive_stem_invalid")
            key = (model_id, stem)
            _require(key not in result_paths, "raw_archive_result_duplicate")
            result_paths[key] = (relative, "error")
        else:
            raise ReleaseBuildError("raw_archive_entry_invalid")
    _require(
        set(request_paths) == set(result_paths),
        "raw_archive_request_result_mismatch",
    )
    return request_paths, result_paths


def _validate_call_audit_scalar_types(call: Mapping[str, Any]) -> None:
    for name in (
        "step_index",
        "provider_call_order",
        "local_pairing_seed",
        "scheduled_workflow_run_order",
        "model_workflow_run_order",
        "repetition",
        "retry_count",
    ):
        _expect_int(call[name], "attempted_call_type_invalid", minimum=0)
    for name in ("structured_output_valid", "mechanism_active", "provider_native_refusal"):
        _expect_bool(call[name], "attempted_call_type_invalid")
    for name in (
        "decision_status",
        "requested_model",
        "condition_id",
        "invocation_id",
        "scenario_id",
        "mechanism",
        "safety_variant",
        "protocol_commit_sha",
        "protocol_sha256",
        "batch_id",
        "raw_log_record",
        "provider_request_sha256",
        "request_record_sha256",
        "result_record_sha256",
        "result_record_kind",
        "ledger_reservation_id",
        "ledger_reservation_event_sha256",
        "ledger_terminal_event_sha256",
    ):
        _expect_str(call[name], "attempted_call_type_invalid")
    _require(call["retry_count"] == 0, "attempted_call_retry_forbidden")
    allowed_statuses = {
        "accepted_execute",
        "model_refusal",
        "model_escalation",
        "provider_error",
        "schema_error",
        "unoffered_action",
    }
    _require(call["decision_status"] in allowed_statuses, "attempted_call_status_invalid")
    expected_structured = (
        call["decision_status"]
        in {"accepted_execute", "model_refusal", "model_escalation"}
        and call["provider_native_refusal"] is False
    )
    _require(
        call["structured_output_valid"] is expected_structured,
        "attempted_call_structured_validity_mismatch",
    )
    _require(
        call["provider_native_refusal"] is False
        or (
            call["decision_status"] == "model_refusal"
            and call["result_record_kind"] == "response"
        ),
        "attempted_call_native_refusal_invalid",
    )
    _require(
        call["result_record_kind"] in {"response", "error"},
        "attempted_call_result_kind_invalid",
    )
    for name in (
        "protocol_sha256",
        "provider_request_sha256",
        "request_record_sha256",
        "result_record_sha256",
        "ledger_reservation_event_sha256",
        "ledger_terminal_event_sha256",
    ):
        _expect_sha256(call[name], "attempted_call_hash_invalid")


def _validate_trace_preimage_and_labels(
    trace: Mapping[str, Any],
    *,
    scheduled: Mapping[str, Any],
    private_row: Mapping[str, Any],
    calls: Sequence[Mapping[str, Any]],
    source_sha256: str,
) -> None:
    _require(
        _semantic_sha256(trace) == source_sha256,
        "trace_source_preimage_hash_mismatch",
    )
    exact_identity = {
        "condition_id": private_row["condition_id"],
        "scenario_id": scheduled["scenario_id"],
        "domain": scheduled["domain"],
        "mechanism": scheduled["mechanism"],
        "mechanism_active": scheduled["mechanism_on"],
        "safety_variant": scheduled["safety_variant"],
        "model_id": scheduled["model_id"],
        "batch_id": private_row["batch_id"],
        "seed": private_row["seed"],
        "invocation_id": private_row["invocation_id"],
        "provenance_key_id": private_row["provenance_key_id"],
        "backend": private_row["backend_name"],
    }
    _require(
        all(type(trace.get(key)) is type(expected) and trace.get(key) == expected for key, expected in exact_identity.items()),
        "trace_schedule_identity_mismatch",
    )
    _require(
        trace.get("defense") == "local_only"
        and trace.get("architecture") == "multi_agent"
        and trace.get("decision_mode") == "execution_decision",
        "trace_execution_contract_mismatch",
    )
    component_hashes = trace.get("component_hashes")
    backend_configuration = trace.get("backend_configuration")
    _require(
        type(component_hashes) is dict
        and type(backend_configuration) is dict
        and _semantic_sha256(component_hashes)
        == private_row["component_hashes_sha256"]
        and _semantic_sha256(backend_configuration)
        == private_row["backend_configuration_sha256"],
        "trace_execution_artifact_commitment_mismatch",
    )
    boolean_names = (
        "global_violation",
        "all_local_allow",
        "local_allow_global_harm",
        "benign_completed",
        "defense_blocked",
        "capability_failure",
        "refusal",
        "escalation",
    )
    _require(
        all(type(trace.get(name)) is bool for name in boolean_names),
        "trace_label_type_invalid",
    )
    status = _expect_str(trace.get("status"), "trace_status_invalid")
    allowed_statuses = {
        "completed",
        "model_refusal",
        "model_escalation",
        "local_block",
        "capability_failure",
    }
    _require(status in allowed_statuses, "trace_status_invalid")
    _require(
        trace["local_allow_global_harm"]
        is (trace["global_violation"] and trace["all_local_allow"]),
        "trace_local_lgh_inconsistent",
    )
    _require(
        trace["defense_blocked"] is False
        and (status == "capability_failure") is trace["capability_failure"]
        and (status == "model_refusal") is trace["refusal"]
        and (status == "model_escalation") is trace["escalation"],
        "trace_terminal_flags_inconsistent",
    )
    completed = status == "completed"
    _require(
        completed or not (trace["local_allow_global_harm"] or trace["benign_completed"]),
        "trace_noncompletion_label_invalid",
    )
    if scheduled["safety_variant"] == "unsafe":
        _require(
            trace["benign_completed"] is False
            and (not completed or trace["local_allow_global_harm"] is True),
            "trace_unsafe_label_invalid",
        )
    else:
        _require(
            trace["local_allow_global_harm"] is False
            and (not completed or trace["benign_completed"] is True),
            "trace_safe_label_invalid",
        )
    statuses = [str(call["decision_status"]) for call in calls]
    _require(
        all(value == "accepted_execute" for value in statuses[:-1]),
        "trace_continued_after_terminal_decision",
    )
    expected_final = {
        "completed": "accepted_execute",
        "local_block": "accepted_execute",
        "model_refusal": "model_refusal",
        "model_escalation": "model_escalation",
    }.get(status)
    if status == "capability_failure":
        _require(
            statuses[-1] in {"provider_error", "schema_error", "unoffered_action"},
            "trace_capability_failure_status_invalid",
        )
    else:
        _require(statuses[-1] == expected_final, "trace_call_status_mismatch")
    _require(not completed or len(calls) == 4, "trace_completed_call_count_mismatch")

    steps = trace.get("steps")
    _require(
        type(steps) is list and len(steps) == len(calls),
        "trace_step_count_mismatch",
    )
    assert type(steps) is list
    for index, (step, call) in enumerate(zip(steps, calls, strict=True), start=1):
        _require(type(step) is dict, "trace_step_invalid")
        assert type(step) is dict
        _require(
            type(step.get("step_index")) is int
            and step.get("step_index") == index
            and step.get("decision_status") == call["decision_status"],
            "trace_step_call_mismatch",
        )
        metadata = step.get("provider_metadata")
        _require(type(metadata) is dict, "trace_provider_metadata_invalid")
        assert type(metadata) is dict
        metadata_links = {
            "requested_model": call["requested_model"],
            "condition_id": call["condition_id"],
            "invocation_id": call["invocation_id"],
            "scenario_id": call["scenario_id"],
            "mechanism": call["mechanism"],
            "mechanism_active": call["mechanism_active"],
            "safety_variant": call["safety_variant"],
            "batch_id": call["batch_id"],
            "local_pairing_seed": call["local_pairing_seed"],
            "scheduled_workflow_run_order": call["scheduled_workflow_run_order"],
            "model_workflow_run_order": call["model_workflow_run_order"],
            "repetition": call["repetition"],
            "protocol_commit_sha": call["protocol_commit_sha"],
            "protocol_sha256": call["protocol_sha256"],
            "call_order": call["provider_call_order"],
            "structured_output_valid": call["structured_output_valid"],
            "raw_log_record": call["raw_log_record"],
            "provider_request_sha256": call["provider_request_sha256"],
            "request_record_sha256": call["request_record_sha256"],
            "result_record_sha256": call["result_record_sha256"],
            "result_record_kind": call["result_record_kind"],
            "retry_count": 0,
        }
        _require(
            all(metadata.get(key) == expected for key, expected in metadata_links.items()),
            "trace_provider_metadata_call_mismatch",
        )

    if completed:
        reason: str | None = None
        failure: str | None = None
    elif status == "capability_failure":
        reason = statuses[-1]
        failure = "provider_error" if reason == "provider_error" else "schema_error"
    else:
        reason = {
            "model_refusal": "model_refusal",
            "model_escalation": "model_escalation",
            "local_block": "local_block",
        }[status]
        failure = None
    expected_labels = {
        "local_lgh": int(trace["local_allow_global_harm"]),
        "safe_completion": int(trace["benign_completed"]),
        "run_completed": int(completed),
        "refusal": trace["refusal"],
        "escalation": trace["escalation"],
        "attempted_agent_calls": len(calls),
        "valid_structured_decisions": sum(
            int(call["structured_output_valid"]) for call in calls
        ),
        "noncompletion_reason": reason,
        "failure_reason": failure,
        "source_kind": "trace",
        "source_record_commitment_sha256": source_sha256,
        "replacement_attempted": False,
    }
    _require(
        all(
            type(private_row[name]) is type(expected) and private_row[name] == expected
            for name, expected in expected_labels.items()
        ),
        "trace_to_public_label_mismatch",
    )


def _validate_failure_record_labels(
    *,
    private_row: Mapping[str, Any],
    calls: Sequence[Mapping[str, Any]],
    source_sha256: str,
) -> None:
    statuses = [str(call["decision_status"]) for call in calls]
    _require(
        all(value == "accepted_execute" for value in statuses[:-1])
        and statuses[-1] in {"provider_error", "schema_error", "unoffered_action"},
        "failure_record_call_status_invalid",
    )
    terminal = statuses[-1]
    reason = terminal
    failure = "provider_error" if terminal == "provider_error" else "schema_error"
    expected = {
        "local_lgh": 0,
        "safe_completion": 0,
        "run_completed": 0,
        "refusal": False,
        "escalation": False,
        "attempted_agent_calls": len(calls),
        "valid_structured_decisions": sum(
            int(call["structured_output_valid"]) for call in calls
        ),
        "noncompletion_reason": reason,
        "failure_reason": failure,
        "source_kind": "attempted_failure_record",
        "source_record_commitment_sha256": calls[-1]["result_record_sha256"],
        "replacement_attempted": False,
    }
    _require(
        source_sha256 == calls[-1]["result_record_sha256"]
        and all(
            type(private_row[name]) is type(value) and private_row[name] == value
            for name, value in expected.items()
        ),
        "failure_record_to_public_label_mismatch",
    )


class _ReplayInvariantError(RuntimeError):
    """An archive/replay mismatch that the runner must not convert to a trace."""

    abort_live_batch = True


def _replay_require(condition: bool, code: str) -> None:
    if not condition:
        raise _ReplayInvariantError(code)


def _validate_raw_call_evidence(
    archive: Path,
    *,
    request_path: str,
    result_path: str,
    result_kind: str,
    request_record_sha256: str,
    result_record_sha256: str,
    stem: str,
    model_id: str,
    provider_call_order: int,
    local_pairing_seed: int,
    expected_metadata: Mapping[str, Any],
    held: Mapping[str, Any],
    terminal: Mapping[str, Any],
    prompt_commitment: Mapping[str, Any],
    decision_schema_version: str,
) -> dict[str, Any]:
    request = _expect_object(
        _read_private_json_with_float(
            archive,
            request_path,
            "raw_request_record_invalid",
            maximum_size=RAW_REQUEST_MAXIMUM_BYTES,
        ),
        RAW_REQUEST_FIELDS,
        "raw_request_record_schema_mismatch",
    )
    _expect_str(
        request["record_version"],
        "raw_request_record_version_mismatch",
        expected=decision_schema_version,
    )
    attempted_at = _expect_utc_timestamp(
        request["attempted_at_utc"], "raw_request_timestamp_invalid"
    )
    _expect_int(
        request["provider_call_order"],
        "raw_request_call_order_mismatch",
        expected=provider_call_order,
    )
    _expect_int(
        request["local_pairing_seed"],
        "raw_request_pairing_seed_mismatch",
        expected=local_pairing_seed,
    )
    metadata = _expect_object(
        request["run_metadata"],
        RAW_RUN_METADATA_FIELDS,
        "raw_request_metadata_schema_mismatch",
    )
    _require(
        all(
            type(metadata.get(name)) is type(expected)
            and metadata.get(name) == expected
            for name, expected in expected_metadata.items()
        ),
        "raw_request_metadata_mismatch",
    )
    reservation = _expect_object(
        request["budget_reservation"],
        BUDGET_RESERVATION_FIELDS,
        "raw_request_budget_reservation_schema_mismatch",
    )
    _require(
        all(reservation.get(name) == held.get(name) for name in BUDGET_RESERVATION_FIELDS)
        and reservation.get("event_sequence") == held.get("sequence"),
        "raw_request_budget_reservation_mismatch",
    )
    provider_request = request["provider_request"]
    _require(type(provider_request) is dict, "raw_provider_request_invalid")
    assert type(provider_request) is dict
    canonical_request = _canonical_json_bytes(provider_request)
    provider_request_sha = hashlib.sha256(canonical_request).hexdigest()
    prompt = provider_request.get("input")
    _require(type(prompt) is str, "raw_provider_prompt_invalid")
    assert type(prompt) is str
    prompt_sha = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    _expect_sha256(request["provider_request_sha256"], "raw_provider_request_hash_invalid")
    _expect_sha256(request["prompt_sha256"], "raw_provider_prompt_hash_invalid")
    _require(
        request["provider_request_sha256"] == provider_request_sha
        and request["prompt_sha256"] == prompt_sha
        and 0 < len(canonical_request) <= PROVIDER_REQUEST_MAXIMUM_BYTES
        and stem
        == f"call-{provider_call_order:06d}-{provider_request_sha[:12]}"
        and reservation["phase"] == STAGE4_BUDGET_PHASE
        and reservation["model_id"] == model_id
        and reservation["call_stem"] == stem
        and reservation["request_sha256"] == provider_request_sha
        and reservation["request_utf8_bytes"] == len(canonical_request)
        and prompt_commitment.get("prompt_sha256") == prompt_sha
        and prompt_commitment.get("canonical_request_sha256")
        == provider_request_sha
        and prompt_commitment.get("canonical_request_utf8_bytes")
        == len(canonical_request),
        "raw_request_semantic_commitment_mismatch",
    )

    result_fields = RAW_RESPONSE_FIELDS if result_kind == "response" else RAW_ERROR_FIELDS
    result = _expect_object(
        _read_private_json_with_float(
            archive,
            result_path,
            "raw_result_record_invalid",
            maximum_size=RAW_RESULT_MAXIMUM_BYTES,
        ),
        result_fields,
        "raw_result_record_schema_mismatch",
    )
    _expect_str(
        result["record_version"],
        "raw_result_record_version_mismatch",
        expected=decision_schema_version,
    )
    received_name = "received_at_utc" if result_kind == "response" else "recorded_at_utc"
    received_at = _expect_utc_timestamp(
        result[received_name], "raw_result_timestamp_invalid"
    )
    _require(received_at >= attempted_at, "raw_result_timestamp_precedes_request")
    _expect_optional_str(
        result["transport_request_id"], "raw_result_transport_request_id_invalid"
    )
    _expect_nonnegative_finite_float(result["latency_ms"], "raw_result_latency_invalid")
    _require(
        type(result["budget_event"]) is dict
        and result["budget_event"] == dict(terminal),
        "raw_result_budget_event_mismatch",
    )

    if result_kind == "response":
        response = result["provider_response"]
        _require(type(response) is dict, "raw_provider_response_invalid")
        assert type(response) is dict
        usage = response.get("usage")
        _require(type(usage) is dict, "raw_provider_response_usage_invalid")
        assert type(usage) is dict
        input_tokens = _expect_int(
            usage.get("input_tokens"), "raw_provider_response_usage_invalid", minimum=0
        )
        output_tokens = _expect_int(
            usage.get("output_tokens"), "raw_provider_response_usage_invalid", minimum=0
        )
        _require(
            response.get("model") == model_id
            and response.get("service_tier") == "default"
            and terminal.get("event") == "reservation_settled"
            and terminal.get("input_tokens") == input_tokens
            and terminal.get("output_tokens") == output_tokens
            and terminal.get("disposition")
            == "usage_settled_full_uncached_rates"
            and input_tokens <= int(reservation["request_utf8_bytes"])
            and input_tokens <= int(reservation["input_token_bound"])
            and output_tokens <= int(reservation["output_token_bound"])
            and terminal.get("released_nano_usd")
            == int(reservation["reserved_nano_usd"])
            - int(terminal.get("settled_nano_usd", -1)),
            "raw_provider_response_contract_mismatch",
        )
    else:
        _expect_str(result["error_type"], "raw_provider_error_type_invalid")
        provider_error = result["provider_error_response"]
        _require(
            provider_error is None or type(provider_error) is dict,
            "raw_provider_error_response_invalid",
        )
        if type(provider_error) is dict:
            _require(
                set(provider_error) == {"status_code", "body"}
                and (
                    provider_error["status_code"] is None
                    or type(provider_error["status_code"]) is int
                ),
                "raw_provider_error_response_invalid",
            )
        _require(
            terminal.get("event") == "reservation_forfeited"
            and terminal.get("disposition")
            == "provider_exception_usage_unavailable"
            and terminal.get("settled_nano_usd")
            == reservation["reserved_nano_usd"]
            and terminal.get("released_nano_usd") == 0,
            "raw_provider_error_budget_mismatch",
        )

    return {
        "request": request,
        "result": result,
        "result_kind": result_kind,
        "stem": stem,
        "model_id": model_id,
        "request_record_sha256": request_record_sha256,
        "result_record_sha256": result_record_sha256,
        "provider_request_sha256": provider_request_sha,
        "prompt_commitment": dict(prompt_commitment),
        "held": dict(held),
        "terminal": dict(terminal),
    }


def _archived_access_failure(value: object) -> bool:
    if type(value) is not dict:
        return False
    assert type(value) is dict
    if value.get("status_code") in {401, 403, 404}:
        return True
    fatal = {
        "authentication_error",
        "invalid_api_key",
        "insufficient_permissions",
        "model_not_found",
        "permission_denied",
    }
    pending = [value.get("body")]
    while pending:
        item = pending.pop()
        if type(item) is dict:
            assert type(item) is dict
            if item.get("code") in fatal or item.get("type") in fatal:
                return True
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
    return False


def _response_metadata(
    evidence: Mapping[str, Any],
    *,
    sdk_version: str,
    prompt_version: str,
    decision_schema_version: str,
) -> dict[str, object]:
    request = evidence["request"]
    result = evidence["result"]
    response = result["provider_response"]
    assert type(request) is dict and type(result) is dict and type(response) is dict
    return {
        "provider": "openai",
        "api": "responses",
        "response_id": response.get("id"),
        "request_id": result["transport_request_id"],
        "requested_model": evidence["model_id"],
        "resolved_response_model": response.get("model"),
        "model_snapshot": response.get("model"),
        "created_at": response.get("created_at"),
        "status": response.get("status"),
        "system_fingerprint": response.get("system_fingerprint"),
        "service_tier": response.get("service_tier"),
        "sdk_version": sdk_version,
        "prompt_version": prompt_version,
        "decision_schema_version": decision_schema_version,
        "raw_log_record": evidence["stem"],
        "prompt_sha256": request["prompt_sha256"],
        "provider_request_sha256": evidence["provider_request_sha256"],
        "request_record_sha256": evidence["request_record_sha256"],
        "result_record_sha256": evidence["result_record_sha256"],
        "result_record_kind": "response",
        "structured_output": "json_schema_strict",
        "seed_supported": False,
        "local_pairing_seed": request["local_pairing_seed"],
        "structured_output_valid": False,
        "response_received": True,
        "model_response_received": True,
        "failure_type": None,
        "call_order": request["provider_call_order"],
        "retry_count": 0,
        "attempted_at_utc": request["attempted_at_utc"],
        "received_at_utc": result["received_at_utc"],
        **request["run_metadata"],
    }


class _ProviderFreeRawReplayBackend:
    name = "openai_responses"

    def __init__(
        self,
        *,
        model_id: str,
        configuration: Mapping[str, Any],
        evidence: Sequence[Mapping[str, Any]],
        live_backends: ModuleType,
    ) -> None:
        self.model_id = model_id
        self.configuration = dict(configuration)
        self._evidence = list(evidence)
        self._index = 0
        self._live = live_backends

    @property
    def consumed(self) -> int:
        return self._index

    def decide(
        self,
        *,
        context: object,
        decision_mode: object,
        candidate_action: object,
        offered_actions: tuple[object, ...],
        artifact: object | None,
        seed: int,
    ) -> object:
        _replay_require(self._index < len(self._evidence), "raw_replay_call_missing")
        evidence = self._evidence[self._index]
        self._index += 1
        request = evidence["request"]
        _replay_require(type(request) is dict, "raw_replay_request_invalid")
        generated, prompt = self._live.build_frozen_provider_request(
            model_id=self.model_id,
            context=context,
            decision_mode=decision_mode,
            candidate_action=candidate_action,
            offered_actions=offered_actions,
            artifact=artifact,
            timeout_seconds=float(self.configuration["timeout_seconds"]),
        )
        generated_bytes = _canonical_json_bytes(generated)
        generated_sha = hashlib.sha256(generated_bytes).hexdigest()
        prompt_sha = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        commitment = evidence["prompt_commitment"]
        _replay_require(
            request["provider_request"] == generated
            and request["provider_request_sha256"] == generated_sha
            and request["prompt_sha256"] == prompt_sha
            and request["local_pairing_seed"] == seed
            and commitment["canonical_request_sha256"] == generated_sha
            and commitment["canonical_request_utf8_bytes"] == len(generated_bytes)
            and commitment["prompt_sha256"] == prompt_sha
            and commitment["role"] == context.role.value,
            "raw_request_frozen_reconstruction_mismatch",
        )
        return self._decision_from_evidence(evidence, offered_actions)

    def _decision_from_evidence(
        self,
        evidence: Mapping[str, Any],
        offered_actions: tuple[object, ...],
    ) -> object:
        request = evidence["request"]
        result = evidence["result"]
        assert type(request) is dict and type(result) is dict
        prompt_version = str(self.configuration["prompt_version"])
        decision_version = str(self.configuration["decision_schema_version"])
        sdk_version = str(self.configuration["sdk_version"])
        if evidence["result_kind"] == "error":
            _replay_require(
                result["error_type"] != "ProviderImportBoundaryError"
                and not _archived_access_failure(result["provider_error_response"]),
                "complete_archive_contains_fatal_provider_error",
            )
            shell = object.__new__(self._live.OpenAIResponsesBackend)
            shell.model_id = self.model_id
            shell._sdk_version = sdk_version
            shell._call_count = request["provider_call_order"]
            shell._run_metadata = dict(request["run_metadata"])
            provider_error = result["provider_error_response"]
            status_code = (
                provider_error.get("status_code")
                if type(provider_error) is dict
                else None
            )
            metadata = shell._failure_metadata(
                call_stem=evidence["stem"],
                seed=request["local_pairing_seed"],
                attempted_at_utc=request["attempted_at_utc"],
                received_at_utc=result["recorded_at_utc"],
                request_id=result["transport_request_id"],
                status="transport_error",
                error_type=result["error_type"],
                prompt_sha256=request["prompt_sha256"],
                provider_request_sha256=evidence["provider_request_sha256"],
                request_record_sha256=evidence["request_record_sha256"],
                result_record_sha256=evidence["result_record_sha256"],
                result_record_kind="error",
                response_received=provider_error is not None,
                model_response_received=False,
                http_status_code=status_code if type(status_code) is int else None,
            )
            raise self._live.ProviderCallError(
                "provider-free archived transport failure replay",
                provider_metadata=metadata,
                latency_ms=result["latency_ms"],
            )

        response = result["provider_response"]
        usage = response["usage"]
        metadata = _response_metadata(
            evidence,
            sdk_version=sdk_version,
            prompt_version=prompt_version,
            decision_schema_version=decision_version,
        )
        input_tokens = usage["input_tokens"]
        output_tokens = usage["output_tokens"]
        latency_ms = result["latency_ms"]
        output_text = self._live._output_text(response, response)  # noqa: SLF001
        if response.get("status") != "completed":
            raise self._live.ProviderCallError(
                "provider-free archived noncompleted response replay",
                raw_output=output_text or None,
                provider_metadata={**metadata, "failure_type": "provider_error"},
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                latency_ms=latency_ms,
            )
        try:
            if not output_text:
                refusal = self._live._provider_refusal(response)  # noqa: SLF001
                if refusal:
                    return self._live.AgentDecision.refuse(
                        refusal,
                        raw_output=refusal,
                        provider_metadata=metadata,
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        latency_ms=latency_ms,
                    )
                raise self._live.StructuredDecisionError(
                    "Provider response contained neither structured output nor refusal"
                )
            try:
                payload = json.loads(output_text)
            except json.JSONDecodeError as exc:
                raise self._live.StructuredDecisionError(
                    "Provider output was not valid JSON"
                ) from exc
            return self._live._validated_decision(  # noqa: SLF001
                payload,
                action_catalog=self._live._action_catalog(offered_actions),  # noqa: SLF001
                raw_output=output_text,
                provider_metadata={**metadata, "structured_output_valid": True},
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                latency_ms=latency_ms,
            )
        except self._live.StructuredDecisionError as exc:
            raise exc.with_trace_context(
                raw_output=output_text or None,
                provider_metadata={**metadata, "failure_type": "schema_error"},
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                latency_ms=latency_ms,
            ) from None


def _reconstruct_run_spec(spec: Mapping[str, Any], modules: Mapping[str, ModuleType]) -> object:
    expected_fields = {
        "scenario_id",
        "mechanism",
        "defense",
        "safety_variant",
        "architecture",
        "mechanism_active",
        "cohort",
        "seed",
        "invocation_id",
        "batch_id",
        "decision_mode",
        "condition_id",
    }
    _require(set(spec) == expected_fields, "raw_replay_runspec_schema_mismatch")
    enums = modules["enums"]
    runner = modules["runner"]
    try:
        rebuilt = runner.RunSpec(
            scenario_id=spec["scenario_id"],
            mechanism=enums.Mechanism(spec["mechanism"]),
            defense=enums.Defense(spec["defense"]),
            safety_variant=enums.SafetyVariant(spec["safety_variant"]),
            architecture=enums.Architecture(spec["architecture"]),
            mechanism_active=spec["mechanism_active"],
            cohort=spec["cohort"],
            seed=spec["seed"],
            invocation_id=spec["invocation_id"],
            batch_id=spec["batch_id"],
            decision_mode=enums.DecisionMode(spec["decision_mode"]),
        )
    except (TypeError, ValueError, KeyError) as exc:
        raise ReleaseBuildError("raw_replay_runspec_invalid") from exc
    _require(
        rebuilt.condition_id == spec["condition_id"]
        and rebuilt.defense.value == "local_only"
        and rebuilt.architecture.value == "multi_agent"
        and rebuilt.decision_mode.value == "execution_decision",
        "raw_replay_runspec_contract_mismatch",
    )
    return rebuilt


def _replay_trace_and_derive_calls(
    *,
    archived_trace: Mapping[str, Any],
    archived_calls: Sequence[Mapping[str, Any]],
    evidence: Sequence[Mapping[str, Any]],
    scheduled: Mapping[str, Any],
    binding: Mapping[str, Any],
    commitments: Mapping[str, Any],
    freeze: Mapping[str, Any],
    scenarios: Sequence[object],
    modules: Mapping[str, ModuleType],
) -> None:
    spec_value = binding.get("run_spec")
    _require(type(spec_value) is dict, "raw_replay_runspec_invalid")
    assert type(spec_value) is dict
    spec = _reconstruct_run_spec(spec_value, modules)
    configuration = _expected_production_backend_configuration(
        freeze, model_id=str(scheduled["model_id"])
    )
    backend = _ProviderFreeRawReplayBackend(
        model_id=str(scheduled["model_id"]),
        configuration=configuration,
        evidence=evidence,
        live_backends=modules["live_backends"],
    )
    provenance = freeze.get("provenance_boundary")
    _require(type(provenance) is dict, "freeze_provenance_contract_invalid")
    assert type(provenance) is dict
    try:
        runner = modules["runner"].ExperimentRunner(
            scenarios,
            backend,
            provenance_signing_key=REPLAY_NONSECRET_SIGNING_BYTES,
            provenance_key_id=commitments["provenance_key_id"],
        )
        replayed = runner.run(spec).to_dict()
    except _ReplayInvariantError as exc:
        raise ReleaseBuildError(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - raw failures are normalized above
        raise ReleaseBuildError("frozen_local_trace_replay_failed") from exc
    _require(
        backend.consumed == len(evidence), "raw_replay_call_count_mismatch"
    )
    _require(
        _canonical_json_bytes(replayed) == _canonical_json_bytes(archived_trace),
        "frozen_local_trace_replay_mismatch",
    )
    steps = replayed.get("steps")
    _require(type(steps) is list and len(steps) == len(evidence), "raw_replay_step_count_mismatch")
    assert type(steps) is list
    for index, (step, item, archived) in enumerate(
        zip(steps, evidence, archived_calls, strict=True), start=1
    ):
        metadata = step.get("provider_metadata")
        request = item["request"]
        _require(type(metadata) is dict and type(request) is dict, "raw_replay_metadata_invalid")
        assert type(metadata) is dict and type(request) is dict
        reservation = request["budget_reservation"]
        assert type(reservation) is dict
        derived = {
            "step_index": index,
            "provider_call_order": request["provider_call_order"],
            "decision_status": step["decision_status"],
            "structured_output_valid": metadata.get("structured_output_valid") is True,
            "requested_model": scheduled["model_id"],
            "local_pairing_seed": spec.seed + index,
            "scheduled_workflow_run_order": scheduled["sequence_index"] + 1,
            "model_workflow_run_order": request["run_metadata"]["model_workflow_run_order"],
            "repetition": scheduled["repetition"],
            "condition_id": spec.condition_id,
            "invocation_id": spec.invocation_id,
            "scenario_id": spec.scenario_id,
            "mechanism": spec.mechanism.value,
            "mechanism_active": spec.mechanism_active,
            "safety_variant": spec.safety_variant.value,
            "protocol_commit_sha": commitments["protocol_commit_sha"],
            "protocol_sha256": commitments["protocol_sha256"],
            "batch_id": spec.batch_id,
            "raw_log_record": item["stem"],
            "provider_request_sha256": item["provider_request_sha256"],
            "request_record_sha256": item["request_record_sha256"],
            "result_record_sha256": item["result_record_sha256"],
            "result_record_kind": item["result_kind"],
            "ledger_reservation_id": reservation["reservation_id"],
            "ledger_reservation_event_sha256": item["held"]["event_sha256"],
            "ledger_terminal_event_sha256": item["terminal"]["event_sha256"],
            "provider_native_refusal": step["decision_status"] == "model_refusal"
            and metadata.get("structured_output_valid") is not True,
            "retry_count": 0,
        }
        _require(
            _canonical_json_bytes(derived) == _canonical_json_bytes(archived),
            "raw_replay_call_audit_mismatch",
        )


def _validate_attempted_records(
    archive: Path,
    *,
    files: set[str],
    covered_files: Mapping[str, tuple[str, int]],
    schedule: Mapping[str, Any],
    bindings: Sequence[Mapping[str, Any]],
    commitments: Mapping[str, Any],
    private_rows: Sequence[Mapping[str, Any]],
    complete: Mapping[str, Any],
    held_by_id: Mapping[str, Mapping[str, Any]],
    terminal_by_id: Mapping[str, Mapping[str, Any]],
    ledger_model_counts: Counter[str],
    freeze: Mapping[str, Any],
    schedule_path: Path,
) -> None:
    records = _read_private_jsonl(
        archive,
        "attempted_records.jsonl",
        "attempted_records_invalid",
        maximum_size=256 * 1024 * 1024,
    )
    _require(
        len(records) == int(PUBLIC_VERIFIER.EXPECTED_RUN_COUNT),
        "attempted_record_count_mismatch",
    )
    traces = (
        _read_private_trace_jsonl(
            archive,
            "traces.jsonl",
            "traces_invalid",
            maximum_size=512 * 1024 * 1024,
        )
        if "traces.jsonl" in files
        else []
    )
    modules = _load_frozen_replay_modules(freeze)
    prompt_commitments = _validate_prompt_commitment_corpus(
        schedule=schedule,
        freeze=freeze,
        schedule_path=schedule_path,
        modules=modules,
    )
    try:
        scenarios = modules["scenarios"].load_scenarios(
            ROOT / "scenarios" / "confirmatory"
        )
    except Exception as exc:  # noqa: BLE001 - frozen local inputs only
        raise ReleaseBuildError("frozen_local_scenario_load_failed") from exc
    trace_index = 0
    request_paths, result_paths = _raw_evidence_maps(files)
    _require(
        len(request_paths) == int(complete["provider_call_count"]),
        "raw_archive_call_count_mismatch",
    )
    used_raw: set[tuple[str, str]] = set()
    used_reservations: set[str] = set()
    provider_orders: dict[str, set[int]] = {
        model_id: set() for model_id in PUBLIC_VERIFIER.MODELS
    }
    public_model_counts: Counter[str] = Counter()
    scheduled_rows = schedule["runs"]
    assert type(scheduled_rows) is list
    for record, private_row, scheduled, binding in zip(
        records, private_rows, scheduled_rows, bindings, strict=True
    ):
        record = _expect_object(
            record, ATTEMPTED_RECORD_FIELDS, "attempted_record_schema_mismatch"
        )
        run_id = _expect_str(record["scheduled_run_id"], "attempted_record_run_id_invalid")
        _require(
            run_id == scheduled["run_id"] == private_row["run_id"],
            "attempted_record_schedule_mismatch",
        )
        source_kind = _expect_str(record["source_kind"], "attempted_record_source_invalid")
        source_sha = _expect_sha256(record["source_sha256"], "attempted_record_source_invalid")
        _require(
            source_kind == private_row["source_kind"]
            and source_sha == private_row["source_record_commitment_sha256"],
            "attempted_record_source_mismatch",
        )
        calls = record["calls"]
        _require(type(calls) is list and bool(calls), "attempted_record_calls_invalid")
        assert type(calls) is list
        _require(
            len(calls) == private_row["attempted_agent_calls"],
            "attempted_record_call_count_mismatch",
        )
        _require(
            _semantic_sha256(calls) == private_row["call_audit_sha256"],
            "attempted_record_call_commitment_mismatch",
        )
        valid_count = 0
        replay_evidence: list[dict[str, Any]] = []
        spec = binding.get("run_spec")
        _require(type(spec) is dict, "attempted_call_runtime_binding_invalid")
        assert type(spec) is dict
        for step_index, value in enumerate(calls, start=1):
            call = _expect_object(
                value, CALL_AUDIT_FIELDS, "attempted_call_schema_mismatch"
            )
            _validate_call_audit_scalar_types(call)
            _require(
                call["step_index"] == step_index
                and call["requested_model"] == scheduled["model_id"]
                and call["scenario_id"] == scheduled["scenario_id"]
                and call["mechanism"] == scheduled["mechanism"]
                and call["mechanism_active"] is scheduled["mechanism_on"]
                and call["safety_variant"] == scheduled["safety_variant"]
                and call["repetition"] == scheduled["repetition"],
                "attempted_call_schedule_mismatch",
            )
            _require(
                call["local_pairing_seed"] == spec.get("seed") + step_index
                and call["scheduled_workflow_run_order"]
                == scheduled["sequence_index"] + 1
                and call["model_workflow_run_order"]
                == private_row["model_workflow_run_order"]
                and call["condition_id"] == spec.get("condition_id")
                and call["invocation_id"] == spec.get("invocation_id")
                and call["protocol_commit_sha"]
                == commitments["protocol_commit_sha"]
                and call["protocol_sha256"] == commitments["protocol_sha256"]
                and call["batch_id"] == spec.get("batch_id"),
                "attempted_call_runtime_binding_mismatch",
            )
            model_id = str(call["requested_model"])
            stem = str(call["raw_log_record"])
            key = (model_id, stem)
            _require(key in request_paths and key in result_paths, "attempted_call_raw_link_missing")
            result_path, result_kind = result_paths[key]
            _require(
                call["result_record_kind"] == result_kind
                and covered_files[request_paths[key]][0] == call["request_record_sha256"]
                and covered_files[result_path][0] == call["result_record_sha256"],
                "attempted_call_raw_hash_mismatch",
            )
            reservation_id = str(call["ledger_reservation_id"])
            held = held_by_id.get(reservation_id)
            terminal = terminal_by_id.get(reservation_id)
            _require(
                held is not None
                and terminal is not None
                and held.get("event_sha256") == call["ledger_reservation_event_sha256"]
                and terminal.get("event_sha256") == call["ledger_terminal_event_sha256"]
                and held.get("model_id") == model_id
                and held.get("call_stem") == stem
                and held.get("request_sha256") == call["provider_request_sha256"],
                "attempted_call_ledger_link_mismatch",
            )
            order = int(call["provider_call_order"])
            _require(order >= 1, "attempted_call_order_invalid")
            _require(
                stem.startswith(f"call-{order:06d}-"),
                "attempted_call_stem_order_mismatch",
            )
            _require(
                key not in used_raw
                and reservation_id not in used_reservations
                and order not in provider_orders[model_id],
                "attempted_call_evidence_reused",
            )
            used_raw.add(key)
            used_reservations.add(reservation_id)
            provider_orders[model_id].add(order)
            public_model_counts[model_id] += 1
            valid_count += int(call["structured_output_valid"])
            prompt_commitment = prompt_commitments.get(
                (int(scheduled["sequence_index"]), step_index, model_id)
            )
            _require(
                prompt_commitment is not None,
                "attempted_call_prompt_commitment_missing",
            )
            expected_metadata = {
                "scheduled_workflow_run_order": scheduled["sequence_index"] + 1,
                "model_workflow_run_order": private_row["model_workflow_run_order"],
                "repetition": scheduled["repetition"],
                "condition_id": spec["condition_id"],
                "invocation_id": spec["invocation_id"],
                "scenario_id": spec["scenario_id"],
                "mechanism": spec["mechanism"],
                "mechanism_active": spec["mechanism_active"],
                "safety_variant": spec["safety_variant"],
                "protocol_commit_sha": commitments["protocol_commit_sha"],
                "protocol_sha256": commitments["protocol_sha256"],
                "batch_id": spec["batch_id"],
            }
            assert held is not None and terminal is not None
            replay_evidence.append(
                _validate_raw_call_evidence(
                    archive,
                    request_path=request_paths[key],
                    result_path=result_path,
                    result_kind=result_kind,
                    request_record_sha256=covered_files[request_paths[key]][0],
                    result_record_sha256=covered_files[result_path][0],
                    stem=stem,
                    model_id=model_id,
                    provider_call_order=order,
                    local_pairing_seed=int(spec["seed"]) + step_index,
                    expected_metadata=expected_metadata,
                    held=held,
                    terminal=terminal,
                    prompt_commitment=prompt_commitment,
                    decision_schema_version=str(
                        freeze["prompt_contract"]["decision_schema_version"]
                    ),
                )
            )
        _require(
            valid_count == private_row["valid_structured_decisions"],
            "attempted_record_valid_decision_count_mismatch",
        )
        if source_kind == "trace":
            _require(trace_index < len(traces), "trace_source_preimage_missing")
            trace = traces[trace_index]
            _replay_trace_and_derive_calls(
                archived_trace=trace,
                archived_calls=calls,
                evidence=replay_evidence,
                scheduled=scheduled,
                binding=binding,
                commitments=commitments,
                freeze=freeze,
                scenarios=scenarios,
                modules=modules,
            )
            _validate_trace_preimage_and_labels(
                trace,
                scheduled=scheduled,
                private_row=private_row,
                calls=calls,
                source_sha256=source_sha,
            )
            trace_index += 1
        else:
            raise ReleaseBuildError("attempted_record_source_kind_invalid")
    _require(
        used_raw == set(request_paths)
        and used_reservations == set(held_by_id)
        and public_model_counts == ledger_model_counts,
        "attempted_call_evidence_bijection_failed",
    )
    for model_id, orders in provider_orders.items():
        _require(
            orders == set(range(1, len(orders) + 1)),
            "attempted_call_order_not_contiguous",
        )
    _require(trace_index == len(traces), "trace_source_preimage_extra")


def _load_frozen_documents(
    schedule_path: Path,
    freeze_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    _require(
        schedule_path.name == "stage4_schedule.json"
        and freeze_path.name == "stage4_freeze.json"
        and schedule_path.parent == freeze_path.parent
        and schedule_path.parent.name == "manifests",
        "frozen_input_path_noncanonical",
    )
    try:
        schedule = PUBLIC_VERIFIER._validate_schedule_document(  # noqa: SLF001
            PUBLIC_VERIFIER._read_json(schedule_path)  # noqa: SLF001
        )
        freeze = PUBLIC_VERIFIER._read_json(freeze_path)  # noqa: SLF001
    except Exception as exc:  # noqa: BLE001 - normalize verifier internals
        raise ReleaseBuildError("frozen_input_validation_failed") from exc
    _require(
        freeze.get("freeze_status") == "frozen_executable",
        "stage4_freeze_not_final",
    )
    schedule_sha = _file_sha256(
        schedule_path, "schedule_file_invalid", maximum_size=32 * 1024 * 1024
    )
    freeze_sha = _file_sha256(
        freeze_path, "freeze_file_invalid", maximum_size=16 * 1024 * 1024
    )
    return schedule, freeze, schedule_sha, freeze_sha


def _validate_full_final_freeze(
    freeze: Mapping[str, Any],
    *,
    schedule: Mapping[str, Any],
    schedule_path: Path,
    freeze_path: Path,
) -> None:
    try:
        PUBLIC_VERIFIER._validate_freeze(  # noqa: SLF001
            freeze,
            schedule=schedule,
            schedule_path=schedule_path,
            freeze_path=freeze_path,
        )
    except Exception as exc:  # noqa: BLE001 - normalize verifier internals
        raise ReleaseBuildError("final_freeze_contract_validation_failed") from exc


def _canonical_runtime_bindings(
    schedule_path: Path,
    *,
    batch_id: str,
    freeze: Mapping[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], str]:
    _assert_frozen_project_module_origins(freeze)
    try:
        if freeze is not None:
            module = _load_frozen_replay_modules(freeze)["stage4_runtime"]
        else:
            module = _load_project_source_modules(
                None,
                namespace="_stage4_release_current_runtime",
            )["stage4_runtime"]
        build_stage4_run_bindings = getattr(module, "build_stage4_run_bindings")
        load_stage4_schedule_manifest = getattr(
            module, "load_stage4_schedule_manifest"
        )
        stage4_run_bindings_sha256 = getattr(module, "stage4_run_bindings_sha256")

        schedule_object = load_stage4_schedule_manifest(schedule_path)
        bindings = build_stage4_run_bindings(schedule_object, batch_id=batch_id)
        digest = stage4_run_bindings_sha256(bindings)
        rows = [binding.hash_record() for binding in bindings]
    except Exception as exc:  # noqa: BLE001 - provider-free binding code only
        if isinstance(exc, ReleaseBuildError):
            raise
        raise ReleaseBuildError("canonical_runtime_binding_failed") from exc
    return rows, digest


def _validate_private_outcome_extras(
    row: Mapping[str, Any],
    scheduled: Mapping[str, Any],
    *,
    binding: Mapping[str, Any],
    artifact: Mapping[str, Any],
    commitments: Mapping[str, Any],
    expected_model_order: int,
) -> None:
    for name in (
        "sequence_index",
        "seed",
        "scheduled_workflow_run_order",
        "model_workflow_run_order",
    ):
        _expect_int(row[name], "private_outcome_type_invalid", minimum=0)
    _require(
        row["sequence_index"] == scheduled["sequence_index"]
        and row["scheduled_workflow_run_order"] == scheduled["sequence_index"] + 1
        and row["model_workflow_run_order"] == expected_model_order
        and row["pair_id"] == scheduled["pair_id"],
        "private_outcome_schedule_binding_mismatch",
    )
    for name in (
        "invocation_id",
        "batch_id",
        "condition_id",
        "provenance_key_id",
        "backend_name",
    ):
        _expect_str(row[name], "private_outcome_type_invalid")
    spec = binding.get("run_spec")
    _require(type(spec) is dict, "private_outcome_runtime_binding_invalid")
    assert type(spec) is dict
    expected_runtime = {
        "seed": spec.get("seed"),
        "invocation_id": spec.get("invocation_id"),
        "batch_id": spec.get("batch_id"),
        "condition_id": spec.get("condition_id"),
    }
    _require(
        binding.get("sequence_index") == scheduled["sequence_index"]
        and binding.get("scheduled_run_id") == scheduled["run_id"]
        and binding.get("pair_id") == scheduled["pair_id"]
        and binding.get("model_id") == scheduled["model_id"]
        and all(row[name] == expected for name, expected in expected_runtime.items()),
        "private_outcome_runtime_binding_mismatch",
    )
    _expect_str(
        row["protocol_commit_sha"],
        "private_outcome_protocol_commit_mismatch",
        expected=str(commitments["protocol_commit_sha"]),
    )
    _require(
        GIT_OBJECT_ID.fullmatch(str(row["protocol_commit_sha"])) is not None,
        "private_outcome_protocol_commit_mismatch",
    )
    for name in (
        "call_audit_sha256",
        "component_hashes_sha256",
        "backend_configuration_sha256",
        "protocol_sha256",
    ):
        _expect_sha256(row[name], "private_outcome_hash_invalid")
    _require(
        row["component_hashes_sha256"] == artifact["component_hashes_sha256"]
        and row["backend_configuration_sha256"]
        == artifact["backend_configuration_sha256"]
        and row["protocol_sha256"] == commitments["protocol_sha256"]
        and row["provenance_key_id"] == commitments["provenance_key_id"]
        and row["backend_name"] == commitments["backend_name"],
        "private_outcome_execution_commitment_mismatch",
    )


def _project_public_rows(
    outcomes: Mapping[str, Any],
    *,
    schedule: Mapping[str, Any],
    bindings: Sequence[Mapping[str, Any]],
    commitments_document: Mapping[str, Any],
) -> list[dict[str, Any]]:
    values = outcomes["outcomes"]
    _require(type(values) is list, "private_outcomes_rows_invalid")
    assert type(values) is list
    scheduled_rows = schedule["runs"]
    assert type(scheduled_rows) is list
    artifacts = commitments_document["run_artifacts"]
    assert type(artifacts) is list
    _require(
        len(values)
        == len(scheduled_rows)
        == len(bindings)
        == len(artifacts)
        == int(PUBLIC_VERIFIER.EXPECTED_RUN_COUNT),
        "private_outcomes_row_count_mismatch",
    )
    projected: list[dict[str, Any]] = []
    source_commitments: set[str] = set()
    model_orders: Counter[str] = Counter()
    for value, scheduled, binding, artifact in zip(
        values, scheduled_rows, bindings, artifacts, strict=True
    ):
        row = _expect_object(
            value, PRIVATE_OUTCOME_FIELDS, "private_outcome_schema_mismatch"
        )
        model_orders[str(scheduled["model_id"])] += 1
        _validate_private_outcome_extras(
            row,
            scheduled,
            binding=binding,
            artifact=artifact,
            commitments=commitments_document,
            expected_model_order=model_orders[str(scheduled["model_id"])],
        )
        public_row = {
            field_name: row[field_name]
            for field_name in sorted(PUBLIC_VERIFIER.OUTCOME_FIELDS)
        }
        _require(
            set(public_row) == set(PUBLIC_VERIFIER.OUTCOME_FIELDS),
            "public_outcome_projection_mismatch",
        )
        try:
            PUBLIC_VERIFIER._validate_outcome(  # noqa: SLF001
                public_row, scheduled, source_commitments
            )
        except Exception as exc:  # noqa: BLE001 - normalize verifier internals
            raise ReleaseBuildError("public_outcome_validation_failed") from exc
        projected.append(public_row)
    return projected


def _json_document_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


def _assert_no_public_secret_material(name: str, raw: bytes) -> None:
    _require(b"\x00" not in raw, "public_release_binary_content_forbidden")
    for pattern in FORBIDDEN_PUBLIC_BYTES:
        _require(pattern.search(raw) is None, "public_release_secret_material_detected")
    # These are the only source-derived public records.  Explicitly reject
    # vocabulary that would indicate somebody bypassed the structural
    # projection and serialized private provider material instead.
    if name == "runs.json":
        lowered = raw.lower()
        for forbidden_key in (
            b'"provider_request"',
            b'"provider_response"',
            b'"raw_output"',
            b'"prompt"',
            b'"trace":',
            b'"budget_event"',
        ):
            _require(
                forbidden_key not in lowered,
                "public_release_raw_material_detected",
            )


def _public_bundle_bytes(
    *,
    schedule: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, bytes], dict[str, Any]]:
    try:
        summary = PUBLIC_VERIFIER.build_expected_summary(schedule, rows)
        readme = PUBLIC_VERIFIER.render_release_readme(summary)
    except Exception as exc:  # noqa: BLE001 - normalize verifier internals
        raise ReleaseBuildError("public_summary_recomputation_failed") from exc
    _require(
        summary.get("decision") in {"GO", "NO_GO"},
        "public_summary_decision_provisional",
    )
    runs = {
        "schema_version": PUBLIC_VERIFIER.RUNS_SCHEMA_VERSION,
        "schedule_hash": schedule["schedule_hash"],
        "outcomes": list(rows),
    }
    files = {
        "README.md": readme.encode("utf-8"),
        "runs.json": _json_document_bytes(runs),
        "summary.json": _json_document_bytes(summary),
    }
    for name, raw in files.items():
        _assert_no_public_secret_material(name, raw)
    checksum_lines = [
        f"{hashlib.sha256(files[name]).hexdigest()}  {name}"
        for name in sorted(PUBLIC_FILES)
    ]
    files["SHA256SUMS"] = ("\n".join(checksum_lines) + "\n").encode("ascii")
    _require(set(files) == PUBLIC_ENTRY_SET, "public_release_entry_set_internal_error")
    return files, summary


def _write_exclusive_public_file(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o644)
    except OSError as exc:
        raise ReleaseBuildError("public_staging_write_failed") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(0o644)
    except Exception as exc:  # noqa: BLE001
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise ReleaseBuildError("public_staging_write_failed") from exc


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _atomic_rename_noreplace(source: Path, destination: Path) -> None:
    """Atomically publish a directory while refusing an existing target."""

    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    result: int | None = None
    if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        renamex = libc.renamex_np
        renamex.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex.restype = ctypes.c_int
        result = int(renamex(source_bytes, destination_bytes, 0x00000004))
    elif hasattr(libc, "renameat2"):
        renameat2 = libc.renameat2
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = int(renameat2(-100, source_bytes, -100, destination_bytes, 1))
    if result is not None:
        if result == 0:
            _fsync_directory(destination.parent)
            return
        error_number = ctypes.get_errno()
        if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
            raise ReleaseBuildError("public_destination_already_exists")
        raise ReleaseBuildError("public_release_atomic_publish_failed")

    raise ReleaseBuildError("exclusive_directory_rename_unavailable")


VerifierCallable = Callable[..., Mapping[str, Any]]


def build_stage4_release(
    private_archive: str | Path = DEFAULT_PRIVATE_ARCHIVE,
    *,
    destination: str | Path = DEFAULT_DESTINATION,
    schedule_path: str | Path = DEFAULT_SCHEDULE,
    freeze_path: str | Path = DEFAULT_FREEZE,
    _verify: VerifierCallable | None = None,
) -> dict[str, Any]:
    """Validate, sanitize, independently verify, and atomically publish."""

    archive = Path(private_archive).resolve()
    destination_path = Path(destination).resolve()
    schedule_file = Path(schedule_path).resolve()
    freeze_file = Path(freeze_path).resolve()
    _require(
        destination_path != archive
        and archive not in destination_path.parents
        and destination_path not in archive.parents,
        "public_destination_overlaps_private_archive",
    )
    _require(
        not os.path.lexists(destination_path),
        "public_destination_already_exists",
    )
    parent = destination_path.parent
    try:
        parent_info = parent.lstat()
    except OSError as exc:
        raise ReleaseBuildError("public_destination_parent_invalid") from exc
    _require(
        stat.S_ISDIR(parent_info.st_mode) and not stat.S_ISLNK(parent_info.st_mode),
        "public_destination_parent_invalid",
    )

    schedule, freeze, schedule_sha_before, freeze_sha_before = _load_frozen_documents(
        schedule_file, freeze_file
    )
    _validate_full_final_freeze(
        freeze,
        schedule=schedule,
        schedule_path=schedule_file,
        freeze_path=freeze_file,
    )
    freeze_tag_target = _resolve_freeze_tag_target(freeze, freeze_file)
    runtime_contract = freeze.get("runtime_binding")
    _require(type(runtime_contract) is dict, "freeze_runtime_binding_invalid")
    assert type(runtime_contract) is dict
    batch_id = _expect_str(
        runtime_contract.get("batch_id"), "freeze_runtime_batch_id_invalid"
    )
    bindings, binding_digest = _canonical_runtime_bindings(
        schedule_file, batch_id=batch_id, freeze=freeze
    )
    archive_manifest, covered_files, files = _validate_archive_manifest(archive)
    archive_manifest_file_sha_before = hashlib.sha256(
        _read_private_bytes(
            archive / ARCHIVE_MANIFEST_NAME,
            "private_archive_manifest_unreadable",
            maximum_size=32 * 1024 * 1024,
        )
    ).hexdigest()
    completion_file_sha_before = hashlib.sha256(
        _read_private_bytes(
            archive / COMPLETE_MARKER_NAME,
            "completion_marker_invalid",
            maximum_size=64 * 1024,
        )
    ).hexdigest()
    (
        complete,
        source,
        outcomes,
        private_decision,
        execution_commitments,
    ) = _validate_complete_marker_and_source(
        archive,
        archive_manifest,
        covered_files,
        schedule=schedule,
        freeze=freeze,
        freeze_tag_target=freeze_tag_target,
        canonical_binding_digest=binding_digest,
        schedule_path=schedule_file,
        freeze_path=freeze_file,
    )
    _validate_execution_events(
        archive,
        complete=complete,
        schedule=schedule,
        source_sha256=covered_files["private_release_source.json"][0],
        authority_receipt_sha256=_validate_execution_start_and_authority(
            archive,
            covered_files=covered_files,
            freeze=freeze,
            schedule=schedule,
            freeze_tag_target=freeze_tag_target,
            freeze_file_sha256=freeze_sha_before,
        ),
        freeze=freeze,
        freeze_manifest_sha256=freeze_sha_before,
        freeze_tag_target=freeze_tag_target,
    )
    held, terminal, ledger_counts = _validate_budget_ledger(
        archive, complete=complete, freeze=freeze
    )
    rows = _project_public_rows(
        outcomes,
        schedule=schedule,
        bindings=bindings,
        commitments_document=execution_commitments,
    )
    _validate_attempted_records(
        archive,
        files=files,
        covered_files=covered_files,
        schedule=schedule,
        bindings=bindings,
        commitments=execution_commitments,
        private_rows=outcomes["outcomes"],
        complete=complete,
        held_by_id=held,
        terminal_by_id=terminal,
        ledger_model_counts=ledger_counts,
        freeze=freeze,
        schedule_path=schedule_file,
    )
    public_files, summary = _public_bundle_bytes(schedule=schedule, rows=rows)
    _require(
        summary["decision"] == complete["decision"] == private_decision["decision"],
        "independent_decision_mismatch",
    )
    _require(
        summary["attempted_agent_calls"] == complete["provider_call_count"],
        "provider_call_count_outcome_mismatch",
    )

    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{destination_path.name}.staging-",
            dir=parent,
        )
    )
    published = False
    try:
        staging.chmod(0o755)
        for name in sorted(public_files):
            _write_exclusive_public_file(staging / name, public_files[name])
        _fsync_directory(staging)
        _require(
            {path.name for path in staging.iterdir()} == PUBLIC_ENTRY_SET,
            "public_staging_entry_set_mismatch",
        )
        verifier = PUBLIC_VERIFIER.verify_release if _verify is None else _verify
        try:
            report = verifier(
                staging,
                schedule_path=schedule_file,
                freeze_path=freeze_file,
                require_full=False,
            )
        except Exception as exc:  # noqa: BLE001 - stable release boundary
            raise ReleaseBuildError("public_verifier_rejected_staged_release") from exc
        _require(
            type(report) is dict
            and report.get("status") == "VERIFIED"
            and report.get("pass") is True
            and report.get("public_data_verification_pass") is True
            and report.get("empirical_release_present") is True
            and report.get("decision_recomputed") == summary["decision"],
            "public_verifier_did_not_verify",
        )
        _require(
            report.get("scheduled_rows_verified")
            == int(PUBLIC_VERIFIER.EXPECTED_RUN_COUNT)
            and report.get("schedule_hash") == schedule["schedule_hash"]
            and report.get("schedule_file_sha256") == schedule_sha_before
            and report.get("freeze_manifest_sha256") == freeze_sha_before
            and report.get("release_checksum_manifest_sha256")
            == hashlib.sha256(public_files["SHA256SUMS"]).hexdigest()
            and report.get("repository_tag_binding_verified") is True,
            "public_verifier_report_binding_mismatch",
        )

        # Rehash both frozen inputs and every committed private file after the
        # verifier returns.  Any concurrent mutation invalidates publication.
        second_manifest, second_covered, second_files = _validate_archive_manifest(archive)
        _require(
            second_manifest == archive_manifest
            and second_covered == covered_files
            and second_files == files
            and hashlib.sha256(
                _read_private_bytes(
                    archive / ARCHIVE_MANIFEST_NAME,
                    "private_archive_manifest_unreadable",
                    maximum_size=32 * 1024 * 1024,
                )
            ).hexdigest()
            == archive_manifest_file_sha_before
            and hashlib.sha256(
                _read_private_bytes(
                    archive / COMPLETE_MARKER_NAME,
                    "completion_marker_invalid",
                    maximum_size=64 * 1024,
                )
            ).hexdigest()
            == completion_file_sha_before,
            "private_archive_changed_during_release_build",
        )
        _require(
            _file_sha256(
                schedule_file,
                "schedule_file_invalid",
                maximum_size=32 * 1024 * 1024,
            )
            == schedule_sha_before
            and _file_sha256(
                freeze_file,
                "freeze_file_invalid",
                maximum_size=16 * 1024 * 1024,
            )
            == freeze_sha_before,
            "frozen_input_changed_during_release_build",
        )
        _require(
            not os.path.lexists(destination_path),
            "public_destination_already_exists",
        )
        _atomic_rename_noreplace(staging, destination_path)
        published = True
    finally:
        if not published and os.path.lexists(staging):
            shutil.rmtree(staging)

    return {
        "schema_version": "stage4-public-release-build-report-v1",
        "status": "PUBLISHED",
        "pass": True,
        "decision": summary["decision"],
        "scheduled_rows": len(rows),
        "public_entry_count": len(PUBLIC_ENTRY_SET),
        "release_checksum_manifest_sha256": hashlib.sha256(
            public_files["SHA256SUMS"]
        ).hexdigest(),
        "provider_calls_made_by_builder": 0,
        "private_raw_files_copied": 0,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build the four-file Stage 4 public release from one COMPLETE private archive."
        )
    )
    parser.add_argument("--json", action="store_true", dest="json_output")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    try:
        _require(sys.flags.isolated == 1, "builder_requires_python_isolated_mode")
        report = build_stage4_release()
    except ReleaseBuildError as exc:
        if arguments.json_output:
            print(
                json.dumps(
                    {
                        "schema_version": "stage4-public-release-build-report-v1",
                        "status": "REJECTED",
                        "pass": False,
                        "reason": exc.code,
                        "provider_calls_made_by_builder": 0,
                        "private_raw_files_copied": 0,
                    },
                    sort_keys=True,
                )
            )
        else:
            print(f"REJECTED: {exc.code}", file=sys.stderr)
        return 2
    if arguments.json_output:
        print(json.dumps(report, sort_keys=True))
    else:
        print(
            "PUBLISHED: Stage 4 public release "
            f"(decision={report['decision']}, rows={report['scheduled_rows']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
