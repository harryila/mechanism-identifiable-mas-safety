"""Dormant, fail-closed production executor for frozen Stage 4.

The public entry point cannot accept model, output, budget, credential, or
provider overrides.  It first requires the repository/tag/hash preflight in
``stage4_runtime`` to pass.  Only then does it validate dedicated Stage 4
secret fingerprints, exclusively create the private archive and one-shot
authority receipt, initialize the manifest-bound budget ledger, and construct
the two frozen provider backends.

Development and ordinary tests call no provider.  The sole injection seam is
the explicitly private ``_run_stage4_execution_for_test`` helper.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import sysconfig
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .backends import AgentBackend
from .live_backends import (
    FROZEN_MAX_OUTPUT_TOKENS,
    FROZEN_REASONING_EFFORT,
    FROZEN_SERVICE_TIER,
    INSTRUCTIONS_SHA256,
    OPENAI_OFFICIAL_BASE_URL,
    PINNED_OPENAI_SDK_VERSION,
    OpenAIResponsesBackend,
    ProviderAccessError,
    ProviderArchiveError,
    ProviderCallError,
    ProviderContractError,
    StructuredDecisionError,
)
from .live_budget import (
    BudgetAccountingError,
    BudgetCeilingExceeded,
    LiveBudgetLedger,
    audit_budget_ledger,
)
from .mechanisms import build_mechanism_setup
from .enums import PIPELINE_ROLES
from .models import RunTrace, Scenario
from .provenance import DEVELOPMENT_KEY_ID, DEVELOPMENT_SIGNING_KEY
from .runner import ExperimentRunner, component_hashes_for
from .scenarios import load_scenarios
from .stage4_decision import decide_stage4
from .stage4_live import EXPECTED_RUN_COUNT, Stage4Schedule, Stage4ScheduledRun
from .stage4_outcomes import (
    EXECUTION_COMMITMENT_SCHEMA_VERSION,
    PROVIDER_FAILURE,
    SCHEMA_FAILURE,
    Stage4ExecutionCommitments,
    Stage4ProviderCallAudit,
    Stage4RunArtifactCommitment,
    Stage4RunFailure,
    Stage4TraceRecord,
    convert_stage4_outcomes,
)
from .stage4_runtime import (
    AMBIENT_STAGE1_API_KEY_ENV,
    AMBIENT_STAGE1_PROVENANCE_KEY_ENV,
    DEFAULT_AUTHORITY_RECEIPT,
    DEFAULT_BUDGET_LEDGER,
    DEFAULT_FREEZE_MANIFEST,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_SCHEDULE_MANIFEST,
    FROZEN_MODEL_IDS,
    STAGE4_API_KEY_ENV,
    STAGE4_PROVENANCE_KEY_ENV,
    Stage4PreflightError,
    Stage4RunBinding,
    build_stage4_run_bindings,
    load_stage4_freeze_manifest,
    load_stage4_schedule_manifest,
    run_stage4_preflight,
    stage4_run_bindings_sha256,
    _git_environment,
)


EXECUTION_SCHEMA_VERSION = "stage4-confirmatory-execution-v1"
AUTHORITY_SCHEMA_VERSION = "stage4-confirmatory-authority-v1"
EVENT_SCHEMA_VERSION = "stage4-confirmatory-execution-event-v1"
ARCHIVE_SCHEMA_VERSION = "stage4-confirmatory-private-archive-v1"
ARCHIVED_AUTHORITY_RECEIPT_NAME = "authority_receipt.json"
STAGE4_BUDGET_PHASE = "stage_4_confirmatory"
STAGE4_PROVENANCE_KEY_ID_ENV = "MAS_SAFETY_STAGE4_PROVENANCE_KEY_ID"
AMBIENT_STAGE1_PROVENANCE_KEY_ID_ENV = "MAS_SAFETY_PROVENANCE_KEY_ID"

_FORBIDDEN_TRANSPORT_ENV = (
    "OPENAI_ADMIN_KEY",
    "OPENAI_BASE_URL",
    "OPENAI_CUSTOM_HEADERS",
    "OPENAI_ORG_ID",
    "OPENAI_PROJECT",
    "OPENAI_PROJECT_ID",
    "OPENAI_WEBHOOK_SECRET",
)
_FORBIDDEN_PYTHON_STARTUP_ENV = frozenset(
    {
        "PYTHONBREAKPOINT",
        "PYTHONCASEOK",
        "PYTHONEXECUTABLE",
        "PYTHONHASHSEED",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONNOUSERSITE",
        "PYTHONOPTIMIZE",
        "PYTHONPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONSAFEPATH",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "PYTHONWARNINGS",
        "__PYVENV_LAUNCHER__",
    }
)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_GIT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_MODEL_DIR = re.compile(r"[A-Za-z0-9._-]+")
_SAFE_PUBLIC_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_SAFE_PUBLIC_ATTESTATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/()\-]{0,127}")
_FORBIDDEN_PUBLIC_VALUE_PREFIXES = ("sk-", "bearer-", "secret-")


class Stage4ExecutionError(Stage4PreflightError):
    """A redaction-safe production boundary failure."""


@dataclass(frozen=True, slots=True)
class _Stage4Secrets:
    api_key: str = field(repr=False)
    credential_id: str
    credential_fingerprint_sha256: str
    provenance_key: bytes = field(repr=False)
    provenance_key_id: str
    provenance_fingerprint_sha256: str


@dataclass(frozen=True, slots=True)
class _ExecutionInputs:
    repository: Path
    manifest: dict[str, Any]
    schedule: Stage4Schedule
    bindings: tuple[Stage4RunBinding, ...]
    scenarios: tuple[Scenario, ...]
    freeze_commit_sha: str
    freeze_tag_object_sha: str
    freeze_manifest_sha256: str
    schedule_file_sha256: str
    preflight_snapshot_sha256: str
    protocol_sha256: str
    ceiling_nano_usd: int
    output_path: Path
    authority_path: Path
    ledger_path: Path
    encrypted_storage_attestation: str
    immutable_archive_attestation: str
    potential_request_commitments: tuple["_PotentialRequestCommitment", ...]


@dataclass(frozen=True, slots=True)
class _PotentialRequestCommitment:
    call_index: int
    sequence_index: int
    scheduled_run_id: str
    pair_id: str
    model_id: str
    role_index: int
    role: str
    prompt_sha256: str
    canonical_request_sha256: str
    canonical_request_utf8_bytes: int


BackendFactory = Callable[
    [str, Path, LiveBudgetLedger, str],
    AgentBackend,
]


class _AppendOnlyEventLog:
    """Small durable hash-chained checkpoint log for crash-visible progress."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.sequence = 0
        self.previous_sha256: str | None = None

    def append(self, event: str, payload: Mapping[str, object]) -> str:
        self.sequence += 1
        row: dict[str, object] = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "sequence": self.sequence,
            "recorded_at_utc": _utc_now(),
            "previous_event_sha256": self.previous_sha256,
            "event": event,
            **dict(payload),
        }
        canonical = _canonical_json_bytes(row)
        event_sha256 = hashlib.sha256(canonical).hexdigest()
        row["event_sha256"] = event_sha256
        _append_private_jsonl(self.path, row, create=self.sequence == 1)
        self.previous_sha256 = event_sha256
        return event_sha256


class _LedgerEvidence:
    """Incremental independent rehasher for the append-only budget ledger."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.offset = 0
        self.file_identity: tuple[int, int] | None = None
        self.raw_sha256 = hashlib.sha256()
        self.sequence = 0
        self.previous_sha256: str | None = None
        self.events_by_sequence: dict[int, dict[str, object]] = {}
        self.events_by_hash: dict[str, dict[str, object]] = {}
        self.terminal_by_reservation: dict[str, dict[str, object]] = {}
        self.represented_reservations: set[str] = set()

    def refresh(self) -> None:
        try:
            with self.path.open("rb") as handle:
                stat_result = os.fstat(handle.fileno())
                identity = (stat_result.st_dev, stat_result.st_ino)
                if self.file_identity is None:
                    self.file_identity = identity
                elif identity != self.file_identity:
                    raise Stage4ExecutionError(
                        "stage4_budget_ledger_file_identity_changed"
                    )
                if stat_result.st_size < self.offset:
                    raise Stage4ExecutionError("stage4_budget_ledger_truncated")
                handle.seek(self.offset)
                chunk = handle.read()
                next_offset = handle.tell()
        except Stage4ExecutionError:
            raise
        except OSError as exc:
            raise Stage4ExecutionError("stage4_budget_ledger_unreadable") from exc
        if not chunk:
            return
        if not chunk.endswith(b"\n"):
            raise Stage4ExecutionError("stage4_budget_ledger_partial_event")
        for raw_line in chunk.splitlines():
            try:
                event = json.loads(raw_line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise Stage4ExecutionError("stage4_budget_ledger_invalid_json") from exc
            if not isinstance(event, dict):
                raise Stage4ExecutionError("stage4_budget_ledger_invalid_event")
            supplied = event.get("event_sha256")
            unhashed = {key: value for key, value in event.items() if key != "event_sha256"}
            recomputed = hashlib.sha256(_canonical_json_bytes(unhashed)).hexdigest()
            sequence = event.get("sequence")
            if (
                type(sequence) is not int
                or sequence != self.sequence + 1
                or supplied != recomputed
                or event.get("previous_event_sha256") != self.previous_sha256
                or recomputed in self.events_by_hash
            ):
                raise Stage4ExecutionError("stage4_budget_ledger_hash_chain_invalid")
            self.sequence = sequence
            self.previous_sha256 = recomputed
            self.events_by_sequence[sequence] = event
            self.events_by_hash[recomputed] = event
            if event.get("event") in {
                "reservation_settled",
                "reservation_forfeited",
                "reservation_cancelled",
            }:
                reservation_id = event.get("reservation_id")
                if (
                    not isinstance(reservation_id, str)
                    or reservation_id in self.terminal_by_reservation
                ):
                    raise Stage4ExecutionError("stage4_budget_terminal_event_duplicate")
                self.terminal_by_reservation[reservation_id] = event
        self.raw_sha256.update(chunk)
        self.offset = next_offset

    def bind_provider_attempt(
        self,
        *,
        reservation: Mapping[str, object],
        terminal: Mapping[str, object],
    ) -> tuple[str, str, str]:
        self.refresh()
        reservation_id = reservation.get("reservation_id")
        event_sequence = reservation.get("event_sequence")
        if not isinstance(reservation_id, str) or type(event_sequence) is not int:
            raise Stage4ExecutionError("stage4_budget_reservation_link_invalid")
        held = self.events_by_sequence.get(event_sequence)
        if held is None or held.get("event") != "reservation_held":
            raise Stage4ExecutionError("stage4_budget_reservation_event_missing")
        for key, value in reservation.items():
            if held.get(key) != value:
                raise Stage4ExecutionError("stage4_budget_reservation_event_mismatch")
        if held.get("phase") != STAGE4_BUDGET_PHASE:
            raise Stage4ExecutionError("stage4_budget_phase_mismatch")
        terminal_sha = terminal.get("event_sha256")
        actual_terminal = (
            self.events_by_hash.get(terminal_sha)
            if isinstance(terminal_sha, str)
            else None
        )
        if actual_terminal is None or actual_terminal != dict(terminal):
            raise Stage4ExecutionError("stage4_budget_terminal_event_mismatch")
        if (
            actual_terminal.get("reservation_id") != reservation_id
            or actual_terminal.get("event")
            not in {"reservation_settled", "reservation_forfeited"}
            or actual_terminal.get("phase") != STAGE4_BUDGET_PHASE
        ):
            raise Stage4ExecutionError("stage4_budget_terminal_disposition_invalid")
        held_sha = held.get("event_sha256")
        if not isinstance(held_sha, str) or not isinstance(terminal_sha, str):
            raise Stage4ExecutionError("stage4_budget_event_hash_missing")
        if reservation_id in self.represented_reservations:
            raise Stage4ExecutionError("stage4_budget_reservation_reused")
        self.represented_reservations.add(reservation_id)
        return reservation_id, held_sha, terminal_sha

    def bind_pre_provider_cancellation(
        self,
        *,
        reservation: Mapping[str, object],
    ) -> tuple[str, str, str]:
        """Bind a durable request record to a verified no-call cancellation."""

        self.refresh()
        reservation_id = reservation.get("reservation_id")
        event_sequence = reservation.get("event_sequence")
        if not isinstance(reservation_id, str) or type(event_sequence) is not int:
            raise Stage4ExecutionError("stage4_budget_reservation_link_invalid")
        held = self.events_by_sequence.get(event_sequence)
        if held is None or held.get("event") != "reservation_held":
            raise Stage4ExecutionError("stage4_budget_reservation_event_missing")
        for key, value in reservation.items():
            if held.get(key) != value:
                raise Stage4ExecutionError("stage4_budget_reservation_event_mismatch")
        cancelled = self.terminal_by_reservation.get(reservation_id)
        if (
            held.get("phase") != STAGE4_BUDGET_PHASE
            or reservation.get("phase") != STAGE4_BUDGET_PHASE
            or cancelled is None
            or cancelled.get("event") != "reservation_cancelled"
            or cancelled.get("phase") != STAGE4_BUDGET_PHASE
            or cancelled.get("model_id") != reservation.get("model_id")
            or cancelled.get("call_stem") != reservation.get("call_stem")
            or cancelled.get("request_sha256") != reservation.get("request_sha256")
            or cancelled.get("settled_nano_usd") != 0
            or cancelled.get("released_nano_usd")
            != reservation.get("reserved_nano_usd")
            or cancelled.get("disposition")
            != "trusted_provider_boundary_failed_before_sdk_invocation"
        ):
            raise Stage4ExecutionError("stage4_budget_precall_cancellation_invalid")
        held_sha = held.get("event_sha256")
        cancelled_sha = cancelled.get("event_sha256")
        if not isinstance(held_sha, str) or not isinstance(cancelled_sha, str):
            raise Stage4ExecutionError("stage4_budget_event_hash_missing")
        return reservation_id, held_sha, cancelled_sha

    def assert_complete_bijection(self) -> None:
        self.refresh()
        provider_terminals = {
            reservation_id
            for reservation_id, event in self.terminal_by_reservation.items()
            if event.get("event") in {"reservation_settled", "reservation_forfeited"}
            and event.get("phase") == STAGE4_BUDGET_PHASE
        }
        if provider_terminals != self.represented_reservations:
            raise Stage4ExecutionError("stage4_raw_ledger_attempt_bijection_failed")

    def assert_matches_terminal_audit(self, audit: Mapping[str, object]) -> None:
        """Require the terminal auditor to have read this exact ledger snapshot."""

        self.refresh()
        if (
            type(audit.get("event_count")) is not int
            or audit.get("event_count") != self.sequence
            or audit.get("last_event_sha256") != self.previous_sha256
            or audit.get("ledger_file_sha256") != self.raw_sha256.hexdigest()
        ):
            raise Stage4ExecutionError("stage4_terminal_budget_evidence_mismatch")


def run_stage4_execution(
    *,
    repository_root: str | Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Execute exactly one final, fully frozen Stage 4 batch.

    This public surface has deliberately no override parameters.  A failed
    preflight raises a redaction-safe error before any directory, ledger,
    authority receipt, SDK client, or provider call can exist.
    """

    env = os.environ if environment is None else environment
    # The optional mapping is a provider-free test seam, not permission to hide
    # ambient startup state from the real production process.
    _assert_stage4_execution_process_boundary(os.environ)
    if env is not os.environ:
        _assert_stage4_execution_process_boundary(env)
    repository = (
        Path(repository_root).resolve()
        if repository_root is not None
        else Path.cwd().resolve()
    )
    preflight = run_stage4_preflight(
        repository_root=repository,
        environment=env,
    )
    if preflight.get("pass") is not True:
        raise Stage4ExecutionError("stage4_execution_preflight_failed")
    inputs = _prepare_execution_inputs(repository, preflight)
    _assert_loaded_package_matches_frozen_repository(inputs)
    secrets = _validate_stage4_secrets(inputs.manifest, env)
    # Re-run the provider-free boundary after loading credentials and compare
    # its exact nonsecret snapshot.  This closes the preflight-to-reload gap;
    # the same snapshot is checked once more immediately before authority.
    fresh_preflight = run_stage4_preflight(
        repository_root=repository,
        environment=env,
    )
    if (
        fresh_preflight.get("pass") is not True
        or fresh_preflight.get("preflight_snapshot_sha256")
        != inputs.preflight_snapshot_sha256
    ):
        raise Stage4ExecutionError("stage4_preflight_snapshot_changed")
    fresh_inputs = _prepare_execution_inputs(repository, fresh_preflight)
    if (
        fresh_inputs.freeze_manifest_sha256 != inputs.freeze_manifest_sha256
        or fresh_inputs.schedule_file_sha256 != inputs.schedule_file_sha256
        or fresh_inputs.freeze_commit_sha != inputs.freeze_commit_sha
    ):
        raise Stage4ExecutionError("stage4_preflight_loaded_inputs_changed")
    _assert_loaded_package_matches_frozen_repository(fresh_inputs)
    fresh_secrets = _validate_stage4_secrets(fresh_inputs.manifest, env)
    return _execute_stage4(fresh_inputs, fresh_secrets, _production_backend_factory)


def _assert_stage4_execution_process_boundary(
    environment: Mapping[str, str],
) -> None:
    """Require an isolated, non-editable installation before secret access.

    ``-I`` alone is insufficient when an editable-install ``.pth`` file adds
    the repository source tree during interpreter startup.  Production must
    also use ``-B`` and a cache-free wheel install provisioned before secrets
    enter the process.  Every effective import path must remain confined to
    interpreter-owned roots.  The standard-library zip placeholder is the sole
    permitted nonexistent path.
    """

    if sys.flags.isolated != 1:
        raise Stage4ExecutionError("stage4_isolated_execution_required")
    if sys.flags.dont_write_bytecode != 1:
        raise Stage4ExecutionError("stage4_bytecode_cache_disable_required")
    if any(name in environment for name in _FORBIDDEN_PYTHON_STARTUP_ENV) or any(
        isinstance(name, str)
        and (name.startswith("PYTHON") or name == "__PYVENV_LAUNCHER__")
        for name in environment
    ):
        raise Stage4ExecutionError("stage4_python_startup_environment_forbidden")

    configured = sysconfig.get_paths()
    try:
        install_roots = tuple(
            dict.fromkeys(
                Path(configured[name]).resolve(strict=True)
                for name in ("purelib", "platlib")
            )
        )
        trusted_roots = tuple(
            dict.fromkeys(
                Path(configured[name]).resolve(strict=True)
                for name in ("stdlib", "platstdlib", "purelib", "platlib")
            )
        )
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise Stage4ExecutionError("stage4_trusted_install_roots_invalid") from exc

    stdlib = Path(configured["stdlib"]).resolve()
    standard_zip = (
        stdlib.parent / f"python{sys.version_info.major}{sys.version_info.minor}.zip"
    ).resolve()
    for entry in sys.path:
        if not isinstance(entry, str) or not entry:
            raise Stage4ExecutionError("stage4_untrusted_import_path")
        candidate = Path(entry).resolve()
        if candidate == standard_zip:
            continue
        if not any(_path_is_within(candidate, root) for root in trusted_roots):
            raise Stage4ExecutionError("stage4_untrusted_import_path")

    loaded_source = Path(__file__).resolve(strict=True)
    if not any(_path_is_within(loaded_source, root) for root in install_roots):
        raise Stage4ExecutionError("stage4_trusted_noneditable_install_required")
    package_root = loaded_source.parent

    def reject_walk_error(exc: OSError) -> None:
        raise Stage4ExecutionError("stage4_loaded_package_origin_invalid") from exc

    for current, directory_names, file_names in os.walk(
        package_root,
        followlinks=False,
        onerror=reject_walk_error,
    ):
        current_path = Path(current)
        if "__pycache__" in directory_names or any(
            name.endswith((".pyc", ".pyo")) for name in file_names
        ):
            raise Stage4ExecutionError("stage4_project_bytecode_cache_forbidden")
        if any((current_path / name).is_symlink() for name in directory_names):
            raise Stage4ExecutionError("stage4_loaded_package_origin_invalid")
    main_module = sys.modules.get("__main__")
    main_origin = getattr(main_module, "__file__", None)
    if not isinstance(main_origin, str):
        raise Stage4ExecutionError("stage4_canonical_module_entrypoint_required")
    try:
        resolved_main = Path(main_origin).resolve(strict=True)
    except OSError as exc:
        raise Stage4ExecutionError("stage4_canonical_module_entrypoint_required") from exc
    if resolved_main != (package_root / "__main__.py").resolve(strict=True):
        raise Stage4ExecutionError("stage4_canonical_module_entrypoint_required")
    for name, module in tuple(sys.modules.items()):
        if name != "mas_safety" and not name.startswith("mas_safety."):
            continue
        origin = getattr(module, "__file__", None)
        if isinstance(origin, str):
            try:
                candidate = Path(origin).resolve(strict=True)
            except OSError as exc:
                raise Stage4ExecutionError(
                    "stage4_loaded_package_origin_invalid"
                ) from exc
            if not _path_is_within(candidate, package_root):
                raise Stage4ExecutionError("stage4_loaded_package_origin_invalid")
        locations = getattr(module, "__path__", None)
        if locations is not None:
            try:
                resolved_locations = tuple(
                    Path(value).resolve(strict=True) for value in locations
                )
            except (OSError, TypeError, ValueError) as exc:
                raise Stage4ExecutionError(
                    "stage4_loaded_package_origin_invalid"
                ) from exc
            if not resolved_locations or any(
                not _path_is_within(value, package_root) for value in resolved_locations
            ):
                raise Stage4ExecutionError("stage4_loaded_package_origin_invalid")


def _assert_loaded_package_matches_frozen_repository(
    inputs: _ExecutionInputs,
) -> None:
    """Bind every imported project source byte to the frozen checkout."""

    package_root = Path(__file__).resolve(strict=True).parent
    tracked = inputs.manifest.get("tracked_artifact_sha256")
    if not isinstance(tracked, dict):
        raise Stage4ExecutionError("stage4_loaded_package_freeze_binding_invalid")
    seen: set[str] = set()
    for name, module in tuple(sys.modules.items()):
        if (
            name != "mas_safety"
            and not name.startswith("mas_safety.")
            and name != "__main__"
        ):
            continue
        origin = getattr(module, "__file__", None)
        if not isinstance(origin, str):
            raise Stage4ExecutionError("stage4_loaded_package_freeze_binding_invalid")
        installed_path = Path(origin).resolve(strict=True)
        if installed_path.suffix in {".pyc", ".pyo"}:
            try:
                installed_path = Path(
                    importlib.util.source_from_cache(str(installed_path))
                ).resolve(strict=True)
            except (OSError, ValueError, NotImplementedError) as exc:
                raise Stage4ExecutionError(
                    "stage4_loaded_package_freeze_binding_invalid"
                ) from exc
        try:
            relative = installed_path.relative_to(package_root)
        except ValueError as exc:
            raise Stage4ExecutionError(
                "stage4_loaded_package_freeze_binding_invalid"
            ) from exc
        if name == "__main__" and relative != Path("__main__.py"):
            raise Stage4ExecutionError("stage4_canonical_module_entrypoint_required")
        repository_relative = (Path("src") / "mas_safety" / relative).as_posix()
        expected = tracked.get(repository_relative)
        repository_path = inputs.repository / repository_relative
        if (
            not _is_sha256(expected)
            or repository_relative in seen
            or not repository_path.is_file()
            or _sha256_file(installed_path) != expected
            or _sha256_file(repository_path) != expected
        ):
            raise Stage4ExecutionError("stage4_loaded_package_freeze_binding_invalid")
        seen.add(repository_relative)


def _run_stage4_execution_for_test(
    inputs: _ExecutionInputs,
    secrets: _Stage4Secrets,
    *,
    backend_factory: BackendFactory,
    stop_after_runs: int | None = None,
) -> dict[str, Any]:
    """Private no-network seam for focused executor tests only."""

    if stop_after_runs is not None and (
        type(stop_after_runs) is not int or stop_after_runs < 1
    ):
        raise ValueError("stop_after_runs must be a positive exact integer")
    return _execute_stage4(
        inputs,
        secrets,
        backend_factory,
        injected_test_backend=True,
        stop_after_runs=stop_after_runs,
    )


def _prepare_execution_inputs(
    repository: Path,
    preflight: Mapping[str, object],
) -> _ExecutionInputs:
    manifest_path = repository / DEFAULT_FREEZE_MANIFEST
    manifest = load_stage4_freeze_manifest(manifest_path)
    if manifest.get("freeze_status") != "frozen_executable":
        raise Stage4ExecutionError("stage4_freeze_status_not_executable")
    resolved_commit = preflight.get("resolved_freeze_commit_sha")
    if not isinstance(resolved_commit, str) or _GIT_ID.fullmatch(resolved_commit) is None:
        raise Stage4ExecutionError("stage4_freeze_commit_unresolved")
    schedule = load_stage4_schedule_manifest(repository / DEFAULT_SCHEDULE_MANIFEST)
    schedule_file_sha256 = _sha256_file(repository / DEFAULT_SCHEDULE_MANIFEST)
    snapshot = preflight.get("preflight_snapshot")
    snapshot_sha256 = preflight.get("preflight_snapshot_sha256")
    if (
        not isinstance(snapshot, dict)
        or not _is_sha256(snapshot_sha256)
        or _semantic_sha256(snapshot) != snapshot_sha256
        or snapshot.get("freeze_manifest_file_sha256")
        != _sha256_file(manifest_path)
        or snapshot.get("schedule_file_sha256") != schedule_file_sha256
        or snapshot.get("tracked_artifact_map_sha256")
        != _semantic_sha256(manifest.get("tracked_artifact_sha256"))
        or snapshot.get("stage3_binding_sha256")
        != _semantic_sha256(manifest.get("stage3_binding"))
        or snapshot.get("repository_binding_sha256")
        != _semantic_sha256(manifest.get("repository_binding"))
        or not isinstance(snapshot.get("freeze_tag_object_sha"), str)
        or re.fullmatch(r"[0-9a-f]{40}", str(snapshot["freeze_tag_object_sha"]))
        is None
        or snapshot.get("resolved_freeze_commit_sha") != resolved_commit
    ):
        raise Stage4ExecutionError("stage4_preflight_snapshot_binding_invalid")
    runtime = _mapping(manifest, "runtime_binding")
    batch_id = runtime.get("batch_id")
    if not isinstance(batch_id, str):
        raise Stage4ExecutionError("stage4_batch_id_invalid")
    bindings = build_stage4_run_bindings(schedule, batch_id=batch_id)
    if runtime.get("runspec_mapping_sha256") != stage4_run_bindings_sha256(bindings):
        raise Stage4ExecutionError("stage4_runspec_mapping_hash_mismatch")
    if schedule.model_ids != FROZEN_MODEL_IDS or len(bindings) != EXPECTED_RUN_COUNT:
        raise Stage4ExecutionError("stage4_execution_matrix_mismatch")

    scenario_dir = repository / "scenarios" / "confirmatory"
    scenarios = tuple(load_scenarios(scenario_dir))
    if {item.scenario_id for item in scenarios} != {
        item.scenario_id for item in schedule.workflows
    }:
        raise Stage4ExecutionError("stage4_scenario_set_mismatch")
    potential_request_commitments = _load_potential_request_commitments(
        repository,
        manifest,
        schedule,
    )

    storage = _mapping(manifest, "storage_authority")
    budget = _mapping(manifest, "budget_authority")
    tracked = _mapping(manifest, "tracked_artifact_sha256")
    output_relative = storage.get("execution_output_path")
    authority_relative = storage.get("one_shot_authority_path")
    ledger_relative = budget.get("ledger_path")
    ceiling = budget.get("authorized_ceiling_nano_usd")
    attestation = storage.get("encrypted_at_rest_attestation")
    immutable_attestation = storage.get("immutable_archive_attestation")
    protocol_sha256 = tracked.get("protocols/v0.4-stage4-confirmatory.md")
    if (
        output_relative != DEFAULT_OUTPUT_DIR.as_posix()
        or authority_relative != DEFAULT_AUTHORITY_RECEIPT.as_posix()
        or ledger_relative != DEFAULT_BUDGET_LEDGER.as_posix()
        or type(ceiling) is not int
        or ceiling <= 0
        or not isinstance(attestation, str)
        or not _is_safe_public_attestation(attestation)
        or not isinstance(immutable_attestation, str)
        or not _is_safe_public_attestation(immutable_attestation)
        or not _is_sha256(protocol_sha256)
    ):
        raise Stage4ExecutionError("stage4_manifest_execution_authority_invalid")
    return _ExecutionInputs(
        repository=repository,
        manifest=manifest,
        schedule=schedule,
        bindings=bindings,
        scenarios=scenarios,
        freeze_commit_sha=resolved_commit,
        freeze_tag_object_sha=str(snapshot["freeze_tag_object_sha"]),
        freeze_manifest_sha256=_sha256_file(manifest_path),
        schedule_file_sha256=schedule_file_sha256,
        preflight_snapshot_sha256=str(snapshot_sha256),
        protocol_sha256=str(protocol_sha256),
        ceiling_nano_usd=ceiling,
        output_path=repository / DEFAULT_OUTPUT_DIR,
        authority_path=repository / DEFAULT_AUTHORITY_RECEIPT,
        ledger_path=repository / DEFAULT_BUDGET_LEDGER,
        encrypted_storage_attestation=attestation,
        immutable_archive_attestation=immutable_attestation,
        potential_request_commitments=potential_request_commitments,
    )


def _load_potential_request_commitments(
    repository: Path,
    manifest: Mapping[str, object],
    schedule: Stage4Schedule,
) -> tuple[_PotentialRequestCommitment, ...]:
    prompt_contract = _mapping(manifest, "prompt_contract")
    path = repository / "manifests" / "stage4_prompt_commitments.json"
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise Stage4ExecutionError("stage4_prompt_commitments_invalid") from exc
    if not isinstance(value, dict):
        raise Stage4ExecutionError("stage4_prompt_commitments_not_object")
    supplied_semantic_sha = value.get("commitments_sha256")
    semantic_payload = {
        key: child for key, child in value.items() if key != "commitments_sha256"
    }
    if (
        value.get("schema_version")
        != "stage4-exact-potential-request-commitments-v1"
        or value.get("schedule_hash") != schedule.schedule_hash
        or value.get("batch_id") != "stage4-v0.4-confirmatory"
        or value.get("call_count") != 3_072
        or value.get("contains_prompt_or_request_bodies") is not False
        or value.get("binds_all_potential_provider_requests") is not True
        or supplied_semantic_sha != _semantic_sha256(semantic_payload)
        or supplied_semantic_sha
        != prompt_contract.get("potential_request_commitments_sha256")
        or _sha256_file(path)
        != prompt_contract.get("potential_request_commitments_file_sha256")
    ):
        raise Stage4ExecutionError("stage4_prompt_commitment_binding_mismatch")
    calls = value.get("calls")
    if not isinstance(calls, list) or len(calls) != 3_072:
        raise Stage4ExecutionError("stage4_prompt_commitment_count_mismatch")
    roles = tuple(role.value for role in PIPELINE_ROLES)
    result: list[_PotentialRequestCommitment] = []
    expected_fields = {
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
    for expected_call_index, raw in enumerate(calls):
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise Stage4ExecutionError("stage4_prompt_commitment_row_invalid")
        try:
            row = _PotentialRequestCommitment(**raw)
        except TypeError as exc:
            raise Stage4ExecutionError("stage4_prompt_commitment_row_invalid") from exc
        if (
            type(row.call_index) is not int
            or row.call_index != expected_call_index
            or type(row.sequence_index) is not int
            or not 0 <= row.sequence_index < EXPECTED_RUN_COUNT
            or type(row.role_index) is not int
            or row.role_index not in {1, 2, 3, 4}
            or row.role != roles[row.role_index - 1]
            or row.call_index != row.sequence_index * 4 + row.role_index - 1
            or not _is_sha256(row.prompt_sha256)
            or not _is_sha256(row.canonical_request_sha256)
            or type(row.canonical_request_utf8_bytes) is not int
            or not 0 < row.canonical_request_utf8_bytes <= 32_768
        ):
            raise Stage4ExecutionError("stage4_prompt_commitment_row_semantics_invalid")
        scheduled = schedule.runs[row.sequence_index]
        if (
            row.scheduled_run_id != scheduled.run_id
            or row.pair_id != scheduled.pair_id
            or row.model_id != scheduled.model_id
        ):
            raise Stage4ExecutionError("stage4_prompt_commitment_schedule_mismatch")
        result.append(row)
    return tuple(result)

def _validate_stage4_secrets(
    manifest: Mapping[str, object],
    environment: Mapping[str, str],
) -> _Stage4Secrets:
    forbidden = {
        AMBIENT_STAGE1_API_KEY_ENV,
        AMBIENT_STAGE1_PROVENANCE_KEY_ENV,
        AMBIENT_STAGE1_PROVENANCE_KEY_ID_ENV,
        *_FORBIDDEN_TRANSPORT_ENV,
    }
    if any(name in environment for name in forbidden) or any(
        isinstance(name, str) and name.startswith("OPENAI_")
        for name in environment
    ):
        raise Stage4ExecutionError("stage4_ambient_provider_or_stage1_env_forbidden")

    credential = _mapping(manifest, "credential_boundary")
    api_key = environment.get(STAGE4_API_KEY_ENV)
    if (
        not isinstance(api_key, str)
        or not api_key
        or api_key != api_key.strip()
    ):
        raise Stage4ExecutionError("stage4_dedicated_credential_missing")
    credential_fingerprint = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    expected_credential_fingerprint = credential.get("credential_fingerprint_sha256")
    credential_id = credential.get("credential_id")
    if (
        not _is_sha256(expected_credential_fingerprint)
        or not isinstance(credential_id, str)
        or not _is_safe_public_identifier(credential_id)
        or not hmac.compare_digest(
            credential_fingerprint,
            str(expected_credential_fingerprint),
        )
    ):
        raise Stage4ExecutionError("stage4_dedicated_credential_identity_mismatch")

    provenance = _mapping(manifest, "provenance_boundary")
    encoded_key = environment.get(STAGE4_PROVENANCE_KEY_ENV)
    key_id = environment.get(STAGE4_PROVENANCE_KEY_ID_ENV)
    if not isinstance(encoded_key, str) or not encoded_key:
        raise Stage4ExecutionError("stage4_provenance_key_missing")
    try:
        provenance_key = base64.b64decode(encoded_key, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise Stage4ExecutionError("stage4_provenance_key_invalid_base64") from exc
    if (
        len(provenance_key) < 32
        or hmac.compare_digest(provenance_key, DEVELOPMENT_SIGNING_KEY)
        or not isinstance(key_id, str)
        or not _is_safe_public_identifier(key_id)
        or key_id == DEVELOPMENT_KEY_ID
    ):
        raise Stage4ExecutionError("stage4_provenance_identity_invalid")
    provenance_fingerprint = hashlib.sha256(provenance_key).hexdigest()
    expected_key_id = provenance.get("key_id")
    expected_fingerprint = provenance.get("key_fingerprint_sha256")
    if (
        key_id != expected_key_id
        or not _is_sha256(expected_fingerprint)
        or not hmac.compare_digest(provenance_fingerprint, str(expected_fingerprint))
    ):
        raise Stage4ExecutionError("stage4_provenance_identity_mismatch")
    return _Stage4Secrets(
        api_key=api_key,
        credential_id=credential_id,
        credential_fingerprint_sha256=credential_fingerprint,
        provenance_key=provenance_key,
        provenance_key_id=key_id,
        provenance_fingerprint_sha256=provenance_fingerprint,
    )


def _execute_stage4(
    inputs: _ExecutionInputs,
    secrets: _Stage4Secrets,
    backend_factory: BackendFactory,
    *,
    injected_test_backend: bool = False,
    stop_after_runs: int | None = None,
) -> dict[str, Any]:
    output_created = False
    authority_consumed = False
    ledger: LiveBudgetLedger | None = None
    ledger_evidence: _LedgerEvidence | None = None
    backends: dict[str, AgentBackend] = {}
    event_log: _AppendOnlyEventLog | None = None
    records: list[Stage4TraceRecord | Stage4RunFailure] = []
    abort_code: str | None = None
    decision_value: str | None = None
    provider_call_count = 0
    attempted_scheduled_run_count = 0

    try:
        if not injected_test_backend:
            _assert_execution_inputs_fresh(inputs)
        _create_private_output_directory(inputs.output_path)
        output_created = True
        event_log = _AppendOnlyEventLog(inputs.output_path / "execution_events.jsonl")
        event_log.append(
            "execution_started_incomplete",
            {
                "freeze_commit_sha": inputs.freeze_commit_sha,
                "freeze_manifest_sha256": inputs.freeze_manifest_sha256,
                "schedule_hash": inputs.schedule.schedule_hash,
                "expected_scheduled_runs": EXPECTED_RUN_COUNT,
                "authorized_ceiling_nano_usd": inputs.ceiling_nano_usd,
                "encrypted_storage_attestation_sha256": hashlib.sha256(
                    inputs.encrypted_storage_attestation.encode("utf-8")
                ).hexdigest(),
                "immutable_archive_attestation_sha256": hashlib.sha256(
                    inputs.immutable_archive_attestation.encode("utf-8")
                ).hexdigest(),
                "injected_test_backend": injected_test_backend,
            },
        )
        _write_exclusive_json(
            inputs.output_path / "execution_started.json",
            {
                "schema_version": EXECUTION_SCHEMA_VERSION,
                "status": "INCOMPLETE",
                "freeze_commit_sha": inputs.freeze_commit_sha,
                "freeze_manifest_sha256": inputs.freeze_manifest_sha256,
                "schedule_hash": inputs.schedule.schedule_hash,
                "batch_id": inputs.bindings[0].run_spec.batch_id,
                "provider_calls_at_creation": 0,
                "injected_test_backend": injected_test_backend,
                "encrypted_storage_attestation_sha256": hashlib.sha256(
                    inputs.encrypted_storage_attestation.encode("utf-8")
                ).hexdigest(),
                "immutable_archive_attestation_sha256": hashlib.sha256(
                    inputs.immutable_archive_attestation.encode("utf-8")
                ).hexdigest(),
            },
        )

        if not injected_test_backend:
            _assert_execution_inputs_fresh(inputs)
        authority_sha256, authority_bytes = _consume_authority(inputs, secrets)
        authority_consumed = True
        _write_exclusive_bytes(
            inputs.output_path / ARCHIVED_AUTHORITY_RECEIPT_NAME,
            authority_bytes,
        )
        event_log.append(
            "one_shot_authority_consumed",
            {"authority_receipt_sha256": authority_sha256},
        )

        ledger = LiveBudgetLedger(
            inputs.ledger_path,
            ceiling_nano_usd=inputs.ceiling_nano_usd,
        )
        ledger_evidence = _LedgerEvidence(inputs.ledger_path)
        ledger_evidence.refresh()
        event_log.append(
            "budget_ledger_initialized",
            {
                "ledger_initial_event_sha256": ledger_evidence.previous_sha256,
                "ceiling_nano_usd": inputs.ceiling_nano_usd,
            },
        )

        for model_id in inputs.schedule.model_ids:
            raw_dir = inputs.output_path / "raw" / _model_directory_name(model_id)
            backend = backend_factory(model_id, raw_dir, ledger, secrets.api_key)
            if injected_test_backend:
                configuration = getattr(backend, "configuration", {})
                if not isinstance(configuration, dict) or (
                    configuration.get("test_only_no_external_io") is not True
                ):
                    raise Stage4ExecutionError("stage4_test_backend_not_offline_marked")
            _assert_backend_contract(
                backend,
                model_id=model_id,
                injected_test_backend=injected_test_backend,
            )
            backends[model_id] = backend
        if tuple(backends) != inputs.schedule.model_ids:
            raise Stage4ExecutionError("stage4_backend_model_order_mismatch")
        event_log.append(
            "provider_clients_constructed",
            {"model_ids": list(inputs.schedule.model_ids)},
        )

        commitments = _build_execution_commitments(inputs, secrets, backends)
        _write_exclusive_json(
            inputs.output_path / "execution_commitments.json",
            asdict(commitments),
        )
        event_log.append(
            "execution_commitments_frozen",
            {"execution_commitments_sha256": commitments.commitments_sha256},
        )

        runners = {
            model_id: ExperimentRunner(
                inputs.scenarios,
                backend,
                provenance_signing_key=secrets.provenance_key,
                provenance_key_id=secrets.provenance_key_id,
            )
            for model_id, backend in backends.items()
        }
        model_run_order = {model_id: 0 for model_id in inputs.schedule.model_ids}
        model_call_order = {model_id: 0 for model_id in inputs.schedule.model_ids}
        observed_stems = {model_id: set() for model_id in inputs.schedule.model_ids}
        potential_commitment_index = {
            (item.sequence_index, item.role_index, item.model_id): item
            for item in inputs.potential_request_commitments
        }
        if len(potential_commitment_index) != 3_072:
            raise Stage4ExecutionError("stage4_prompt_commitment_index_not_unique")

        for scheduled, binding in zip(inputs.schedule.runs, inputs.bindings, strict=True):
            if stop_after_runs is not None and len(records) >= stop_after_runs:
                abort_code = "stage4_test_requested_early_stop"
                break
            model_id = binding.model_id
            backend = backends[model_id]
            model_run_order[model_id] += 1
            metadata = _run_metadata(
                scheduled,
                binding,
                model_workflow_run_order=model_run_order[model_id],
                protocol_commit_sha=inputs.freeze_commit_sha,
                protocol_sha256=inputs.protocol_sha256,
            )
            setter = getattr(backend, "set_run_metadata", None)
            if not callable(setter):
                raise Stage4ExecutionError("stage4_backend_metadata_binding_missing")
            setter(metadata)
            event_log.append(
                "scheduled_run_started",
                {
                    "sequence_index": scheduled.sequence_index,
                    "scheduled_run_id": scheduled.run_id,
                    "model_id": model_id,
                    "model_workflow_run_order": model_run_order[model_id],
                },
            )
            trace: RunTrace | None = None
            failure: Exception | None = None
            try:
                trace = runners[model_id].run(binding.run_spec)
            except Exception as exc:  # noqa: BLE001 - classified without messages
                failure = exc

            # Count durable terminal provider evidence before the strict
            # raw/ledger audit.  Request records alone are not attempts: they
            # are written before network I/O.  A typed post-call archive error
            # supplies the only allowed terminal-evidence exception.
            current_raw_dir = Path(getattr(backend, "raw_log_dir", ""))
            current_request_stems = {
                path.name.removesuffix(".request.json")
                for path in current_raw_dir.glob("*.request.json")
            }
            new_request_stems = current_request_stems - observed_stems[model_id]
            current_result_stems = {
                path.name.removesuffix(suffix)
                for suffix in (".response.json", ".error.json")
                for path in current_raw_dir.glob(f"*{suffix}")
            }
            new_result_stems = current_result_stems - observed_stems[model_id]
            if not new_result_stems.issubset(new_request_stems):
                raise Stage4ExecutionError("stage4_orphan_raw_result_record")
            evidenced_call_count = len(new_result_stems)
            if (
                failure is not None
                and getattr(failure, "provider_call_attempted", None) is True
            ):
                request_only_stems = new_request_stems - new_result_stems
                if len(request_only_stems) > 1 or (
                    not request_only_stems and not new_result_stems
                ):
                    raise Stage4ExecutionError(
                        "stage4_typed_provider_attempt_checkpoint_mismatch"
                    )
                evidenced_call_count += len(request_only_stems)
            provider_call_count += evidenced_call_count
            if evidenced_call_count:
                attempted_scheduled_run_count += 1
            calls, new_stems = _audit_new_provider_calls(
                raw_dir=current_raw_dir,
                prior_stems=observed_stems[model_id],
                ledger_evidence=ledger_evidence,
                scheduled=scheduled,
                binding=binding,
                commitments=commitments,
                model_workflow_run_order=model_run_order[model_id],
                expected_first_call_order=model_call_order[model_id] + 1,
                trace=trace,
                untraced_failure=failure,
                potential_commitment_index=potential_commitment_index,
            )
            if new_stems != new_request_stems:
                raise Stage4ExecutionError("stage4_raw_request_set_changed_during_audit")
            observed_stems[model_id].update(new_stems)
            model_call_order[model_id] += len(calls)

            if trace is not None:
                _assert_deterministic_trace_run_id(
                    trace,
                    binding=binding,
                    backend=backend,
                    provenance_key_id=secrets.provenance_key_id,
                )
                record: Stage4TraceRecord | Stage4RunFailure = Stage4TraceRecord(
                    scheduled_run_id=scheduled.run_id,
                    trace=trace,
                    calls=calls,
                )
                _append_private_jsonl(
                    inputs.output_path / "traces.jsonl",
                    trace.to_dict(),
                )
                source_kind = "trace"
            elif calls:
                record = Stage4RunFailure(
                    scheduled_run_id=scheduled.run_id,
                    reason=(
                        SCHEMA_FAILURE
                        if calls[-1].decision_status
                        in {"schema_error", "unoffered_action"}
                        else PROVIDER_FAILURE
                    ),
                    calls=calls,
                )
                source_kind = "attempted_failure_record"
            else:
                record = None  # type: ignore[assignment]
                source_kind = "unattempted_abort"

            if record is not None:
                records.append(record)
                _append_private_jsonl(
                    inputs.output_path / "attempted_records.jsonl",
                    {
                        "scheduled_run_id": scheduled.run_id,
                        "source_kind": source_kind,
                        "source_sha256": (
                            hashlib.sha256(
                                _canonical_json_bytes(trace.to_dict())
                            ).hexdigest()
                            if trace is not None
                            else calls[-1].result_record_sha256
                        ),
                        "calls": [asdict(call) for call in calls],
                    },
                )
            event_log.append(
                "scheduled_run_retained" if record is not None else "scheduled_run_unattempted",
                {
                    "sequence_index": scheduled.sequence_index,
                    "scheduled_run_id": scheduled.run_id,
                    "source_kind": source_kind,
                    "attempted_provider_calls": len(calls),
                },
            )
            if failure is not None:
                if (
                    getattr(failure, "abort_live_batch", False) is not True
                    and isinstance(
                        failure,
                        (ProviderCallError, StructuredDecisionError),
                    )
                ):
                    continue
                abort_code = _abort_code(failure, attempted=bool(calls))
                break

        if abort_code is None and len(records) != EXPECTED_RUN_COUNT:
            abort_code = "stage4_execution_matrix_incomplete"
        if abort_code is None and injected_test_backend:
            # The private injection seam exists only to exercise failure and
            # evidence paths without network I/O.  It can never mint a
            # publishable COMPLETE archive, even when a full synthetic matrix
            # was supplied and all downstream analysis helpers were patched.
            abort_code = "stage4_test_backend_execution_nonpublishable"

        if abort_code is None:
            ledger.assert_quiescent()
            ledger_evidence.assert_complete_bijection()
            budget_audit = audit_budget_ledger(inputs.ledger_path)
            if budget_audit.get("pass") is not True:
                raise Stage4ExecutionError("stage4_terminal_budget_audit_failed")
            ledger_evidence.assert_matches_terminal_audit(budget_audit)
            outcome_set = convert_stage4_outcomes(
                inputs.schedule,
                records,
                run_bindings=inputs.bindings,
                commitments=commitments,
            )
            decision = decide_stage4(
                inputs.schedule,
                outcome_set,
                run_bindings=inputs.bindings,
                commitments=commitments,
            )
            _write_exclusive_json(
                inputs.output_path / "outcomes.json",
                outcome_set.to_dict(),
            )
            _write_exclusive_json(
                inputs.output_path / "decision.json",
                decision.to_dict(),
            )
            event_log.append(
                "provisional_confirmatory_decision_computed",
                {
                    "decision": decision.decision,
                    "scheduled_run_count": len(records),
                    "provider_call_count": provider_call_count,
                    "budget_ledger_sha256": budget_audit.get("ledger_file_sha256"),
                },
            )
            release_source_path = inputs.output_path / "private_release_source.json"
            _write_exclusive_json(
                release_source_path,
                {
                    "schema_version": "stage4-private-release-source-v1",
                    "private_only": True,
                    "public_release_emitted": False,
                    "freeze_commit_sha": inputs.freeze_commit_sha,
                    "freeze_manifest_sha256": inputs.freeze_manifest_sha256,
                    "schedule_hash": inputs.schedule.schedule_hash,
                    "schedule_file_sha256": _sha256_file(
                        inputs.repository / DEFAULT_SCHEDULE_MANIFEST
                    ),
                    "prompt_commitments_file_sha256": _sha256_file(
                        inputs.repository
                        / "manifests"
                        / "stage4_prompt_commitments.json"
                    ),
                    "run_bindings_sha256": commitments.run_bindings_sha256,
                    "execution_commitments_sha256": commitments.commitments_sha256,
                    "execution_commitments_file_sha256": _sha256_file(
                        inputs.output_path / "execution_commitments.json"
                    ),
                    "attempted_records_file_sha256": _sha256_file(
                        inputs.output_path / "attempted_records.jsonl"
                    ),
                    "traces_file_sha256": (
                        _sha256_file(inputs.output_path / "traces.jsonl")
                        if (inputs.output_path / "traces.jsonl").is_file()
                        else None
                    ),
                    "budget_ledger_file_sha256": budget_audit.get(
                        "ledger_file_sha256"
                    ),
                    "outcomes_file_sha256": _sha256_file(
                        inputs.output_path / "outcomes.json"
                    ),
                    "decision_file_sha256": _sha256_file(
                        inputs.output_path / "decision.json"
                    ),
                },
            )
            event_log.append(
                "private_release_source_committed",
                {"private_release_source_sha256": _sha256_file(release_source_path)},
            )
            # The private archive commitment is deliberately part of the
            # completion transaction.  A COMPLETE marker must never exist if
            # durable enumeration/hash commitment of the raw evidence failed.
            archive_manifest_sha256 = _write_private_archive_manifest(
                inputs.output_path,
                immutable_archive_attestation=inputs.immutable_archive_attestation,
            )
            _write_atomic_exclusive_json(
                inputs.output_path / "execution_complete.json",
                {
                    "schema_version": EXECUTION_SCHEMA_VERSION,
                    "status": "COMPLETE",
                    "decision": decision.decision,
                    "scheduled_run_count": len(records),
                    "provider_call_count": provider_call_count,
                    "outcomes_sha256": _sha256_file(
                        inputs.output_path / "outcomes.json"
                    ),
                    "decision_sha256": _sha256_file(
                        inputs.output_path / "decision.json"
                    ),
                    "private_archive_manifest_sha256": archive_manifest_sha256,
                    "private_release_source_sha256": _sha256_file(
                        release_source_path
                    ),
                    "terminal_event_sha256": event_log.previous_sha256,
                },
            )
            decision_value = decision.decision
        else:
            event_log.append(
                "execution_aborted_incomplete",
                {
                    "abort_code": abort_code,
                    "attempted_run_records": len(records),
                    "attempted_scheduled_runs": attempted_scheduled_run_count,
                    "provider_call_count": provider_call_count,
                    "unattempted_scheduled_runs": (
                        EXPECTED_RUN_COUNT - attempted_scheduled_run_count
                    ),
                },
            )
            _write_exclusive_json(
                inputs.output_path / "execution_incomplete.json",
                {
                    "schema_version": EXECUTION_SCHEMA_VERSION,
                    "status": "INCOMPLETE",
                    "abort_code": abort_code,
                    "attempted_run_records": len(records),
                    "attempted_scheduled_runs": attempted_scheduled_run_count,
                    "provider_call_count": provider_call_count,
                    "unattempted_scheduled_runs": (
                        EXPECTED_RUN_COUNT - attempted_scheduled_run_count
                    ),
                    "confirmatory_decision_emitted": False,
                    "terminal_event_sha256": event_log.previous_sha256,
                },
            )
            _write_private_archive_manifest(
                inputs.output_path,
                immutable_archive_attestation=inputs.immutable_archive_attestation,
            )
    except Exception as exc:  # noqa: BLE001 - redact all private boundary errors
        if abort_code is None:
            abort_code = (
                exc.code
                if isinstance(exc, Stage4ExecutionError)
                else "stage4_process_or_storage_abort"
            )
        completion_path = inputs.output_path / "execution_complete.json"
        if (
            output_created
            and event_log is not None
            and not os.path.lexists(completion_path)
        ):
            try:
                event_log.append(
                    "execution_aborted_incomplete",
                    {
                        "abort_code": abort_code,
                        "attempted_run_records": len(records),
                        "attempted_scheduled_runs": attempted_scheduled_run_count,
                        "provider_call_count": provider_call_count,
                        "unattempted_scheduled_runs": (
                            EXPECTED_RUN_COUNT - attempted_scheduled_run_count
                        ),
                    },
                )
                incomplete_path = inputs.output_path / "execution_incomplete.json"
                if not os.path.lexists(incomplete_path):
                    _write_exclusive_json(
                        incomplete_path,
                        {
                            "schema_version": EXECUTION_SCHEMA_VERSION,
                            "status": "INCOMPLETE",
                            "abort_code": abort_code,
                            "attempted_run_records": len(records),
                            "attempted_scheduled_runs": attempted_scheduled_run_count,
                            "provider_call_count": provider_call_count,
                            "unattempted_scheduled_runs": (
                                EXPECTED_RUN_COUNT - attempted_scheduled_run_count
                            ),
                            "confirmatory_decision_emitted": False,
                            "terminal_event_sha256": event_log.previous_sha256,
                        },
                    )
                archive_path = inputs.output_path / "private_archive_manifest.json"
                if not os.path.lexists(archive_path):
                    _write_private_archive_manifest(
                        inputs.output_path,
                        immutable_archive_attestation=(
                            inputs.immutable_archive_attestation
                        ),
                    )
            except Exception:  # noqa: BLE001 - the existing checkpoints remain evidence
                pass
        elif not authority_consumed:
            # No output/client/provider boundary was crossed; preserve a typed
            # precondition failure for the CLI without creating state.
            if isinstance(exc, Stage4ExecutionError):
                raise
            raise Stage4ExecutionError("stage4_private_output_creation_failed") from None
    finally:
        _close_backend_clients(tuple(backends.values()))

    completed = abort_code is None and decision_value in {"GO", "NO_GO"}
    return {
        "schema_version": EXECUTION_SCHEMA_VERSION,
        "pass": completed,
        "execution_status": "COMPLETE" if completed else "INCOMPLETE",
        "decision": decision_value if completed else None,
        "freeze_commit_sha": inputs.freeze_commit_sha,
        "schedule_hash": inputs.schedule.schedule_hash,
        "scheduled_run_records": len(records),
        "attempted_scheduled_runs": attempted_scheduled_run_count,
        "unattempted_scheduled_runs": (
            EXPECTED_RUN_COUNT - attempted_scheduled_run_count
        ),
        "provider_calls_made": provider_call_count,
        "provider_client_constructed": bool(backends),
        "authority_consumed": authority_consumed,
        "ledger_created": ledger is not None,
        "confirmatory_decision_emitted": completed,
        "abort_code": None if completed else abort_code,
    }


def _production_backend_factory(
    model_id: str,
    raw_log_dir: Path,
    ledger: LiveBudgetLedger,
    api_key: str,
) -> AgentBackend:
    return OpenAIResponsesBackend(
        model_id=model_id,
        raw_log_dir=raw_log_dir,
        api_key=api_key,
        max_output_tokens=FROZEN_MAX_OUTPUT_TOKENS,
        timeout_seconds=120.0,
        budget_ledger=ledger,
        budget_phase=STAGE4_BUDGET_PHASE,
    )


def _assert_execution_inputs_fresh(inputs: _ExecutionInputs) -> None:
    """Rehash every execution input immediately before consuming authority."""

    manifest_path = inputs.repository / DEFAULT_FREEZE_MANIFEST
    schedule_path = inputs.repository / DEFAULT_SCHEDULE_MANIFEST
    try:
        current_manifest = load_stage4_freeze_manifest(manifest_path)
    except Stage4PreflightError as exc:
        raise Stage4ExecutionError("stage4_execution_snapshot_manifest_changed") from exc
    if (
        _sha256_file(manifest_path) != inputs.freeze_manifest_sha256
        or _canonical_json_bytes(current_manifest)
        != _canonical_json_bytes(inputs.manifest)
        or _sha256_file(schedule_path) != inputs.schedule_file_sha256
    ):
        raise Stage4ExecutionError("stage4_execution_snapshot_changed")

    tracked = current_manifest.get("tracked_artifact_sha256")
    if not isinstance(tracked, dict):
        raise Stage4ExecutionError("stage4_execution_tracked_snapshot_invalid")
    for relative, expected_sha256 in tracked.items():
        if (
            not isinstance(relative, str)
            or not _is_sha256(expected_sha256)
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
        ):
            raise Stage4ExecutionError("stage4_execution_tracked_snapshot_invalid")
        path = inputs.repository / relative
        try:
            actual_sha256 = _sha256_file(path)
        except OSError as exc:
            raise Stage4ExecutionError(
                "stage4_execution_tracked_snapshot_unreadable"
            ) from exc
        if actual_sha256 != expected_sha256:
            raise Stage4ExecutionError("stage4_execution_tracked_snapshot_changed")

    scenario_package = current_manifest.get("scenario_package")
    ordered_scenarios = (
        scenario_package.get("ordered_scenarios")
        if isinstance(scenario_package, dict)
        else None
    )
    if not isinstance(ordered_scenarios, list):
        raise Stage4ExecutionError("stage4_execution_scenario_snapshot_invalid")
    for row in ordered_scenarios:
        if not isinstance(row, dict):
            raise Stage4ExecutionError("stage4_execution_scenario_snapshot_invalid")
        relative = row.get("path")
        expected_sha256 = row.get("file_sha256")
        if (
            not isinstance(relative, str)
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
            or not _is_sha256(expected_sha256)
        ):
            raise Stage4ExecutionError("stage4_execution_scenario_snapshot_invalid")
        try:
            actual_sha256 = _sha256_file(inputs.repository / relative)
        except OSError as exc:
            raise Stage4ExecutionError(
                "stage4_execution_scenario_snapshot_unreadable"
            ) from exc
        if actual_sha256 != expected_sha256:
            raise Stage4ExecutionError("stage4_execution_scenario_snapshot_changed")

    repository_binding = current_manifest.get("repository_binding")
    if not isinstance(repository_binding, dict):
        raise Stage4ExecutionError("stage4_execution_repository_snapshot_invalid")
    tag = repository_binding.get("planned_annotated_tag")
    if not isinstance(tag, str):
        raise Stage4ExecutionError("stage4_execution_repository_snapshot_invalid")
    tag_ref = f"refs/tags/{tag}"
    expected_tag_lines = [
        (
            "Stage 4 freeze manifest SHA-256: "
            f"{inputs.freeze_manifest_sha256}"
        ),
        (
            "Stage 4 ordered schedule file SHA-256: "
            f"{inputs.schedule_file_sha256}"
        ),
        (
            "Stage 3 selection seal SHA-256: "
            f"{current_manifest['stage3_binding']['selection_seal_sha256']}"
        ),
    ]
    tag_object = _git_bytes(inputs.repository, "cat-file", "tag", tag_ref)
    tag_header, separator, tag_message = tag_object.partition(b"\n\n")
    tag_header_lines = tag_header.splitlines()
    expected_tag_message = ("\n".join(expected_tag_lines) + "\n").encode("utf-8")
    if (
        _git_read(inputs.repository, "cat-file", "-t", tag_ref) != "tag"
        or _git_read(inputs.repository, "rev-parse", "--verify", tag_ref)
        != inputs.freeze_tag_object_sha
        or _git_read(inputs.repository, "rev-parse", f"{tag_ref}^{{commit}}")
        != inputs.freeze_commit_sha
        or _git_read(inputs.repository, "rev-parse", "HEAD")
        != inputs.freeze_commit_sha
        or _git_read(
            inputs.repository,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        )
        != ""
        or separator != b"\n\n"
        or f"object {inputs.freeze_commit_sha}".encode("ascii")
        not in tag_header_lines
        or b"type commit" not in tag_header_lines
        or f"tag {tag}".encode("utf-8") not in tag_header_lines
        or tag_message != expected_tag_message
    ):
        raise Stage4ExecutionError("stage4_execution_repository_snapshot_changed")


def _git_read(repository: Path, *arguments: str) -> str:
    output = _git_bytes(repository, *arguments)
    try:
        return output.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise Stage4ExecutionError("stage4_execution_git_snapshot_invalid") from exc


def _git_bytes(repository: Path, *arguments: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=repository,
            env=_git_environment(),
            check=False,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise Stage4ExecutionError("stage4_execution_git_snapshot_unreadable") from exc
    if completed.returncode != 0:
        raise Stage4ExecutionError("stage4_execution_git_snapshot_unreadable")
    return completed.stdout


def _assert_backend_contract(
    backend: AgentBackend,
    *,
    model_id: str,
    injected_test_backend: bool,
) -> None:
    configuration = getattr(backend, "configuration", None)
    if not isinstance(configuration, dict):
        raise Stage4ExecutionError("stage4_backend_configuration_invalid")
    if backend.model_id != model_id or backend.name != "openai_responses":
        raise Stage4ExecutionError("stage4_backend_identity_mismatch")
    expected = {
        "provider": "openai",
        "api": "responses",
        "base_url": OPENAI_OFFICIAL_BASE_URL,
        "requested_model": model_id,
        "pinned_sdk_version": PINNED_OPENAI_SDK_VERSION,
        "store": False,
        "service_tier": FROZEN_SERVICE_TIER,
        "reasoning_effort": FROZEN_REASONING_EFFORT,
        "max_output_tokens": FROZEN_MAX_OUTPUT_TOKENS,
        "timeout_seconds": 120.0,
        "temperature": "provider_default_unset",
        "top_p": "provider_default_unset",
        "tools": "none",
        "max_retries": 0,
        "http_follow_redirects": False,
        "http_trust_env": False,
        "hard_budget_enforced": True,
        "budget_phase": STAGE4_BUDGET_PHASE,
    }
    if any(configuration.get(key) != value for key, value in expected.items()):
        raise Stage4ExecutionError("stage4_backend_frozen_contract_mismatch")
    if not injected_test_backend and configuration.get("sdk_version") != PINNED_OPENAI_SDK_VERSION:
        raise Stage4ExecutionError("stage4_backend_sdk_version_mismatch")
    _reject_secret_shaped_configuration(configuration)


def _build_execution_commitments(
    inputs: _ExecutionInputs,
    secrets: _Stage4Secrets,
    backends: Mapping[str, AgentBackend],
) -> Stage4ExecutionCommitments:
    scenarios = {scenario.scenario_id: scenario for scenario in inputs.scenarios}
    artifacts: list[Stage4RunArtifactCommitment] = []
    for binding in inputs.bindings:
        scenario = scenarios[binding.run_spec.scenario_id]
        setup = build_mechanism_setup(
            scenario,
            binding.run_spec.mechanism,
            binding.run_spec.safety_variant,
            active=binding.run_spec.mechanism_active,
            architecture=binding.run_spec.architecture,
        )
        backend = backends[binding.model_id]
        configuration = dict(backend.configuration)
        component_hashes = component_hashes_for(
            scenario,
            setup.contexts,
            backend_name=backend.name,
            model_id=backend.model_id,
            backend_configuration=configuration,
            provenance_key_id=secrets.provenance_key_id,
        )
        artifacts.append(
            Stage4RunArtifactCommitment(
                scheduled_run_id=binding.scheduled_run_id,
                component_hashes_sha256=_semantic_sha256(component_hashes),
                backend_configuration_sha256=_semantic_sha256(configuration),
            )
        )
    return Stage4ExecutionCommitments(
        schema_version=EXECUTION_COMMITMENT_SCHEMA_VERSION,
        run_bindings_sha256=stage4_run_bindings_sha256(inputs.bindings),
        protocol_commit_sha=inputs.freeze_commit_sha,
        protocol_sha256=inputs.protocol_sha256,
        provenance_key_id=secrets.provenance_key_id,
        backend_name="openai_responses",
        run_artifacts=tuple(artifacts),
    )


def _run_metadata(
    scheduled: Stage4ScheduledRun,
    binding: Stage4RunBinding,
    *,
    model_workflow_run_order: int,
    protocol_commit_sha: str,
    protocol_sha256: str,
) -> dict[str, object]:
    spec = binding.run_spec
    return {
        "scheduled_workflow_run_order": scheduled.sequence_index + 1,
        "model_workflow_run_order": model_workflow_run_order,
        "repetition": scheduled.repetition,
        "condition_id": spec.condition_id,
        "invocation_id": spec.invocation_id,
        "scenario_id": spec.scenario_id,
        "mechanism": spec.mechanism.value,
        "mechanism_active": spec.mechanism_active,
        "safety_variant": spec.safety_variant.value,
        "protocol_commit_sha": protocol_commit_sha,
        "protocol_sha256": protocol_sha256,
        "batch_id": spec.batch_id,
    }


def _audit_new_provider_calls(
    *,
    raw_dir: Path,
    prior_stems: set[str],
    ledger_evidence: _LedgerEvidence,
    scheduled: Stage4ScheduledRun,
    binding: Stage4RunBinding,
    commitments: Stage4ExecutionCommitments,
    model_workflow_run_order: int,
    expected_first_call_order: int,
    trace: RunTrace | None,
    untraced_failure: Exception | None,
    potential_commitment_index: Mapping[
        tuple[int, int, str], _PotentialRequestCommitment
    ],
) -> tuple[tuple[Stage4ProviderCallAudit, ...], set[str]]:
    if not _private_directory_is_safe(raw_dir):
        raise Stage4ExecutionError("stage4_raw_archive_directory_unsafe")
    request_paths = {
        path.name.removesuffix(".request.json"): path
        for path in raw_dir.glob("*.request.json")
    }
    if prior_stems - set(request_paths):
        raise Stage4ExecutionError("stage4_raw_request_record_disappeared")
    new_stems = set(request_paths) - prior_stems
    pre_provider_abort = (
        trace is None
        and untraced_failure is not None
        and getattr(untraced_failure, "provider_call_attempted", None) is False
    )
    expected_calls = len(trace.steps) if trace is not None else None
    if expected_calls is not None and len(new_stems) != expected_calls:
        raise Stage4ExecutionError("stage4_trace_raw_call_count_mismatch")
    if trace is None and len(new_stems) > 4:
        raise Stage4ExecutionError("stage4_failed_run_raw_call_count_invalid")
    if pre_provider_abort and len(new_stems) > 1:
        raise Stage4ExecutionError("stage4_precall_raw_request_count_invalid")
    if not new_stems:
        return (), set()

    rows: list[tuple[int, str, dict[str, Any], Path]] = []
    for stem in new_stems:
        request_path = request_paths[stem]
        request_record = _read_private_json(request_path)
        call_order = request_record.get("provider_call_order")
        if type(call_order) is not int:
            raise Stage4ExecutionError("stage4_raw_provider_call_order_invalid")
        rows.append((call_order, stem, request_record, request_path))
    rows.sort(key=lambda item: item[0])
    observed_orders = [item[0] for item in rows]
    if observed_orders != list(
        range(expected_first_call_order, expected_first_call_order + len(rows))
    ):
        raise Stage4ExecutionError("stage4_raw_provider_call_order_noncontiguous")

    expected_metadata = _run_metadata(
        scheduled,
        binding,
        model_workflow_run_order=model_workflow_run_order,
        protocol_commit_sha=commitments.protocol_commit_sha,
        protocol_sha256=commitments.protocol_sha256,
    )
    audits: list[Stage4ProviderCallAudit] = []
    for step_index, (call_order, stem, request_record, request_path) in enumerate(
        rows, start=1
    ):
        if request_record.get("run_metadata") != expected_metadata:
            raise Stage4ExecutionError("stage4_raw_run_metadata_mismatch")
        if request_record.get("local_pairing_seed") != binding.run_spec.seed + step_index:
            raise Stage4ExecutionError("stage4_raw_local_pairing_seed_mismatch")
        provider_request = request_record.get("provider_request")
        if not isinstance(provider_request, dict):
            raise Stage4ExecutionError("stage4_raw_provider_request_invalid")
        canonical_request = _canonical_json_bytes(provider_request)
        request_sha256 = hashlib.sha256(canonical_request).hexdigest()
        potential = potential_commitment_index.get(
            (scheduled.sequence_index, step_index, binding.model_id)
        )
        if potential is None:
            raise Stage4ExecutionError("stage4_actual_call_has_no_prompt_commitment")
        if (
            request_record.get("provider_request_sha256") != request_sha256
            or request_record.get("prompt_sha256")
            != hashlib.sha256(str(provider_request.get("input", "")).encode("utf-8")).hexdigest()
            or hashlib.sha256(
                str(provider_request.get("instructions", "")).encode("utf-8")
            ).hexdigest()
            != INSTRUCTIONS_SHA256
            or len(canonical_request) > 32_768
            or potential.scheduled_run_id != scheduled.run_id
            or potential.pair_id != scheduled.pair_id
            or potential.role_index != step_index
            or potential.canonical_request_sha256 != request_sha256
            or potential.canonical_request_utf8_bytes != len(canonical_request)
            or potential.prompt_sha256 != request_record.get("prompt_sha256")
        ):
            raise Stage4ExecutionError("stage4_actual_request_commitment_mismatch")
        try:
            prompt_payload = json.loads(str(provider_request.get("input", "")))
        except json.JSONDecodeError as exc:
            raise Stage4ExecutionError("stage4_actual_prompt_invalid_json") from exc
        if (
            not isinstance(prompt_payload, dict)
            or prompt_payload.get("role") != potential.role
        ):
            raise Stage4ExecutionError("stage4_actual_prompt_role_mismatch")
        _assert_frozen_raw_request(provider_request, binding.model_id)
        request_record_sha256 = _sha256_file(request_path)

        reservation = request_record.get("budget_reservation")
        if not isinstance(reservation, dict):
            raise Stage4ExecutionError("stage4_raw_budget_link_missing")
        if (
            reservation.get("model_id") != binding.model_id
            or reservation.get("call_stem") != stem
            or reservation.get("request_sha256") != request_sha256
            or reservation.get("request_utf8_bytes") != len(canonical_request)
            or reservation.get("request_utf8_bytes")
            != potential.canonical_request_utf8_bytes
        ):
            raise Stage4ExecutionError("stage4_raw_budget_request_identity_mismatch")

        response_path = raw_dir / f"{stem}.response.json"
        error_path = raw_dir / f"{stem}.error.json"
        result_count = int(response_path.is_file()) + int(error_path.is_file())
        if pre_provider_abort:
            if result_count != 0:
                raise Stage4ExecutionError("stage4_precall_result_record_present")
            ledger_evidence.bind_pre_provider_cancellation(reservation=reservation)
            continue
        if result_count != 1:
            raise Stage4ExecutionError("stage4_raw_result_record_cardinality_invalid")
        result_path = response_path if response_path.is_file() else error_path
        result_kind = "response" if result_path is response_path else "error"
        result_record = _read_private_json(result_path)
        result_record_sha256 = _sha256_file(result_path)
        terminal = result_record.get("budget_event")
        if not isinstance(terminal, dict):
            raise Stage4ExecutionError("stage4_raw_budget_link_missing")
        reservation_id, held_sha, terminal_sha = ledger_evidence.bind_provider_attempt(
            reservation=reservation,
            terminal=terminal,
        )

        if trace is not None:
            step = trace.steps[step_index - 1]
            decision_status = step.decision_status
            metadata = step.provider_metadata
            if not isinstance(metadata, dict):
                raise Stage4ExecutionError("stage4_trace_provider_metadata_invalid")
            structured_valid = metadata.get("structured_output_valid") is True
            provider_native_refusal = (
                decision_status == "model_refusal" and not structured_valid
            )
            expected_trace_links = {
                "call_order": call_order,
                "retry_count": 0,
                "raw_log_record": stem,
                "provider_request_sha256": request_sha256,
                "request_record_sha256": request_record_sha256,
                "result_record_sha256": result_record_sha256,
                "result_record_kind": result_kind,
            }
            if any(metadata.get(key) != value for key, value in expected_trace_links.items()):
                raise Stage4ExecutionError("stage4_trace_raw_archive_link_mismatch")
        else:
            decision_status = (
                "accepted_execute"
                if step_index < len(rows)
                else (
                    str(getattr(untraced_failure, "decision_status", "provider_error"))
                    if isinstance(
                        untraced_failure,
                        (ProviderCallError, StructuredDecisionError),
                    )
                    else "provider_error"
                )
            )
            structured_valid = step_index < len(rows)
            provider_native_refusal = False
            if structured_valid and not _raw_response_is_structured_execute(result_record):
                raise Stage4ExecutionError("stage4_preabort_call_not_structured_execute")

        _audit_raw_result_semantics(
            result_kind=result_kind,
            result_record=result_record,
            terminal_event=terminal,
            model_id=binding.model_id,
            trace_step=(trace.steps[step_index - 1] if trace is not None else None),
            decision_status=decision_status,
            structured_output_valid=structured_valid,
            prompt_sha256=str(request_record.get("prompt_sha256")),
            provider_request_sha256=request_sha256,
            local_pairing_seed=binding.run_spec.seed + step_index,
            provider_request=provider_request,
        )

        audits.append(
            Stage4ProviderCallAudit(
                step_index=step_index,
                provider_call_order=call_order,
                decision_status=decision_status,
                structured_output_valid=structured_valid,
                requested_model=binding.model_id,
                local_pairing_seed=binding.run_spec.seed + step_index,
                scheduled_workflow_run_order=scheduled.sequence_index + 1,
                model_workflow_run_order=model_workflow_run_order,
                repetition=scheduled.repetition,
                condition_id=binding.run_spec.condition_id,
                invocation_id=binding.run_spec.invocation_id,
                scenario_id=binding.run_spec.scenario_id,
                mechanism=binding.run_spec.mechanism.value,
                mechanism_active=binding.run_spec.mechanism_active,
                safety_variant=binding.run_spec.safety_variant.value,
                protocol_commit_sha=commitments.protocol_commit_sha,
                protocol_sha256=commitments.protocol_sha256,
                batch_id=binding.run_spec.batch_id,
                raw_log_record=stem,
                provider_request_sha256=request_sha256,
                request_record_sha256=request_record_sha256,
                result_record_sha256=result_record_sha256,
                result_record_kind=result_kind,
                ledger_reservation_id=reservation_id,
                ledger_reservation_event_sha256=held_sha,
                ledger_terminal_event_sha256=terminal_sha,
                provider_native_refusal=provider_native_refusal,
                retry_count=0,
            )
        )
    return tuple(audits), new_stems


def _assert_frozen_raw_request(request: Mapping[str, object], model_id: str) -> None:
    exact = {
        "model": model_id,
        "store": False,
        "service_tier": FROZEN_SERVICE_TIER,
        "reasoning": {"effort": FROZEN_REASONING_EFFORT},
        "max_output_tokens": FROZEN_MAX_OUTPUT_TOKENS,
        "timeout": 120.0,
    }
    if any(request.get(key) != value for key, value in exact.items()):
        raise Stage4ExecutionError("stage4_raw_request_frozen_parameters_mismatch")
    if any(key in request for key in ("temperature", "top_p", "seed", "tools")):
        raise Stage4ExecutionError("stage4_raw_request_unfrozen_parameter_present")
    text = request.get("text")
    if not isinstance(text, dict):
        raise Stage4ExecutionError("stage4_raw_structured_output_contract_missing")
    output_format = text.get("format")
    if not isinstance(output_format, dict) or output_format.get("strict") is not True:
        raise Stage4ExecutionError("stage4_raw_structured_output_contract_invalid")


def _raw_response_is_structured_execute(result_record: Mapping[str, object]) -> bool:
    response = result_record.get("provider_response")
    if not isinstance(response, dict) or response.get("status") != "completed":
        return False
    output_text = _archived_output_text(response)
    if not output_text:
        return False
    try:
        payload = json.loads(output_text)
    except json.JSONDecodeError:
        return False
    return isinstance(payload, dict) and payload.get("decision") == "execute"


def _audit_raw_result_semantics(
    *,
    result_kind: str,
    result_record: Mapping[str, object],
    terminal_event: Mapping[str, object],
    model_id: str,
    trace_step: object | None,
    decision_status: str,
    structured_output_valid: bool,
    prompt_sha256: str,
    provider_request_sha256: str,
    local_pairing_seed: int,
    provider_request: Mapping[str, object],
) -> None:
    """Independently reconcile raw provider bytes, ledger, and trace telemetry."""

    terminal_kind = terminal_event.get("event")
    if result_kind == "error":
        archived_access_failure = _archived_provider_access_failure(
            result_record.get("provider_error_response")
        )
        if (
            terminal_kind != "reservation_forfeited"
            or result_record.get("budget_event") != dict(terminal_event)
            or not isinstance(result_record.get("error_type"), str)
            or trace_step is not None
            and (
                getattr(trace_step, "decision_status", None) != "provider_error"
                or getattr(trace_step, "token_usage", None)
                != {"input": 0, "output": 0}
            )
            or archived_access_failure and trace_step is not None
        ):
            raise Stage4ExecutionError("stage4_raw_error_ledger_trace_mismatch")
        if trace_step is not None:
            metadata = getattr(trace_step, "provider_metadata", None)
            if (
                not isinstance(metadata, dict)
                or metadata.get("status") != "transport_error"
                or metadata.get("requested_model") != model_id
                or metadata.get("prompt_sha256") != prompt_sha256
                or metadata.get("provider_request_sha256")
                != provider_request_sha256
                or metadata.get("local_pairing_seed") != local_pairing_seed
                or metadata.get("request_id")
                != result_record.get("transport_request_id")
            ):
                raise Stage4ExecutionError("stage4_raw_error_metadata_mismatch")
        return

    if result_kind != "response":
        raise Stage4ExecutionError("stage4_raw_result_kind_invalid")
    response = result_record.get("provider_response")
    if not isinstance(response, dict):
        raise Stage4ExecutionError("stage4_raw_response_payload_invalid")
    usage = _archived_usage(response)
    if terminal_kind == "reservation_settled":
        if (
            usage is None
            or terminal_event.get("input_tokens") != usage[0]
            or terminal_event.get("output_tokens") != usage[1]
        ):
            raise Stage4ExecutionError("stage4_raw_response_ledger_usage_mismatch")
    elif terminal_kind != "reservation_forfeited":
        raise Stage4ExecutionError("stage4_raw_response_ledger_terminal_invalid")
    if result_record.get("budget_event") != dict(terminal_event):
        raise Stage4ExecutionError("stage4_raw_response_budget_event_mismatch")

    status = response.get("status")
    resolved_model = response.get("model")
    service_tier = response.get("service_tier")
    if resolved_model != model_id or service_tier != FROZEN_SERVICE_TIER:
        raise Stage4ExecutionError("stage4_raw_response_frozen_contract_mismatch")

    output_text = _archived_output_text(response)
    refusal_text = _archived_refusal(response)
    parsed_output: object | None = None
    if output_text:
        try:
            parsed_output = json.loads(output_text)
        except json.JSONDecodeError:
            parsed_output = None

    if trace_step is None:
        # A fatal budget/contract abort has no StepTrace; raw bytes and the
        # ledger still have to reconcile.  Earlier calls in the same aborted
        # run must be exact successful execute decisions.
        if decision_status == "accepted_execute" and not (
            status == "completed"
            and isinstance(parsed_output, dict)
            and parsed_output.get("decision") == "execute"
        ):
            raise Stage4ExecutionError("stage4_preabort_response_decision_mismatch")
        return

    try:
        prompt_payload = json.loads(str(provider_request.get("input", "")))
    except json.JSONDecodeError as exc:
        raise Stage4ExecutionError("stage4_raw_prompt_decision_binding_invalid") from exc
    if not isinstance(prompt_payload, dict):
        raise Stage4ExecutionError("stage4_raw_prompt_decision_binding_invalid")

    metadata = getattr(trace_step, "provider_metadata", None)
    token_usage = getattr(trace_step, "token_usage", None)
    raw_model_output = getattr(trace_step, "raw_model_output", None)
    if (
        usage is None
        or token_usage != {"input": usage[0], "output": usage[1]}
        or not isinstance(metadata, dict)
        or metadata.get("requested_model") != model_id
        or metadata.get("resolved_response_model") != resolved_model
        or metadata.get("status") != status
        or metadata.get("response_id") != response.get("id")
        or metadata.get("created_at") != response.get("created_at")
        or metadata.get("system_fingerprint") != response.get("system_fingerprint")
        or metadata.get("request_id") != result_record.get("transport_request_id")
        or metadata.get("prompt_sha256") != prompt_sha256
        or metadata.get("provider_request_sha256") != provider_request_sha256
        or metadata.get("local_pairing_seed") != local_pairing_seed
        or metadata.get("structured_output_valid") is not structured_output_valid
    ):
        raise Stage4ExecutionError("stage4_raw_response_trace_telemetry_mismatch")

    if decision_status == "accepted_execute":
        expected_agent_decision = _expected_archived_agent_decision(
            parsed_output,
            prompt_payload,
        )
        valid_decision = (
            status == "completed"
            and isinstance(parsed_output, dict)
            and parsed_output.get("decision") == "execute"
            and raw_model_output == output_text
            and expected_agent_decision is not None
            and getattr(trace_step, "agent_decision", None)
            == expected_agent_decision
            and getattr(trace_step, "selected_action", None)
            == expected_agent_decision["action"]
        )
    elif decision_status == "model_escalation":
        expected_agent_decision = _expected_archived_agent_decision(
            parsed_output,
            prompt_payload,
        )
        valid_decision = (
            status == "completed"
            and isinstance(parsed_output, dict)
            and parsed_output.get("decision") == "escalate"
            and raw_model_output == output_text
            and expected_agent_decision is not None
            and getattr(trace_step, "agent_decision", None)
            == expected_agent_decision
            and getattr(trace_step, "selected_action", None) is None
        )
    elif decision_status == "model_refusal":
        expected_agent_decision = _expected_archived_agent_decision(
            parsed_output,
            prompt_payload,
        )
        valid_decision = (
            status == "completed"
            and (
                (
                    structured_output_valid
                    and isinstance(parsed_output, dict)
                    and parsed_output.get("decision") == "refuse"
                    and raw_model_output == output_text
                    and expected_agent_decision is not None
                    and getattr(trace_step, "agent_decision", None)
                    == expected_agent_decision
                )
                or (
                    not structured_output_valid
                    and isinstance(refusal_text, str)
                    and bool(refusal_text)
                    and raw_model_output == refusal_text
                    and getattr(trace_step, "agent_decision", None)
                    == {
                        "kind": "refuse",
                        "action": None,
                        "reason": refusal_text,
                        "missing_information": [],
                    }
                )
            )
            and getattr(trace_step, "selected_action", None) is None
        )
    elif decision_status == "provider_error":
        valid_decision = status != "completed"
    else:
        # Schema/capability failures retain the exact raw output but are not
        # allowed to masquerade as a successful structured decision.
        valid_decision = (
            decision_status in {"schema_error", "unoffered_action"}
            and status == "completed"
            and raw_model_output == (output_text or raw_model_output)
        )
    if not valid_decision:
        raise Stage4ExecutionError("stage4_raw_response_decision_trace_mismatch")

    offered = prompt_payload.get("offered_actions")
    candidate_id = prompt_payload.get("candidate_action_id")
    if not isinstance(offered, list):
        raise Stage4ExecutionError("stage4_raw_prompt_offered_actions_invalid")
    offered_payloads: list[dict[str, object]] = []
    candidate_payload: dict[str, object] | None = None
    for item in offered:
        if not isinstance(item, dict) or not isinstance(item.get("action_id"), str):
            raise Stage4ExecutionError("stage4_raw_prompt_offered_actions_invalid")
        action = {key: value for key, value in item.items() if key != "action_id"}
        offered_payloads.append(action)
        if item["action_id"] == candidate_id:
            candidate_payload = action
    if (
        candidate_payload is None
        or tuple(offered_payloads) != getattr(trace_step, "offered_actions", None)
        or candidate_payload != getattr(trace_step, "candidate_action", None)
    ):
        raise Stage4ExecutionError("stage4_raw_prompt_trace_action_set_mismatch")


def _expected_archived_agent_decision(
    payload: object,
    prompt_payload: Mapping[str, object],
) -> dict[str, object] | None:
    if not isinstance(payload, dict) or set(payload) != {
        "decision",
        "selected_action_id",
        "reason",
        "missing_information",
    }:
        return None
    decision = payload.get("decision")
    selected_action_id = payload.get("selected_action_id")
    reason = payload.get("reason")
    missing = payload.get("missing_information")
    if not isinstance(missing, list) or any(
        not isinstance(item, str) or not item.strip() for item in missing
    ):
        return None
    offered = prompt_payload.get("offered_actions")
    if not isinstance(offered, list):
        return None
    actions = {
        item["action_id"]: {
            key: value for key, value in item.items() if key != "action_id"
        }
        for item in offered
        if isinstance(item, dict) and isinstance(item.get("action_id"), str)
    }
    if len(actions) != len(offered):
        return None
    if decision == "execute":
        if (
            not isinstance(selected_action_id, str)
            or selected_action_id not in actions
            or reason is not None
            or missing
        ):
            return None
        return {
            "kind": "execute",
            "action": actions[selected_action_id],
            "reason": None,
            "missing_information": [],
        }
    if decision == "refuse":
        if (
            selected_action_id is not None
            or not isinstance(reason, str)
            or not reason.strip()
            or missing
        ):
            return None
        return {
            "kind": "refuse",
            "action": None,
            "reason": reason.strip(),
            "missing_information": [],
        }
    if decision == "escalate":
        if selected_action_id is not None or reason is not None or not missing:
            return None
        return {
            "kind": "escalate",
            "action": None,
            "reason": None,
            "missing_information": missing,
        }
    return None


def _archived_provider_access_failure(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    if value.get("status_code") in {401, 403, 404}:
        return True
    fatal_codes = {
        "authentication_error",
        "invalid_api_key",
        "insufficient_permissions",
        "model_not_found",
        "permission_denied",
    }
    return any(
        isinstance(candidate, str) and candidate in fatal_codes
        for item in _walk_archived_dicts(value.get("body"))
        for candidate in (item.get("code"), item.get("type"))
    )


def _archived_usage(response: Mapping[str, object]) -> tuple[int, int] | None:
    usage = response.get("usage")
    if not isinstance(usage, dict):
        return None
    input_tokens = usage.get("input_tokens")
    output_tokens = usage.get("output_tokens")
    if (
        type(input_tokens) is not int
        or input_tokens < 0
        or type(output_tokens) is not int
        or output_tokens < 0
    ):
        return None
    return input_tokens, output_tokens


def _archived_output_text(response: Mapping[str, object]) -> str:
    direct = response.get("output_text")
    if isinstance(direct, str) and direct:
        return direct
    for item in _walk_archived_dicts(response):
        if item.get("type") == "output_text" and isinstance(item.get("text"), str):
            return str(item["text"])
    return ""


def _archived_refusal(response: Mapping[str, object]) -> str | None:
    for item in _walk_archived_dicts(response):
        refusal = item.get("refusal")
        if item.get("type") == "refusal" and isinstance(refusal, str) and refusal:
            return refusal
    return None


def _walk_archived_dicts(value: object):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_archived_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_archived_dicts(child)


def _assert_deterministic_trace_run_id(
    trace: RunTrace,
    *,
    binding: Stage4RunBinding,
    backend: AgentBackend,
    provenance_key_id: str,
) -> None:
    spec = binding.run_spec
    payload = "|".join(
        (
            spec.condition_id,
            backend.name,
            backend.model_id,
            json.dumps(
                backend.configuration,
                sort_keys=True,
                separators=(",", ":"),
            ),
            provenance_key_id,
            spec.batch_id,
            spec.invocation_id,
            str(spec.seed),
        )
    )
    expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
    if trace.run_id != expected:
        raise Stage4ExecutionError("stage4_trace_run_id_mismatch")


def _consume_authority(
    inputs: _ExecutionInputs,
    secrets: _Stage4Secrets,
) -> tuple[str, bytes]:
    parent = inputs.authority_path.parent
    _ensure_private_directory(parent)
    payload = {
        "schema_version": AUTHORITY_SCHEMA_VERSION,
        "created_at_utc": _utc_now(),
        "scope": "one_exact_stage4_v0.4_confirmatory_batch",
        "freeze_commit_sha": inputs.freeze_commit_sha,
        "freeze_manifest_sha256": inputs.freeze_manifest_sha256,
        "schedule_hash": inputs.schedule.schedule_hash,
        "batch_id": inputs.bindings[0].run_spec.batch_id,
        "authorized_ceiling_nano_usd": inputs.ceiling_nano_usd,
        "credential_id": secrets.credential_id,
        "credential_fingerprint_sha256": secrets.credential_fingerprint_sha256,
        "provenance_key_id": secrets.provenance_key_id,
        "provenance_key_fingerprint_sha256": secrets.provenance_fingerprint_sha256,
        "output_path_sha256": hashlib.sha256(
            DEFAULT_OUTPUT_DIR.as_posix().encode("utf-8")
        ).hexdigest(),
        "encrypted_storage_attestation_sha256": hashlib.sha256(
            inputs.encrypted_storage_attestation.encode("utf-8")
        ).hexdigest(),
        "immutable_archive_attestation_sha256": hashlib.sha256(
            inputs.immutable_archive_attestation.encode("utf-8")
        ).hexdigest(),
        "rerun_under_same_authority": False,
        "contains_secret_material": False,
    }
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    serialized_bytes = serialized.encode("utf-8")
    _write_exclusive_bytes(inputs.authority_path, serialized_bytes)
    _fsync_directory(parent)
    return hashlib.sha256(serialized_bytes).hexdigest(), serialized_bytes


def _write_private_archive_manifest(
    output: Path,
    *,
    immutable_archive_attestation: str,
) -> str:
    archive_path = output / "private_archive_manifest.json"
    if os.path.lexists(archive_path):
        raise Stage4ExecutionError("stage4_private_archive_manifest_already_exists")
    files: list[dict[str, object]] = []
    coverage_exclusions = {
        "private_archive_manifest.json",
        "execution_complete.json",
    }
    for path in sorted(output.rglob("*")):
        if path == archive_path or not path.is_file():
            continue
        relative = path.relative_to(output).as_posix()
        if relative in coverage_exclusions:
            continue
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077:
            raise Stage4ExecutionError("stage4_private_archive_file_unsafe")
        files.append(
            {
                "path": relative,
                "sha256": _sha256_file(path),
                "bytes": info.st_size,
            }
        )
    payload: dict[str, object] = {
        "schema_version": ARCHIVE_SCHEMA_VERSION,
        "contains_raw_private_provider_material": True,
        "contains_credential_or_provenance_key_material": False,
        "immutable_archive_attestation": immutable_archive_attestation,
        "immutable_archive_attestation_sha256": hashlib.sha256(
            immutable_archive_attestation.encode("utf-8")
        ).hexdigest(),
        "completion_marker_policy": (
            "execution_complete_created_only_after_archive_commitment"
        ),
        "coverage_exclusions": sorted(coverage_exclusions),
        "file_count": len(files),
        "files": files,
    }
    payload["archive_commitment_sha256"] = _semantic_sha256(payload)
    _write_exclusive_json(archive_path, payload)
    return _sha256_file(archive_path)


def _create_private_output_directory(path: Path) -> None:
    if os.path.lexists(path):
        raise Stage4ExecutionError("stage4_output_already_exists")
    if not _private_directory_is_safe(path.parent):
        raise Stage4ExecutionError("stage4_private_output_parent_unsafe")
    try:
        os.mkdir(path, 0o700)
        path.chmod(0o700)
    except OSError as exc:
        raise Stage4ExecutionError("stage4_private_output_creation_failed") from exc
    if not _private_directory_is_safe(path, exact_mode=True):
        raise Stage4ExecutionError("stage4_private_output_permissions_unsafe")


def _ensure_private_directory(path: Path) -> None:
    if os.path.lexists(path):
        if not _private_directory_is_safe(path):
            raise Stage4ExecutionError("stage4_private_directory_unsafe")
        path.chmod(0o700)
        return
    if not _private_directory_is_safe(path.parent):
        raise Stage4ExecutionError("stage4_private_directory_parent_unsafe")
    try:
        os.mkdir(path, 0o700)
        path.chmod(0o700)
    except OSError as exc:
        raise Stage4ExecutionError("stage4_private_directory_creation_failed") from exc


def _private_directory_is_safe(path: Path, *, exact_mode: bool = False) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    mode = stat.S_IMODE(info.st_mode)
    return (
        stat.S_ISDIR(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_nlink >= 1
        and (mode == 0o700 if exact_mode else mode & 0o077 == 0)
    )


def _read_private_json(path: Path) -> dict[str, Any]:
    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            raise Stage4ExecutionError("stage4_private_record_permissions_unsafe")
        value = json.loads(path.read_text(encoding="utf-8"))
    except Stage4ExecutionError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Stage4ExecutionError("stage4_private_record_invalid") from exc
    if not isinstance(value, dict):
        raise Stage4ExecutionError("stage4_private_record_not_object")
    return value


def _write_exclusive_json(path: Path, payload: object) -> None:
    _write_exclusive_bytes(
        path,
        (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def _write_atomic_exclusive_json(path: Path, payload: object) -> None:
    """Publish a complete marker atomically without replacing any target."""

    content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    pending = path.parent.parent / ".stage4-confirmatory-completion.pending"
    _write_exclusive_bytes(pending, content)
    linked = False
    try:
        os.link(pending, path, follow_symlinks=False)
        linked = True
        _fsync_directory(path.parent)
    except OSError as exc:
        raise Stage4ExecutionError(
            "stage4_completion_marker_atomic_publish_failed"
        ) from exc
    finally:
        if linked:
            try:
                pending.unlink()
                _fsync_directory(path.parent)
            except OSError as exc:
                # A COMPLETE marker is valid only when its redundant pending
                # link is gone. Roll the target back and fail closed so the
                # outer transaction emits INCOMPLETE evidence instead.
                try:
                    path.unlink()
                    _fsync_directory(path.parent)
                except OSError:
                    pass
                try:
                    pending.unlink()
                    _fsync_directory(path.parent)
                except OSError:
                    pass
                raise Stage4ExecutionError(
                    "stage4_completion_marker_pending_cleanup_failed"
                ) from exc


def _write_exclusive_bytes(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise Stage4ExecutionError("stage4_private_record_exclusive_create_failed") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(0o600)
        _fsync_directory(path.parent)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _append_private_jsonl(
    path: Path,
    payload: object,
    *,
    create: bool = False,
) -> None:
    flags = os.O_WRONLY | (os.O_CREAT | os.O_EXCL if create else os.O_CREAT | os.O_APPEND)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise Stage4ExecutionError("stage4_private_checkpoint_open_failed") from exc
    try:
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(0o600)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _close_backend_clients(backends: Sequence[AgentBackend]) -> None:
    for backend in backends:
        client = getattr(backend, "_client", None)
        close = getattr(client, "close", None)
        if callable(close):
            try:
                close()
            except Exception:  # noqa: BLE001 - cleanup cannot change labels
                pass


def _abort_code(error: Exception, *, attempted: bool) -> str:
    if isinstance(error, ProviderAccessError):
        return "stage4_provider_access_abort"
    if isinstance(error, ProviderArchiveError):
        return (
            "stage4_private_archive_abort_after_attempt"
            if attempted
            else "stage4_private_archive_abort_before_attempt"
        )
    if isinstance(error, ProviderContractError):
        return "stage4_provider_contract_abort"
    if isinstance(error, (BudgetCeilingExceeded, BudgetAccountingError)):
        return "stage4_budget_abort_after_attempt" if attempted else "stage4_budget_abort"
    if isinstance(error, Stage4ExecutionError):
        return error.code
    return "stage4_process_abort_after_attempt" if attempted else "stage4_process_abort"


def _raw_response_output_text(response: Mapping[str, object]) -> str | None:
    value = response.get("output_text")
    if isinstance(value, str):
        return value
    output = response.get("output")
    if not isinstance(output, list):
        return None
    for item in output:
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []):
            if isinstance(content, dict) and isinstance(content.get("text"), str):
                return str(content["text"])
    return None


def _model_directory_name(model_id: str) -> str:
    if _MODEL_DIR.fullmatch(model_id) is None:
        raise Stage4ExecutionError("stage4_model_directory_name_unsafe")
    return model_id


def _reject_secret_shaped_configuration(value: object, *, key: str = "") -> None:
    if isinstance(value, dict):
        for child_key, child in value.items():
            lowered = str(child_key).lower()
            if lowered in {"api_key", "authorization", "credential", "secret"}:
                raise Stage4ExecutionError("stage4_backend_configuration_contains_secret")
            _reject_secret_shaped_configuration(child, key=lowered)
    elif isinstance(value, list):
        for child in value:
            _reject_secret_shaped_configuration(child, key=key)
    elif isinstance(value, str) and value.lower().startswith(
        (*_FORBIDDEN_PUBLIC_VALUE_PREFIXES, "bearer ")
    ):
        raise Stage4ExecutionError("stage4_backend_configuration_contains_secret")


def _mapping(value: Mapping[str, object], key: str) -> dict[str, Any]:
    child = value.get(key)
    if not isinstance(child, dict):
        raise Stage4ExecutionError(f"stage4_{key}_invalid")
    return dict(child)


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


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _is_safe_public_identifier(value: str) -> bool:
    return (
        _SAFE_PUBLIC_IDENTIFIER.fullmatch(value) is not None
        and not value.lower().startswith(_FORBIDDEN_PUBLIC_VALUE_PREFIXES)
    )


def _is_safe_public_attestation(value: str) -> bool:
    return (
        _SAFE_PUBLIC_ATTESTATION.fullmatch(value) is not None
        and not value.lower().startswith(_FORBIDDEN_PUBLIC_VALUE_PREFIXES)
    )


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


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


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
