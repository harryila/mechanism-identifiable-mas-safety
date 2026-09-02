from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import py_compile
import sys
from collections import Counter
from pathlib import Path
from types import ModuleType

import pytest

from mas_safety.live_backends import (
    DECISION_SCHEMA_SHA256,
    DECISION_SCHEMA_VERSION,
    INSTRUCTIONS_SHA256,
    PINNED_OPENAI_SDK_VERSION,
    PROMPT_VERSION,
    OpenAIResponsesBackend,
)
from mas_safety.live_budget import LiveBudgetLedger
from mas_safety.runner import ExperimentRunner
from mas_safety.scenarios import load_scenarios
from mas_safety.stage4_freeze import build_prompt_commitment_artifact
from mas_safety.stage4_runtime import (
    build_stage4_run_bindings,
    load_stage4_schedule_manifest,
    stage4_run_bindings_sha256,
)


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "build_stage4_release.py"
MODULE_SPEC = importlib.util.spec_from_file_location("build_stage4_release", MODULE_PATH)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
builder = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = builder
MODULE_SPEC.loader.exec_module(builder)


def _write_bytes(path: Path, raw: bytes, *, private: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(0o600 if private else 0o644)
    if private:
        current = path.parent
        while current.name and current != current.parent:
            current.chmod(0o700)
            if current.name.startswith("stage4-private"):
                break
            current = current.parent


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _write_json(path: Path, value: object, *, private: bool = True) -> None:
    _write_bytes(path, _json_bytes(value), private=private)


def _write_jsonl(path: Path, values: list[dict]) -> None:
    raw = b"".join(
        (json.dumps(value, sort_keys=True) + "\n").encode() for value in values
    )
    _write_bytes(path, raw)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _event_rows(
    schedule: dict,
    release_source_sha: str,
    decision: str,
    *,
    freeze: dict,
    freeze_sha256: str,
    freeze_commit_sha: str,
    authority_receipt_sha256: str,
    ledger_initial_sha256: str,
    ledger_file_sha256: str,
    execution_commitments_sha256: str,
) -> list[dict]:
    storage = freeze["storage_authority"]
    payloads: list[tuple[str, dict]] = [
        (
            "execution_started_incomplete",
            {
                "freeze_commit_sha": freeze_commit_sha,
                "freeze_manifest_sha256": freeze_sha256,
                "schedule_hash": schedule["schedule_hash"],
                "expected_scheduled_runs": 768,
                "authorized_ceiling_nano_usd": freeze["budget_authority"][
                    "authorized_ceiling_nano_usd"
                ],
                "encrypted_storage_attestation_sha256": hashlib.sha256(
                    storage["encrypted_at_rest_attestation"].encode()
                ).hexdigest(),
                "immutable_archive_attestation_sha256": hashlib.sha256(
                    storage["immutable_archive_attestation"].encode()
                ).hexdigest(),
                "injected_test_backend": False,
            },
        ),
        (
            "one_shot_authority_consumed",
            {"authority_receipt_sha256": authority_receipt_sha256},
        ),
        (
            "budget_ledger_initialized",
            {
                "ledger_initial_event_sha256": ledger_initial_sha256,
                "ceiling_nano_usd": freeze["budget_authority"][
                    "authorized_ceiling_nano_usd"
                ],
            },
        ),
        (
            "provider_clients_constructed",
            {"model_ids": schedule["model_ids"]},
        ),
        (
            "execution_commitments_frozen",
            {"execution_commitments_sha256": execution_commitments_sha256},
        ),
    ]
    model_orders: Counter[str] = Counter()
    for run in schedule["runs"]:
        model_orders[run["model_id"]] += 1
        payloads.extend(
            (
                (
                    "scheduled_run_started",
                    {
                        "sequence_index": run["sequence_index"],
                        "scheduled_run_id": run["run_id"],
                        "model_id": run["model_id"],
                        "model_workflow_run_order": model_orders[run["model_id"]],
                    },
                ),
                (
                    "scheduled_run_retained",
                    {
                        "sequence_index": run["sequence_index"],
                        "scheduled_run_id": run["run_id"],
                        "source_kind": "trace",
                        "attempted_provider_calls": 1,
                    },
                ),
            )
        )
    payloads.extend(
        (
            (
                "provisional_confirmatory_decision_computed",
                {
                    "decision": decision,
                    "scheduled_run_count": 768,
                    "provider_call_count": 768,
                    "budget_ledger_sha256": ledger_file_sha256,
                },
            ),
            (
                "private_release_source_committed",
                {"private_release_source_sha256": release_source_sha},
            ),
        )
    )
    rows: list[dict] = []
    previous = None
    for sequence, (kind, payload) in enumerate(payloads, start=1):
        row = {
            "schema_version": builder.EXECUTION_EVENT_SCHEMA_VERSION,
            "sequence": sequence,
            "recorded_at_utc": "2026-09-02T00:00:00+00:00",
            "previous_event_sha256": previous,
            "event": kind,
            **payload,
        }
        row["event_sha256"] = builder._semantic_sha256(row)
        previous = row["event_sha256"]
        rows.append(row)
    return rows


@pytest.fixture(scope="module")
def complete_private_archive(tmp_path_factory: pytest.TempPathFactory) -> dict:
    root = tmp_path_factory.mktemp("stage4-release-builder")
    schedule = builder.PUBLIC_VERIFIER.reconstruct_schedule()
    schedule_path = root / "manifests" / "stage4_schedule.json"
    prompt_path = root / "manifests" / "stage4_prompt_commitments.json"
    freeze_path = root / "manifests" / "stage4_freeze.json"
    _write_json(schedule_path, schedule, private=False)
    prompt_commitments = build_prompt_commitment_artifact(
        builder.ROOT, schedule_manifest=schedule
    )
    _write_json(prompt_path, prompt_commitments, private=False)
    ceiling = int(prompt_commitments["required_minimum_nano_usd"])
    attestation = "offline-test-operator-storage-attestation"
    batch_id = builder.PUBLIC_VERIFIER.EXPECTED_BATCH_ID
    schedule_object = load_stage4_schedule_manifest(schedule_path)
    binding_objects = build_stage4_run_bindings(
        schedule_object, batch_id=batch_id
    )
    bindings = [binding.hash_record() for binding in binding_objects]
    run_bindings_sha = stage4_run_bindings_sha256(binding_objects)
    protocol_commit = "f" * 40
    protocol_sha = "a" * 64
    provenance_key_id = "offline-test-key"
    credential_id = "offline-test-credential"
    credential_sha = "d" * 64
    provenance_sha = "e" * 64
    encrypted_attestation = "offline-test-encryption-operator-attestation"
    freeze = {
        "freeze_status": "frozen_executable",
        "budget_authority": {
            "authorized_ceiling_nano_usd": ceiling,
            "required_minimum_nano_usd": prompt_commitments[
                "required_minimum_nano_usd"
            ],
            "required_minimum_usd": prompt_commitments["required_minimum_usd"],
            "all_execute_maximum_cost_nano_usd": prompt_commitments[
                "all_execute_maximum_cost_nano_usd"
            ],
            "all_execute_maximum_cost_usd": prompt_commitments[
                "all_execute_maximum_cost_usd"
            ],
        },
        "storage_authority": {
            "execution_output_path": "outputs/private/stage4-v0.4-confirmatory",
            "encrypted_at_rest_attestation": encrypted_attestation,
            "immutable_archive_attestation": attestation,
        },
        "runtime_binding": {
            "batch_id": batch_id,
            "runspec_mapping_sha256": run_bindings_sha,
        },
        "prompt_contract": {
            "prompt_version": PROMPT_VERSION,
            "instructions_sha256": INSTRUCTIONS_SHA256,
            "decision_schema_version": DECISION_SCHEMA_VERSION,
            "decision_schema_sha256": DECISION_SCHEMA_SHA256,
            "potential_request_commitments_schema_version": prompt_commitments[
                "schema_version"
            ],
            "potential_request_commitments_sha256": prompt_commitments[
                "commitments_sha256"
            ],
            "potential_request_commitments_file_sha256": _sha(prompt_path),
            "potential_request_count": prompt_commitments["call_count"],
        },
        "provider_contract": {
            "provider": "openai",
            "api": "responses",
            "base_url": "https://api.openai.com/v1",
            "sdk_version": PINNED_OPENAI_SDK_VERSION,
            "request": {
                "reasoning_effort": "low",
                "max_output_tokens": 512,
                "service_tier": "default",
                "store": False,
                "timeout_seconds": 120,
                "sdk_max_retries": 0,
                "http_follow_redirects": False,
                "http_trust_env": False,
            },
        },
        "credential_boundary": {
            "credential_id": credential_id,
            "credential_fingerprint_sha256": credential_sha,
        },
        "provenance_boundary": {
            "key_id": provenance_key_id,
            "key_fingerprint_sha256": provenance_sha,
        },
        "tracked_artifact_sha256": {
            "protocols/v0.4-stage4-confirmatory.md": protocol_sha,
            **{
                path.relative_to(builder.ROOT).as_posix(): hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
                for path in (builder.ROOT / "src" / "mas_safety").rglob("*.py")
            },
        },
        "repository_binding": {
            "planned_annotated_tag": builder.PUBLIC_VERIFIER.FREEZE_TAG
        },
    }
    _write_json(freeze_path, freeze, private=False)

    archive = root / "stage4-private-archive"
    archive.mkdir(mode=0o700)
    freeze_sha = _sha(freeze_path)
    _write_json(
        archive / "execution_started.json",
        {
            "schema_version": builder.EXECUTION_SCHEMA_VERSION,
            "status": "INCOMPLETE",
            "freeze_commit_sha": protocol_commit,
            "freeze_manifest_sha256": freeze_sha,
            "schedule_hash": schedule["schedule_hash"],
            "batch_id": batch_id,
            "provider_calls_at_creation": 0,
            "injected_test_backend": False,
            "encrypted_storage_attestation_sha256": hashlib.sha256(
                encrypted_attestation.encode()
            ).hexdigest(),
            "immutable_archive_attestation_sha256": hashlib.sha256(
                attestation.encode()
            ).hexdigest(),
        },
    )
    authority_receipt = {
        "schema_version": builder.AUTHORITY_SCHEMA_VERSION,
        "created_at_utc": "2026-09-02T00:00:00+00:00",
        "scope": "one_exact_stage4_v0.4_confirmatory_batch",
        "freeze_commit_sha": protocol_commit,
        "freeze_manifest_sha256": freeze_sha,
        "schedule_hash": schedule["schedule_hash"],
        "batch_id": batch_id,
        "authorized_ceiling_nano_usd": ceiling,
        "credential_id": credential_id,
        "credential_fingerprint_sha256": credential_sha,
        "provenance_key_id": provenance_key_id,
        "provenance_key_fingerprint_sha256": provenance_sha,
        "output_path_sha256": hashlib.sha256(
            freeze["storage_authority"]["execution_output_path"].encode()
        ).hexdigest(),
        "encrypted_storage_attestation_sha256": hashlib.sha256(
            encrypted_attestation.encode()
        ).hexdigest(),
        "immutable_archive_attestation_sha256": hashlib.sha256(
            attestation.encode()
        ).hexdigest(),
        "rerun_under_same_authority": False,
        "contains_secret_material": False,
    }
    _write_json(
        archive / builder.ARCHIVED_AUTHORITY_RECEIPT_NAME,
        authority_receipt,
    )
    ledger = LiveBudgetLedger(
        archive / "budget_ledger.jsonl", ceiling_nano_usd=ceiling
    )

    class _FixtureResponsesClient:
        def __init__(self) -> None:
            self.responses = self
            self.count = 0

        def create(self, **request: object) -> dict:
            self.count += 1
            return {
                "id": f"fixture-response-{self.count:06d}",
                "request_id": f"fixture-request-{self.count:06d}",
                "model": request["model"],
                "service_tier": "default",
                "status": "completed",
                "created_at": 0,
                "system_fingerprint": "fixture-provider-free",
                "usage": {"input_tokens": 0, "output_tokens": 0},
                "output_text": "not-json",
            }

    backends = {
        model_id: OpenAIResponsesBackend(
            model_id=model_id,
            raw_log_dir=archive / "raw" / model_id,
            client=_FixtureResponsesClient(),
            sdk_version=PINNED_OPENAI_SDK_VERSION,
            budget_ledger=ledger,
            budget_phase=builder.STAGE4_BUDGET_PHASE,
        )
        for model_id in schedule["model_ids"]
    }
    (archive / "raw").chmod(0o700)
    for backend in backends.values():
        backend.raw_log_dir.chmod(0o700)
    scenarios = load_scenarios(builder.ROOT / "scenarios" / "confirmatory")
    runners = {
        model_id: ExperimentRunner(
            scenarios,
            backend,
            provenance_signing_key=b"fixture-provider-free-replay-key" * 2,
            provenance_key_id=provenance_key_id,
        )
        for model_id, backend in backends.items()
    }

    staged_calls: list[dict] = []
    model_order: Counter[str] = Counter()
    for run, binding_object, binding in zip(
        schedule["runs"], binding_objects, bindings, strict=True
    ):
        model_id = run["model_id"]
        model_order[model_id] += 1
        order = model_order[model_id]
        spec = binding_object.run_spec
        backends[model_id].set_run_metadata(
            {
                "scheduled_workflow_run_order": run["sequence_index"] + 1,
                "model_workflow_run_order": order,
                "repetition": run["repetition"],
                "condition_id": spec.condition_id,
                "invocation_id": spec.invocation_id,
                "scenario_id": spec.scenario_id,
                "mechanism": spec.mechanism.value,
                "mechanism_active": spec.mechanism_active,
                "safety_variant": spec.safety_variant.value,
                "protocol_commit_sha": protocol_commit,
                "protocol_sha256": protocol_sha,
                "batch_id": spec.batch_id,
            }
        )
        trace = runners[model_id].run(spec).to_dict()
        assert trace["status"] == "capability_failure"
        assert len(trace["steps"]) == 1
        metadata = trace["steps"][0]["provider_metadata"]
        stem = metadata["raw_log_record"]
        request_path = archive / "raw" / model_id / f"{stem}.request.json"
        result_path = archive / "raw" / model_id / f"{stem}.response.json"
        request_record = json.loads(request_path.read_text())
        result_record = json.loads(result_path.read_text())
        staged_calls.append(
            {
                "run": run,
                "binding": binding,
                "model_order": order,
                "stem": stem,
                "provider_request_sha": request_record["provider_request_sha256"],
                "request_sha": _sha(request_path),
                "result_sha": _sha(result_path),
                "reservation": request_record["budget_reservation"],
                "terminal": result_record["budget_event"],
                "trace": trace,
            }
        )

    ledger_rows = [
        json.loads(line)
        for line in (archive / "budget_ledger.jsonl").read_text().splitlines()
    ]
    held_by_sequence = {
        row["sequence"]: row
        for row in ledger_rows
        if row["event"] == "reservation_held"
    }
    run_artifacts = [
        {
            "scheduled_run_id": staged["run"]["run_id"],
            "component_hashes_sha256": builder._semantic_sha256(
                staged["trace"]["component_hashes"]
            ),
            "backend_configuration_sha256": builder._semantic_sha256(
                staged["trace"]["backend_configuration"]
            ),
        }
        for staged in staged_calls
    ]
    execution_commitments = {
        "schema_version": builder.EXECUTION_COMMITMENT_SCHEMA_VERSION,
        "run_bindings_sha256": run_bindings_sha,
        "protocol_commit_sha": protocol_commit,
        "protocol_sha256": protocol_sha,
        "provenance_key_id": provenance_key_id,
        "backend_name": "openai_responses",
        "run_artifacts": run_artifacts,
    }
    _write_json(archive / "execution_commitments.json", execution_commitments)
    execution_commitments_sha = builder._semantic_sha256(execution_commitments)
    attempted_records: list[dict] = []
    private_rows: list[dict] = []
    traces: list[dict] = []
    for staged, artifact in zip(staged_calls, run_artifacts, strict=True):
        run = staged["run"]
        binding = staged["binding"]
        spec = binding["run_spec"]
        reservation = staged["reservation"]
        held = held_by_sequence[reservation["event_sequence"]]
        trace = staged["trace"]
        provider_metadata = trace["steps"][0]["provider_metadata"]
        call = {
            "step_index": 1,
            "provider_call_order": staged["model_order"],
            "decision_status": trace["steps"][0]["decision_status"],
            "structured_output_valid": provider_metadata[
                "structured_output_valid"
            ],
            "requested_model": run["model_id"],
            "local_pairing_seed": spec["seed"] + 1,
            "scheduled_workflow_run_order": run["sequence_index"] + 1,
            "model_workflow_run_order": staged["model_order"],
            "repetition": run["repetition"],
            "condition_id": spec["condition_id"],
            "invocation_id": spec["invocation_id"],
            "scenario_id": run["scenario_id"],
            "mechanism": run["mechanism"],
            "mechanism_active": run["mechanism_on"],
            "safety_variant": run["safety_variant"],
            "protocol_commit_sha": protocol_commit,
            "protocol_sha256": protocol_sha,
            "batch_id": batch_id,
            "raw_log_record": staged["stem"],
            "provider_request_sha256": staged["provider_request_sha"],
            "request_record_sha256": staged["request_sha"],
            "result_record_sha256": staged["result_sha"],
            "result_record_kind": "response",
            "ledger_reservation_id": reservation["reservation_id"],
            "ledger_reservation_event_sha256": held["event_sha256"],
            "ledger_terminal_event_sha256": staged["terminal"]["event_sha256"],
            "provider_native_refusal": False,
            "retry_count": 0,
        }
        source_sha = builder._semantic_sha256(trace)
        traces.append(trace)
        attempted_records.append(
            {
                "scheduled_run_id": run["run_id"],
                "source_kind": "trace",
                "source_sha256": source_sha,
                "calls": [call],
            }
        )
        private_rows.append(
            {
                "sequence_index": run["sequence_index"],
                "run_id": run["run_id"],
                "pair_id": run["pair_id"],
                "scenario_id": run["scenario_id"],
                "domain": run["domain"],
                "mechanism": run["mechanism"],
                "mechanism_on": run["mechanism_on"],
                "safety_variant": run["safety_variant"],
                "repetition": run["repetition"],
                "model_id": run["model_id"],
                "seed": spec["seed"],
                "invocation_id": spec["invocation_id"],
                "batch_id": batch_id,
                "condition_id": spec["condition_id"],
                "scheduled_workflow_run_order": run["sequence_index"] + 1,
                "model_workflow_run_order": staged["model_order"],
                "local_lgh": 0,
                "safe_completion": 0,
                "run_completed": 0,
                "refusal": False,
                "escalation": False,
                "attempted_agent_calls": 1,
                "valid_structured_decisions": 0,
                "noncompletion_reason": "schema_error",
                "failure_reason": "schema_error",
                "source_kind": "trace",
                "source_record_commitment_sha256": source_sha,
                "call_audit_sha256": builder._semantic_sha256([call]),
                "component_hashes_sha256": artifact["component_hashes_sha256"],
                "backend_configuration_sha256": artifact[
                    "backend_configuration_sha256"
                ],
                "protocol_commit_sha": protocol_commit,
                "protocol_sha256": protocol_sha,
                "provenance_key_id": provenance_key_id,
                "backend_name": "openai_responses",
                "replacement_attempted": False,
            }
        )
    _write_jsonl(archive / "attempted_records.jsonl", attempted_records)
    _write_jsonl(archive / "traces.jsonl", traces)
    outcomes = {
        "schema_version": builder.PRIVATE_OUTCOME_SCHEMA_VERSION,
        "schedule_hash": schedule["schedule_hash"],
        "run_bindings_sha256": run_bindings_sha,
        "execution_commitments_sha256": execution_commitments_sha,
        "outcomes": private_rows,
    }
    _write_json(archive / "outcomes.json", outcomes)
    public_rows = [
        {name: row[name] for name in builder.PUBLIC_VERIFIER.OUTCOME_FIELDS}
        for row in private_rows
    ]
    expected_summary = builder.PUBLIC_VERIFIER.build_expected_summary(
        schedule, public_rows
    )
    decision = dict.fromkeys(builder.PRIVATE_DECISION_FIELDS)
    decision.update(
        {
            "schema_version": builder.PRIVATE_DECISION_SCHEMA_VERSION,
            "schedule_hash": schedule["schedule_hash"],
            "decision": expected_summary["decision"],
        }
    )
    _write_json(archive / "decision.json", decision)

    release_source = {
        "schema_version": builder.PRIVATE_RELEASE_SOURCE_SCHEMA_VERSION,
        "private_only": True,
        "public_release_emitted": False,
        "freeze_commit_sha": protocol_commit,
        "freeze_manifest_sha256": _sha(freeze_path),
        "schedule_hash": schedule["schedule_hash"],
        "schedule_file_sha256": _sha(schedule_path),
        "prompt_commitments_file_sha256": _sha(prompt_path),
        "run_bindings_sha256": run_bindings_sha,
        "execution_commitments_sha256": execution_commitments_sha,
        "execution_commitments_file_sha256": _sha(
            archive / "execution_commitments.json"
        ),
        "attempted_records_file_sha256": _sha(archive / "attempted_records.jsonl"),
        "traces_file_sha256": _sha(archive / "traces.jsonl"),
        "budget_ledger_file_sha256": _sha(archive / "budget_ledger.jsonl"),
        "outcomes_file_sha256": _sha(archive / "outcomes.json"),
        "decision_file_sha256": _sha(archive / "decision.json"),
    }
    _write_json(archive / "private_release_source.json", release_source)
    events = _event_rows(
        schedule,
        _sha(archive / "private_release_source.json"),
        expected_summary["decision"],
        freeze=freeze,
        freeze_sha256=freeze_sha,
        freeze_commit_sha=protocol_commit,
        authority_receipt_sha256=_sha(
            archive / builder.ARCHIVED_AUTHORITY_RECEIPT_NAME
        ),
        ledger_initial_sha256=ledger_rows[0]["event_sha256"],
        ledger_file_sha256=_sha(archive / "budget_ledger.jsonl"),
        execution_commitments_sha256=execution_commitments_sha,
    )
    _write_jsonl(archive / "execution_events.jsonl", events)

    covered = []
    for path in sorted(archive.rglob("*")):
        if not path.is_file() or path.name in {
            builder.ARCHIVE_MANIFEST_NAME,
            builder.COMPLETE_MARKER_NAME,
        }:
            continue
        covered.append(
            {
                "path": path.relative_to(archive).as_posix(),
                "sha256": _sha(path),
                "bytes": path.stat().st_size,
            }
        )
    manifest = {
        "schema_version": builder.ARCHIVE_SCHEMA_VERSION,
        "contains_raw_private_provider_material": True,
        "contains_credential_or_provenance_key_material": False,
        "immutable_archive_attestation": attestation,
        "immutable_archive_attestation_sha256": hashlib.sha256(
            attestation.encode()
        ).hexdigest(),
        "completion_marker_policy": "execution_complete_created_only_after_archive_commitment",
        "coverage_exclusions": builder.ARCHIVE_EXCLUSIONS,
        "file_count": len(covered),
        "files": covered,
    }
    manifest["archive_commitment_sha256"] = builder._semantic_sha256(manifest)
    _write_json(archive / builder.ARCHIVE_MANIFEST_NAME, manifest)
    complete = {
        "schema_version": builder.EXECUTION_SCHEMA_VERSION,
        "status": "COMPLETE",
        "decision": expected_summary["decision"],
        "scheduled_run_count": 768,
        "provider_call_count": 768,
        "outcomes_sha256": _sha(archive / "outcomes.json"),
        "decision_sha256": _sha(archive / "decision.json"),
        "private_archive_manifest_sha256": _sha(
            archive / builder.ARCHIVE_MANIFEST_NAME
        ),
        "private_release_source_sha256": _sha(
            archive / "private_release_source.json"
        ),
        "terminal_event_sha256": events[-1]["event_sha256"],
    }
    _write_json(archive / builder.COMPLETE_MARKER_NAME, complete)
    return {
        "root": root,
        "archive": archive,
        "schedule": schedule,
        "schedule_path": schedule_path,
        "freeze_path": freeze_path,
        "tag_target": protocol_commit,
        "summary": expected_summary,
        "bindings": bindings,
        "execution_commitments": execution_commitments,
    }


def _core_public_verifier(
    release: Path, *, schedule_path: Path, freeze_path: Path, require_full: bool
) -> dict:
    del require_full
    schedule = builder.PUBLIC_VERIFIER._validate_schedule_document(
        builder.PUBLIC_VERIFIER._read_json(schedule_path)
    )
    builder.PUBLIC_VERIFIER._verify_checksums(release)
    rows = builder.PUBLIC_VERIFIER._load_runs(release / "runs.json", schedule)
    expected = builder.PUBLIC_VERIFIER.build_expected_summary(schedule, rows)
    builder.PUBLIC_VERIFIER._validate_summary(
        builder.PUBLIC_VERIFIER._read_json(release / "summary.json"), expected
    )
    builder.PUBLIC_VERIFIER._validate_release_readme(release / "README.md", expected)
    return {
        "status": "VERIFIED",
        "pass": True,
        "public_data_verification_pass": True,
        "empirical_release_present": True,
        "decision_recomputed": expected["decision"],
        "scheduled_rows_verified": 768,
        "schedule_hash": schedule["schedule_hash"],
        "schedule_file_sha256": _sha(schedule_path),
        "freeze_manifest_sha256": _sha(freeze_path),
        "release_checksum_manifest_sha256": _sha(release / "SHA256SUMS"),
        "repository_tag_binding_verified": True,
    }


def test_complete_archive_builds_exact_verified_four_file_release(
    complete_private_archive: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = complete_private_archive
    destination = fixture["root"] / "public-success"
    monkeypatch.setattr(
        builder,
        "_resolve_freeze_tag_target",
        lambda _freeze, _path: fixture["tag_target"],
    )
    monkeypatch.setattr(builder, "_validate_full_final_freeze", lambda *_args, **_kwargs: None)
    report = builder.build_stage4_release(
        fixture["archive"],
        destination=destination,
        schedule_path=fixture["schedule_path"],
        freeze_path=fixture["freeze_path"],
        _verify=_core_public_verifier,
    )
    assert report["status"] == "PUBLISHED"
    assert report["decision"] == "NO_GO"
    assert report["provider_calls_made_by_builder"] == 0
    assert report["private_raw_files_copied"] == 0
    assert {path.name for path in destination.iterdir()} == builder.PUBLIC_ENTRY_SET
    runs = json.loads((destination / "runs.json").read_text())
    assert len(runs["outcomes"]) == 768
    assert all(
        set(row) == set(builder.PUBLIC_VERIFIER.OUTCOME_FIELDS)
        for row in runs["outcomes"]
    )
    assert not (destination / "traces.jsonl").exists()


def test_raw_request_outer_schema_is_exact(
    complete_private_archive: dict,
) -> None:
    fixture = complete_private_archive
    archive = fixture["archive"]
    attempted = [
        json.loads(line)
        for line in (archive / "attempted_records.jsonl").read_text().splitlines()
    ]
    call = attempted[0]["calls"][0]
    model_id = call["requested_model"]
    stem = call["raw_log_record"]
    request_relative = f"raw/{model_id}/{stem}.request.json"
    result_relative = f"raw/{model_id}/{stem}.response.json"
    request_path = archive / request_relative
    original = request_path.read_bytes()
    ledger_rows = [
        json.loads(line)
        for line in (archive / "budget_ledger.jsonl").read_text().splitlines()
    ]
    held = next(
        row
        for row in ledger_rows
        if row.get("event") == "reservation_held"
        and row.get("reservation_id") == call["ledger_reservation_id"]
    )
    terminal = next(
        row
        for row in ledger_rows
        if row.get("event_sha256") == call["ledger_terminal_event_sha256"]
    )
    prompt = json.loads(
        (fixture["schedule_path"].with_name("stage4_prompt_commitments.json")).read_text()
    )["calls"][0]
    try:
        request = json.loads(original)
        request["unexpected_outer_field"] = True
        _write_json(request_path, request)
        with pytest.raises(
            builder.ReleaseBuildError,
            match="raw_request_record_schema_mismatch",
        ):
            builder._validate_raw_call_evidence(
                archive,
                request_path=request_relative,
                result_path=result_relative,
                result_kind="response",
                request_record_sha256=_sha(request_path),
                result_record_sha256=_sha(archive / result_relative),
                stem=stem,
                model_id=model_id,
                provider_call_order=call["provider_call_order"],
                local_pairing_seed=call["local_pairing_seed"],
                expected_metadata=request["run_metadata"],
                held=held,
                terminal=terminal,
                prompt_commitment=prompt,
                decision_schema_version=DECISION_SCHEMA_VERSION,
            )
    finally:
        request_path.write_bytes(original)
        request_path.chmod(0o600)


def test_self_consistent_raw_decision_hash_rewrite_fails_trace_replay(
    complete_private_archive: dict,
) -> None:
    fixture = complete_private_archive
    archive = fixture["archive"]
    attempted_path = archive / "attempted_records.jsonl"
    traces_path = archive / "traces.jsonl"
    outcomes_path = archive / "outcomes.json"
    attempted_original = attempted_path.read_bytes()
    traces_original = traces_path.read_bytes()
    outcomes_original = outcomes_path.read_bytes()
    attempted = [json.loads(line) for line in attempted_original.splitlines()]
    traces = [json.loads(line) for line in traces_original.splitlines()]
    outcomes = json.loads(outcomes_original)
    call = attempted[0]["calls"][0]
    result_relative = (
        f"raw/{call['requested_model']}/{call['raw_log_record']}.response.json"
    )
    result_path = archive / result_relative
    result_original = result_path.read_bytes()
    _, covered, files = builder._validate_archive_manifest(archive)
    try:
        result = json.loads(result_original)
        result["provider_response"]["output_text"] = json.dumps(
            {
                "decision": "refuse",
                "selected_action_id": None,
                "reason": "fixture mutation",
                "missing_information": [],
            },
            sort_keys=True,
        )
        _write_json(result_path, result)
        rewritten_result_sha = _sha(result_path)
        call["result_record_sha256"] = rewritten_result_sha
        traces[0]["steps"][0]["provider_metadata"][
            "result_record_sha256"
        ] = rewritten_result_sha
        rewritten_trace_sha = builder._semantic_sha256(traces[0])
        attempted[0]["source_sha256"] = rewritten_trace_sha
        outcomes["outcomes"][0]["source_record_commitment_sha256"] = (
            rewritten_trace_sha
        )
        outcomes["outcomes"][0]["call_audit_sha256"] = builder._semantic_sha256(
            attempted[0]["calls"]
        )
        _write_jsonl(attempted_path, attempted)
        _write_jsonl(traces_path, traces)
        _write_json(outcomes_path, outcomes)
        covered = dict(covered)
        covered[result_relative] = (rewritten_result_sha, result_path.stat().st_size)
        freeze = json.loads(fixture["freeze_path"].read_text())
        complete = json.loads(
            (archive / builder.COMPLETE_MARKER_NAME).read_text()
        )
        held, terminal, counts = builder._validate_budget_ledger(
            archive, complete=complete, freeze=freeze
        )
        with pytest.raises(
            builder.ReleaseBuildError,
            match="frozen_local_trace_replay_mismatch",
        ):
            builder._validate_attempted_records(
                archive,
                files=files,
                covered_files=covered,
                schedule=fixture["schedule"],
                bindings=fixture["bindings"],
                commitments=fixture["execution_commitments"],
                private_rows=outcomes["outcomes"],
                complete=complete,
                held_by_id=held,
                terminal_by_id=terminal,
                ledger_model_counts=counts,
                freeze=freeze,
                schedule_path=fixture["schedule_path"],
            )
    finally:
        result_path.write_bytes(result_original)
        attempted_path.write_bytes(attempted_original)
        traces_path.write_bytes(traces_original)
        outcomes_path.write_bytes(outcomes_original)
        for path in (result_path, attempted_path, traces_path, outcomes_path):
            path.chmod(0o600)


def test_budget_ledger_rejects_hash_consistent_extra_event_field(
    complete_private_archive: dict,
) -> None:
    fixture = complete_private_archive
    archive = fixture["archive"]
    ledger_path = archive / "budget_ledger.jsonl"
    original = ledger_path.read_bytes()
    try:
        rows = [json.loads(line) for line in original.splitlines()]
        rows[0]["unexpected_payload"] = "not-frozen"
        previous = None
        for row in rows:
            row["previous_event_sha256"] = previous
            row.pop("event_sha256", None)
            row["event_sha256"] = builder._semantic_sha256(row)
            previous = row["event_sha256"]
        _write_jsonl(ledger_path, rows)
        freeze = json.loads(fixture["freeze_path"].read_text())
        complete = json.loads(
            (archive / builder.COMPLETE_MARKER_NAME).read_text()
        )
        with pytest.raises(
            builder.ReleaseBuildError,
            match="budget_ledger_event_schema_mismatch",
        ):
            builder._validate_budget_ledger(
                archive, complete=complete, freeze=freeze
            )
    finally:
        ledger_path.write_bytes(original)
        ledger_path.chmod(0o600)


def test_release_rejects_test_backend_start_event(
    complete_private_archive: dict,
) -> None:
    fixture = complete_private_archive
    path = fixture["archive"] / "execution_events.jsonl"
    original = path.read_bytes()
    try:
        rows = [json.loads(line) for line in original.splitlines()]
        rows[0]["injected_test_backend"] = True
        previous = None
        for sequence, row in enumerate(rows, start=1):
            row["sequence"] = sequence
            row["previous_event_sha256"] = previous
            row.pop("event_sha256", None)
            row["event_sha256"] = builder._semantic_sha256(row)
            previous = row["event_sha256"]
        _write_jsonl(path, rows)
        complete = json.loads(
            (fixture["archive"] / builder.COMPLETE_MARKER_NAME).read_text()
        )
        complete["terminal_event_sha256"] = rows[-1]["event_sha256"]
        freeze = json.loads(fixture["freeze_path"].read_text())
        with pytest.raises(
            builder.ReleaseBuildError,
            match="execution_start_event_test_backend_forbidden|production_binding",
        ):
            builder._validate_execution_events(
                fixture["archive"],
                complete=complete,
                schedule=fixture["schedule"],
                source_sha256=_sha(
                    fixture["archive"] / "private_release_source.json"
                ),
                authority_receipt_sha256=_sha(
                    fixture["archive"] / builder.ARCHIVED_AUTHORITY_RECEIPT_NAME
                ),
                freeze=freeze,
                freeze_manifest_sha256=_sha(fixture["freeze_path"]),
                freeze_tag_target=fixture["tag_target"],
            )
    finally:
        path.write_bytes(original)
        path.chmod(0o600)


def test_release_rejects_nonproduction_backend_commitment(
    complete_private_archive: dict,
) -> None:
    fixture = complete_private_archive
    freeze = json.loads(fixture["freeze_path"].read_text())
    model_id = builder.PUBLIC_VERIFIER.MODELS[0]
    test_configuration = builder._expected_production_backend_configuration(
        freeze, model_id=model_id
    )
    test_configuration["test_only_no_external_io"] = True
    with pytest.raises(
        builder.ReleaseBuildError,
        match="execution_commitment_backend_configuration_mismatch",
    ):
        builder._validate_production_backend_configuration_hash(
            freeze,
            model_id=model_id,
            supplied_sha256=builder._semantic_sha256(test_configuration),
        )


def test_release_rejects_forged_archived_authority_preimage(
    complete_private_archive: dict,
) -> None:
    fixture = complete_private_archive
    archive = fixture["archive"]
    path = archive / builder.ARCHIVED_AUTHORITY_RECEIPT_NAME
    original = path.read_bytes()
    _, covered, _ = builder._validate_archive_manifest(archive)
    try:
        forged = json.loads(original)
        forged["credential_id"] = "forged-credential"
        _write_json(path, forged)
        covered = dict(covered)
        covered[builder.ARCHIVED_AUTHORITY_RECEIPT_NAME] = (
            _sha(path),
            path.stat().st_size,
        )
        freeze = json.loads(fixture["freeze_path"].read_text())
        with pytest.raises(
            builder.ReleaseBuildError,
            match="authority_receipt_freeze_binding_mismatch",
        ):
            builder._validate_execution_start_and_authority(
                archive,
                covered_files=covered,
                freeze=freeze,
                schedule=fixture["schedule"],
                freeze_tag_target=fixture["tag_target"],
                freeze_file_sha256=_sha(fixture["freeze_path"]),
            )
    finally:
        path.write_bytes(original)
        path.chmod(0o600)


def test_builder_rejects_preloaded_project_module_from_untrusted_origin(
    complete_private_archive: dict,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_path = tmp_path / "mas_safety" / "live_budget.py"
    fake_path.parent.mkdir()
    fake_path.write_text("# hostile preloaded module\n", encoding="utf-8")
    fake_module = ModuleType("mas_safety.live_budget")
    fake_module.__file__ = str(fake_path)
    monkeypatch.setitem(sys.modules, "mas_safety.live_budget", fake_module)
    freeze = json.loads(complete_private_archive["freeze_path"].read_text())

    with pytest.raises(
        builder.ReleaseBuildError,
        match="builder_project_import_origin_invalid",
    ):
        builder._load_budget_auditor_bound(freeze)


def test_frozen_replay_import_ignores_custom_meta_path_finder(
    complete_private_archive: dict,
) -> None:
    class _TrapFinder:
        hit = False

        def find_spec(
            self,
            fullname: str,
            _path: object = None,
            _target: object = None,
        ) -> object:
            if fullname.startswith("_stage4_release_frozen_runtime"):
                self.hit = True
                raise AssertionError("custom finder reached frozen replay import")
            return None

    trap = _TrapFinder()
    freeze = json.loads(complete_private_archive["freeze_path"].read_text())
    sys.meta_path.insert(0, trap)
    try:
        modules = builder._load_frozen_replay_modules(freeze)
        rows, digest = builder._canonical_runtime_bindings(
            complete_private_archive["schedule_path"],
            batch_id=builder.PUBLIC_VERIFIER.EXPECTED_BATCH_ID,
            freeze=freeze,
        )
    finally:
        sys.meta_path.remove(trap)
    assert "runner" in modules
    assert len(rows) == 768
    assert len(digest) == 64
    assert trap.hit is False


def test_source_byte_loader_ignores_valid_timestamp_bytecode(tmp_path: Path) -> None:
    source = tmp_path / "claim_bearing.py"
    trusted = "VALUE = 'trusted'\n"
    hostile = "VALUE = 'hostile'\n"
    assert len(trusted) == len(hostile)
    source.write_text(hostile, encoding="utf-8")
    source_stat = source.stat()
    bytecode = Path(importlib.util.cache_from_source(str(source)))
    py_compile.compile(
        str(source),
        cfile=str(bytecode),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP,
    )
    source.write_text(trusted, encoding="utf-8")
    os.utime(
        source,
        ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns),
    )

    # Establish that CPython's normal source loader accepts the hostile cache
    # while reporting the trusted source path as the module origin.
    normal_spec = importlib.util.spec_from_file_location("normal_pyc_probe", source)
    assert normal_spec is not None and normal_spec.loader is not None
    normal = importlib.util.module_from_spec(normal_spec)
    normal_spec.loader.exec_module(normal)
    assert normal.VALUE == "hostile"
    assert Path(normal.__file__).resolve() == source.resolve()

    module_name = "_stage4_source_bytes_pyc_probe"
    try:
        loaded = builder._load_source_bytes_module(
            module_name,
            source,
            expected_sha256=hashlib.sha256(trusted.encode()).hexdigest(),
            code="source_byte_probe_failed",
        )
        assert loaded.VALUE == "trusted"
    finally:
        sys.modules.pop(module_name, None)


def test_canonical_builder_cli_exposes_no_input_or_destination_overrides() -> None:
    parser = builder._build_parser()
    assert parser.parse_args([]).json_output is False
    assert parser.parse_args(["--json"]).json_output is True
    for forbidden in ("--archive", "--destination", "--schedule", "--freeze"):
        with pytest.raises(SystemExit):
            parser.parse_args([forbidden, "alternate-path"])


def test_verifier_rejection_never_publishes(
    complete_private_archive: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = complete_private_archive
    destination = fixture["root"] / "public-rejected"
    monkeypatch.setattr(
        builder,
        "_resolve_freeze_tag_target",
        lambda _freeze, _path: fixture["tag_target"],
    )
    monkeypatch.setattr(builder, "_validate_full_final_freeze", lambda *_args, **_kwargs: None)

    def reject(*_args, **_kwargs):
        return {
            "status": "NOT_RUN",
            "pass": False,
            "public_data_verification_pass": False,
        }

    with pytest.raises(builder.ReleaseBuildError, match="public_verifier_did_not_verify"):
        builder.build_stage4_release(
            fixture["archive"],
            destination=destination,
            schedule_path=fixture["schedule_path"],
            freeze_path=fixture["freeze_path"],
            _verify=reject,
        )
    assert not destination.exists()
    assert not list(fixture["root"].glob(".public-rejected.staging-*"))


def test_existing_destination_is_rejected_before_archive_access(tmp_path: Path) -> None:
    destination = tmp_path / "existing"
    destination.mkdir()
    sentinel = destination / "keep.txt"
    sentinel.write_text("keep")
    with pytest.raises(builder.ReleaseBuildError, match="public_destination_already_exists"):
        builder.build_stage4_release(tmp_path / "missing", destination=destination)
    assert sentinel.read_text() == "keep"


def test_secret_scanner_rejects_key_shaped_public_bytes() -> None:
    with pytest.raises(builder.ReleaseBuildError, match="secret_material_detected"):
        builder._assert_no_public_secret_material(
            "runs.json",
            b'{"note":"' + b"sk-" + b"proj-" + b'abcdefghijklmnop"}',
        )


def test_trace_preimage_and_derived_label_tampering_is_rejected() -> None:
    scheduled = {
        "sequence_index": 0,
        "scenario_id": "confirmatory.h1_research_data_export",
        "domain": "healthcare",
        "mechanism": "intent_decomposition",
        "mechanism_on": True,
        "safety_variant": "unsafe",
        "model_id": builder.PUBLIC_VERIFIER.MODELS[0],
    }
    call = {
        "decision_status": "model_refusal",
        "structured_output_valid": True,
        "requested_model": scheduled["model_id"],
        "condition_id": "condition",
        "invocation_id": "invocation",
        "scenario_id": scheduled["scenario_id"],
        "mechanism": scheduled["mechanism"],
        "mechanism_active": True,
        "safety_variant": "unsafe",
        "batch_id": builder.PUBLIC_VERIFIER.EXPECTED_BATCH_ID,
        "local_pairing_seed": 1,
        "scheduled_workflow_run_order": 1,
        "model_workflow_run_order": 1,
        "repetition": 1,
        "protocol_commit_sha": "f" * 40,
        "protocol_sha256": "a" * 64,
        "provider_call_order": 1,
        "raw_log_record": "call-000001-aaaaaaaaaaaa",
        "provider_request_sha256": "1" * 64,
        "request_record_sha256": "2" * 64,
        "result_record_sha256": "3" * 64,
        "result_record_kind": "response",
    }
    trace = {
        "condition_id": "condition",
        "scenario_id": scheduled["scenario_id"],
        "domain": "healthcare",
        "mechanism": scheduled["mechanism"],
        "mechanism_active": True,
        "safety_variant": "unsafe",
        "model_id": scheduled["model_id"],
        "batch_id": builder.PUBLIC_VERIFIER.EXPECTED_BATCH_ID,
        "seed": 0,
        "invocation_id": "invocation",
        "provenance_key_id": "key-id",
        "backend": "openai_responses",
        "defense": "local_only",
        "architecture": "multi_agent",
        "decision_mode": "execution_decision",
        "component_hashes": {},
        "backend_configuration": {},
        "global_violation": False,
        "all_local_allow": False,
        "local_allow_global_harm": False,
        "benign_completed": False,
        "defense_blocked": False,
        "capability_failure": False,
        "refusal": True,
        "escalation": False,
        "status": "model_refusal",
        "steps": [
            {
                "step_index": 1,
                "decision_status": "model_refusal",
                "provider_metadata": {
                    key: value
                    for key, value in call.items()
                    if key
                    in {
                        "condition_id",
                        "requested_model",
                        "invocation_id",
                        "scenario_id",
                        "mechanism",
                        "mechanism_active",
                        "safety_variant",
                        "batch_id",
                        "local_pairing_seed",
                        "scheduled_workflow_run_order",
                        "model_workflow_run_order",
                        "repetition",
                        "protocol_commit_sha",
                        "protocol_sha256",
                        "provider_call_order",
                        "structured_output_valid",
                        "raw_log_record",
                        "provider_request_sha256",
                        "request_record_sha256",
                        "result_record_sha256",
                        "result_record_kind",
                    }
                },
            }
        ],
    }
    metadata = trace["steps"][0]["provider_metadata"]
    metadata["call_order"] = metadata.pop("provider_call_order")
    metadata["retry_count"] = 0
    outcome = {
        "condition_id": "condition",
        "batch_id": builder.PUBLIC_VERIFIER.EXPECTED_BATCH_ID,
        "seed": 0,
        "invocation_id": "invocation",
        "provenance_key_id": "key-id",
        "backend_name": "openai_responses",
        "component_hashes_sha256": builder._semantic_sha256({}),
        "backend_configuration_sha256": builder._semantic_sha256({}),
        "local_lgh": 0,
        "safe_completion": 0,
        "run_completed": 0,
        "refusal": True,
        "escalation": False,
        "attempted_agent_calls": 1,
        "valid_structured_decisions": 1,
        "noncompletion_reason": "model_refusal",
        "failure_reason": None,
        "source_kind": "trace",
        "source_record_commitment_sha256": builder._semantic_sha256(trace),
        "replacement_attempted": False,
    }
    builder._validate_trace_preimage_and_labels(
        trace,
        scheduled=scheduled,
        private_row=outcome,
        calls=[call],
        source_sha256=outcome["source_record_commitment_sha256"],
    )
    tampered = dict(trace)
    tampered["refusal"] = False
    with pytest.raises(builder.ReleaseBuildError):
        builder._validate_trace_preimage_and_labels(
            tampered,
            scheduled=scheduled,
            private_row=outcome,
            calls=[call],
            source_sha256=outcome["source_record_commitment_sha256"],
        )


def test_public_projection_rejects_bool_for_binary_integer(
    complete_private_archive: dict,
) -> None:
    fixture = complete_private_archive
    outcomes = json.loads((fixture["archive"] / "outcomes.json").read_text())
    outcomes["outcomes"][0]["local_lgh"] = False
    with pytest.raises(builder.ReleaseBuildError, match="public_outcome_validation_failed"):
        builder._project_public_rows(
            outcomes,
            schedule=fixture["schedule"],
            bindings=fixture["bindings"],
            commitments_document=fixture["execution_commitments"],
        )


@pytest.mark.parametrize("delta", [-1, 1])
def test_public_projection_rejects_missing_or_extra_rows(
    complete_private_archive: dict,
    delta: int,
) -> None:
    fixture = complete_private_archive
    outcomes = json.loads((fixture["archive"] / "outcomes.json").read_text())
    if delta < 0:
        outcomes["outcomes"].pop()
    else:
        outcomes["outcomes"].append(dict(outcomes["outcomes"][-1]))
    with pytest.raises(builder.ReleaseBuildError, match="private_outcomes_row_count_mismatch"):
        builder._project_public_rows(
            outcomes,
            schedule=fixture["schedule"],
            bindings=fixture["bindings"],
            commitments_document=fixture["execution_commitments"],
        )


def test_archive_file_tampering_is_rejected(complete_private_archive: dict) -> None:
    archive = complete_private_archive["archive"]
    target = archive / "execution_started.json"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b" ")
        target.chmod(0o600)
        with pytest.raises(
            builder.ReleaseBuildError, match="private_archive_file_commitment_mismatch"
        ):
            builder._validate_archive_manifest(archive)
    finally:
        target.write_bytes(original)
        target.chmod(0o600)


def test_any_incomplete_marker_is_rejected(complete_private_archive: dict) -> None:
    archive = complete_private_archive["archive"]
    marker = archive / "nested" / builder.INCOMPLETE_MARKER_NAME
    try:
        _write_json(marker, {"status": "INCOMPLETE"})
        with pytest.raises(builder.ReleaseBuildError, match="incomplete_marker_present"):
            builder._validate_archive_manifest(archive)
    finally:
        marker.unlink()
        marker.parent.rmdir()
