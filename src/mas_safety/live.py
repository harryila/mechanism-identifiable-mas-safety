from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Callable, Iterable, Sequence
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree

from .backends import AgentBackend
from .enums import (
    AgentDecisionKind,
    Architecture,
    DecisionMode,
    Defense,
    Mechanism,
    Role,
    SafetyVariant,
)
from .live_analysis import EXPECTED_REPETITIONS, EXPECTED_RUNS, analyze_live_development
from .live_backends import (
    FROZEN_MAX_OUTPUT_TOKENS,
    FROZEN_REASONING_EFFORT,
    FROZEN_SERVICE_TIER,
    OpenAIResponsesBackend,
    build_frozen_provider_request,
)
from .live_budget import (
    FROZEN_GROSS_CEILING_NANO_USD,
    FROZEN_MODEL_IDS,
    FROZEN_OUTPUT_RESERVATION_TOKENS,
    LiveBudgetLedger,
    audit_budget_ledger,
    estimate_standard_cost_nano_usd,
)
from .models import ActionSpec, AgentDecision, RunTrace, Scenario, StageContext
from .runner import ExperimentRunner, RunSpec, frozen_program_hashes
from .scenarios import load_scenarios

BackendFactory = Callable[[str, Path], AgentBackend]
_SNAPSHOT_DATE = re.compile(
    r"(?:19|20)\d{2}[-_](?:0[1-9]|1[0-2])[-_](?:0[1-9]|[12]\d|3[01])"
)
DEVELOPMENT_SCENARIO_IDS = frozenset(
    {
        "healthcare.patient_summary_disclosure",
        "finance.unapproved_payment",
    }
)
HARD_QA_EXPECTED_TESTS = 118  # Updated only when the frozen release suite changes.
HARD_QA_SENTINEL_NAME = "test_hard_qa_sentinel"


def live_development_specs(
    scenarios: Iterable[Scenario],
    *,
    repetitions: int = EXPECTED_REPETITIONS,
    batch_id: str = "stage1-development-template",
) -> list[RunSpec]:
    """Return one model's paired Stage 1 local-only development matrix."""

    scenario_items = sorted(scenarios, key=lambda item: item.scenario_id)
    scenario_ids = {item.scenario_id for item in scenario_items}
    if (
        len(scenario_items) != 2
        or len(scenario_ids) != 2
        or scenario_ids != DEVELOPMENT_SCENARIO_IDS
    ):
        raise ValueError(
            "Stage 1 requires exactly the two preregistered development workflows"
        )
    if not batch_id.strip():
        raise ValueError("Stage 1 batch_id must be non-empty")
    if repetitions != EXPECTED_REPETITIONS:
        raise ValueError(
            f"Stage 1 is frozen at {EXPECTED_REPETITIONS} repetitions per cell"
        )

    specs: list[RunSpec] = []
    for repetition in range(1, repetitions + 1):
        for scenario in scenario_items:
            for mechanism in Mechanism:
                for safety_variant in SafetyVariant:
                    pair_material = (
                        f"v0.2.1-live|{scenario.scenario_id}|{mechanism.value}|"
                        f"{safety_variant.value}|{repetition}"
                    )
                    digest = hashlib.sha256(pair_material.encode()).hexdigest()
                    seed = int(digest[:8], 16) & 0x7FFFFFFF
                    invocation_id = f"stage1-r{repetition:02d}-{digest[8:20]}"
                    assignments = (False, True) if seed % 2 == 0 else (True, False)
                    for active in assignments:
                        specs.append(
                            RunSpec(
                                scenario_id=scenario.scenario_id,
                                mechanism=mechanism,
                                defense=Defense.LOCAL_ONLY,
                                safety_variant=safety_variant,
                                architecture=Architecture.MULTI_AGENT,
                                mechanism_active=active,
                                cohort="mechanism_on" if active else "mechanism_off",
                                seed=seed,
                                invocation_id=invocation_id,
                                batch_id=batch_id,
                                decision_mode=DecisionMode.EXECUTION_DECISION,
                            )
                        )
    expected_per_model = EXPECTED_RUNS // 2
    if len(specs) != expected_per_model:
        raise AssertionError(
            f"Stage 1 generator produced {len(specs)} specs, expected {expected_per_model}"
        )
    return specs


def run_live_development(
    *,
    scenarios: Sequence[Scenario],
    model_ids: Sequence[str],
    output_dir: str | Path,
    provenance_signing_key: bytes,
    provenance_key_id: str,
) -> dict[str, object]:
    """Run the production Stage 1 path with no injectable provider bypasses."""

    return _run_live_development_impl(
        scenarios=scenarios,
        model_ids=model_ids,
        output_dir=output_dir,
        provenance_signing_key=provenance_signing_key,
        provenance_key_id=provenance_key_id,
        backend_factory=None,
        repository_freeze_override=None,
        test_mode=False,
    )


def _run_live_development_for_test(
    *,
    scenarios: Sequence[Scenario],
    model_ids: Sequence[str],
    output_dir: str | Path,
    provenance_signing_key: bytes,
    provenance_key_id: str,
    backend_factory: BackendFactory,
    repository_freeze_override: dict[str, object],
) -> dict[str, object]:
    """Exercise orchestration without an empirical GO; for repository tests only."""

    return _run_live_development_impl(
        scenarios=scenarios,
        model_ids=model_ids,
        output_dir=output_dir,
        provenance_signing_key=provenance_signing_key,
        provenance_key_id=provenance_key_id,
        backend_factory=backend_factory,
        repository_freeze_override=repository_freeze_override,
        test_mode=True,
    )


def _run_live_development_impl(
    *,
    scenarios: Sequence[Scenario],
    model_ids: Sequence[str],
    output_dir: str | Path,
    provenance_signing_key: bytes,
    provenance_key_id: str,
    backend_factory: BackendFactory | None,
    repository_freeze_override: dict[str, object] | None,
    test_mode: bool,
) -> dict[str, object]:
    """Execute and checkpoint the complete two-model Stage 1 matrix.

    The output directory is private by design because traces contain raw model
    outputs and the sibling ``raw_responses`` tree contains full prompts and API
    responses. Share only reviewed, redacted derivatives.
    """

    models = tuple(model_ids)
    if len(models) != 2 or len(set(models)) != 2 or any(not item.strip() for item in models):
        raise ValueError("Provide exactly two distinct, non-empty model IDs")
    if any(_SNAPSHOT_DATE.search(item) is None for item in models):
        raise ValueError(
            "Each live model ID must contain an immutable YYYY-MM-DD snapshot date"
        )
    if not test_mode and models != FROZEN_MODEL_IDS:
        raise ValueError(
            "Production Stage 1 requires the exact ordered frozen model snapshots"
        )
    if len(provenance_signing_key) < 32:
        raise ValueError("Live provenance signing key must contain at least 32 bytes")
    if not provenance_key_id.strip() or provenance_key_id.startswith("development"):
        raise ValueError("Live provenance key ID must be explicit and non-development")

    # Freeze a defensive snapshot of the exact preregistered scenario objects.
    frozen_scenarios = tuple(deepcopy(tuple(scenarios)))
    frozen_scenario_hashes = _scenario_hashes(frozen_scenarios)
    if set(frozen_scenario_hashes) != DEVELOPMENT_SCENARIO_IDS:
        raise ValueError(
            "Stage 1 requires exactly the two preregistered development workflows"
        )

    destination = Path(output_dir)
    _assert_private_output_destination(destination)
    if test_mode is not (backend_factory is not None):
        raise AssertionError("Backend injection must match the internal test mode")
    if test_mode is not (repository_freeze_override is not None):
        raise AssertionError("Freeze override must match the internal test mode")
    injected_test_backend = test_mode
    repository_freeze = (
        _validated_freeze_override(repository_freeze_override)
        if repository_freeze_override is not None
        else _repository_freeze_metadata()
    )
    repository_root: Path | None = None
    if not injected_test_backend:
        repository_root = _git_repository_root(required=True)
        assert repository_root is not None
        committed_scenario_hashes = _scenario_hashes(
            tuple(load_scenarios(repository_root / "scenarios"))
        )
        if frozen_scenario_hashes != committed_scenario_hashes:
            raise RuntimeError(
                "Live scenarios differ from the preregistered repository fixtures"
            )
    hard_qa_attestation = (
        {
            "required": False,
            "pass": True,
            "reason": "injected_test_backend",
            "commit_sha": repository_freeze["commit_sha"],
        }
        if injected_test_backend
        else _run_hard_qa_attestation(repository_freeze)
    )
    if not injected_test_backend:
        _assert_repository_freeze_unchanged(
            repository_freeze,
            context="during the hard-QA preflight",
        )
    frozen_components = frozen_program_hashes()
    batch_id = _new_batch_id()
    trace_path = destination / "traces.jsonl"
    manifest_path = destination / "model_call_manifest.json"
    if destination.exists():
        raise FileExistsError(
            "Refusing to reuse a live output path; choose a new batch directory"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir(exist_ok=False, mode=0o700)
    try:
        destination.chmod(0o700)
    except OSError:
        pass

    specs = live_development_specs(frozen_scenarios, batch_id=batch_id)
    cost_preflight = _stage_one_cost_preflight(frozen_scenarios, specs, models)
    if (
        not injected_test_backend
        and cost_preflight["byte_upper_bound_cost_nano_usd"]
        > FROZEN_GROSS_CEILING_NANO_USD
    ):
        raise RuntimeError(
            "Frozen Stage 1 request sizing no longer fits the USD 20 authorization"
        )
    authority_lock = (
        None
        if injected_test_backend
        else _acquire_provider_authority_lock(
            repository_root=repository_root,
            repository_freeze=repository_freeze,
            batch_id=batch_id,
            destination=destination,
        )
    )
    budget_ledger = (
        None
        if injected_test_backend
        else LiveBudgetLedger(destination / "budget_ledger.jsonl")
    )
    started_at = _utc_now()
    manifest: dict[str, object] = {
        "schema_version": "0.2.1",
        "protocol_version": "v0.2.1-live",
        "stage": "stage_1_local_only_live_micro_pilot",
        "state": "smoke_pending",
        "started_at_utc": started_at,
        "completed_at_utc": None,
        "batch_id": batch_id,
        "execution_mode": (
            "injected_test_backend" if injected_test_backend else "default_live_backend"
        ),
        "requested_model_ids": list(models),
        "provider_authority_lock": authority_lock,
        "backend_configurations": [],
        "matrix": {
            "workflows": 2,
            "mechanisms": len(Mechanism),
            "assignments": 2,
            "safety_variants": len(SafetyVariant),
            "repetitions": EXPECTED_REPETITIONS,
            "models": 2,
            "expected_workflow_runs": EXPECTED_RUNS,
            "maximum_agent_calls": EXPECTED_RUNS * 4,
            "defense": Defense.LOCAL_ONLY.value,
            "architecture": Architecture.MULTI_AGENT.value,
            "decision_mode": DecisionMode.EXECUTION_DECISION.value,
        },
        "run_spec_sha256": _spec_hash(specs),
        "cost_preflight": cost_preflight,
        "repository_freeze": repository_freeze,
        "hard_qa_attestation": hard_qa_attestation,
        "frozen_component_hashes": frozen_components,
        "frozen_scenario_hashes": frozen_scenario_hashes,
        "scenario_source": (
            "injected_test_objects"
            if injected_test_backend
            else "preregistered_repository_fixtures"
        ),
        "provenance_key_id": provenance_key_id,
        "provenance_key_material_recorded": False,
        "raw_data": {
            "location": (
                "smoke_raw_responses/ and raw_responses/ "
                "(private; gitignored by repository policy)"
            ),
            "contains_full_prompts_and_responses": True,
            "review_before_sharing": True,
        },
        "retry_policy": {
            "sdk_max_retries": 0,
            "application_retries": 0,
            "per_call_timeout_seconds": 120.0,
        },
        "workflow_runs_completed": 0,
        "agent_calls_completed": 0,
        "smoke_calls_completed": 0,
        "smoke_attestation": None,
        "budget_ledger": (
            budget_ledger.snapshot()
            if budget_ledger is not None
            else {
                "required": False,
                "reason": "injected_test_backend",
                "hard_gross_ceiling_usd": "20.000000000",
            }
        ),
    }
    _write_private_json(manifest_path, manifest)

    traces: list[RunTrace] = []
    model_run_counts = [0, 0]
    smoke_backends: list[AgentBackend] = []
    backends: list[AgentBackend] = []
    runners: list[ExperimentRunner] = []
    stage_started = False
    try:
        smoke_backends = [
            (
                backend_factory(
                    model_id,
                    destination / "smoke_raw_responses" / f"model-{index:02d}",
                )
                if backend_factory is not None
                else _default_backend_factory(
                    model_id,
                    destination / "smoke_raw_responses" / f"model-{index:02d}",
                    budget_ledger=budget_ledger,
                    budget_phase="pre_stage_1_smoke",
                )
            )
            for index, model_id in enumerate(models, start=1)
        ]
        _assert_injected_backends_are_offline(smoke_backends, injected_test_backend)
        smoke_attestation = _run_out_of_study_smoke(
            backends=smoke_backends,
            model_ids=models,
            destination=destination,
            repository_freeze=repository_freeze,
            batch_id=batch_id,
            injected_test_backend=injected_test_backend,
            budget_ledger=budget_ledger,
        )
        manifest["smoke_attestation"] = smoke_attestation
        manifest["smoke_calls_completed"] = smoke_attestation["attempt_count"]
        if budget_ledger is not None:
            manifest["budget_ledger"] = budget_ledger.snapshot()
        _write_private_json(manifest_path, manifest)
        _close_backend_clients(smoke_backends)
        smoke_backends = []
        if smoke_attestation.get("pass") is not True:
            raise RuntimeError(
                "Out-of-study provider smoke failed; Stage 1 did not begin"
            )

        backends = [
            (
                backend_factory(
                    model_id,
                    destination / "raw_responses" / f"model-{index:02d}",
                )
                if backend_factory is not None
                else _default_backend_factory(
                    model_id,
                    destination / "raw_responses" / f"model-{index:02d}",
                    budget_ledger=budget_ledger,
                    budget_phase="stage_1_live_feasibility",
                )
            )
            for index, model_id in enumerate(models, start=1)
        ]
        _assert_injected_backends_are_offline(backends, injected_test_backend)
        manifest["backend_configurations"] = [
            dict(backend.configuration) for backend in backends
        ]
        manifest["state"] = "running"
        _write_private_json(manifest_path, manifest)
        runners = [
            ExperimentRunner(
                frozen_scenarios,
                backend,
                provenance_signing_key=provenance_signing_key,
                provenance_key_id=provenance_key_id,
            )
            for backend in backends
        ]
        stage_started = True
        for spec_index, spec in enumerate(specs):
            # Counterbalance which provider is sampled first across adjacent cells.
            runner_order = (0, 1) if (spec_index + spec.seed) % 2 == 0 else (1, 0)
            for runner_index in runner_order:
                model_run_counts[runner_index] += 1
                set_run_metadata = getattr(backends[runner_index], "set_run_metadata", None)
                if callable(set_run_metadata):
                    set_run_metadata(
                        {
                            "scheduled_workflow_run_order": len(traces) + 1,
                            "model_workflow_run_order": model_run_counts[runner_index],
                            "repetition": _repetition_from(spec),
                            "condition_id": spec.condition_id,
                            "invocation_id": spec.invocation_id,
                            "scenario_id": spec.scenario_id,
                            "mechanism": spec.mechanism.value,
                            "mechanism_active": spec.mechanism_active,
                            "safety_variant": spec.safety_variant.value,
                            "protocol_commit_sha": repository_freeze["commit_sha"],
                            "protocol_sha256": repository_freeze["protocol_sha256"],
                            "batch_id": batch_id,
                        }
                    )
                trace = runners[runner_index].run(spec)
                _assert_trace_matches_freeze(
                    trace,
                    batch_id=batch_id,
                    frozen_components=frozen_components,
                    frozen_scenario_hashes=frozen_scenario_hashes,
                )
                traces.append(trace)
                _append_private_trace(trace_path, trace)
                manifest["workflow_runs_completed"] = len(traces)
                manifest["agent_calls_completed"] = sum(
                    len(item.steps) for item in traces
                )
                if budget_ledger is not None:
                    manifest["budget_ledger"] = budget_ledger.snapshot()
                _write_private_json(manifest_path, manifest)
    except BaseException as exc:
        _close_backend_clients((*smoke_backends, *backends))
        budget_audit = _budget_audit(budget_ledger, injected_test_backend)
        manifest.update(
            {
                "state": "aborted" if stage_started else "smoke_failed",
                "completed_at_utc": _utc_now(),
                "abort_error_type": type(exc).__name__,
                "budget_ledger": (
                    budget_ledger.snapshot()
                    if budget_ledger is not None
                    else manifest["budget_ledger"]
                ),
                "budget_ledger_audit": budget_audit,
            }
        )
        _write_private_json(manifest_path, manifest)
        abort_analysis_error_type: str | None = None
        if traces:
            try:
                raw_archive_audit = _raw_archive_audit(
                    destination,
                    traces,
                    models,
                    repository_freeze=repository_freeze,
                    required=not injected_test_backend,
                )
                analyze_live_development(
                    traces,
                    destination,
                    requested_model_ids=models,
                    hard_qa_attestation=hard_qa_attestation,
                    raw_archive_audit=raw_archive_audit,
                    smoke_attestation=(
                        manifest["smoke_attestation"]
                        if isinstance(manifest.get("smoke_attestation"), dict)
                        else None
                    ),
                    budget_audit=budget_audit,
                )
            except BaseException as analysis_exc:  # noqa: BLE001
                # Partial-batch analysis is best-effort and must never replace the
                # original provider/runtime failure being re-raised below.
                abort_analysis_error_type = type(analysis_exc).__name__
        analysis_artifacts_invalidated = _invalidate_live_analysis_report(
            destination,
            abort_error_type=type(exc).__name__,
        )
        manifest["analysis_artifacts_invalidated"] = analysis_artifacts_invalidated
        if abort_analysis_error_type is not None:
            manifest["abort_analysis_error_type"] = abort_analysis_error_type
        _write_private_json(manifest_path, manifest)
        raise

    try:
        _close_backend_clients(backends)
        backends = []
        if budget_ledger is not None:
            budget_ledger.assert_quiescent()
        budget_audit = _budget_audit(budget_ledger, injected_test_backend)
        if budget_audit.get("pass") is not True:
            raise RuntimeError("Private live budget ledger audit failed")
        if not injected_test_backend:
            _assert_repository_freeze_unchanged(
                repository_freeze,
                context="during the live batch",
            )
        if frozen_program_hashes() != frozen_components:
            raise RuntimeError(
                "A frozen program or schema component changed during the live batch"
            )
        if _scenario_hashes(frozen_scenarios) != frozen_scenario_hashes:
            raise RuntimeError("A frozen scenario object changed during the live batch")

        raw_archive_audit = _raw_archive_audit(
            destination,
            traces,
            models,
            repository_freeze=repository_freeze,
            required=not injected_test_backend,
        )
        report = analyze_live_development(
            traces,
            destination,
            requested_model_ids=models,
            hard_qa_attestation=hard_qa_attestation,
            raw_archive_audit=raw_archive_audit,
            smoke_attestation=(
                manifest["smoke_attestation"]
                if isinstance(manifest.get("smoke_attestation"), dict)
                else None
            ),
            budget_audit=budget_audit,
        )
        if not injected_test_backend:
            _assert_repository_freeze_unchanged(
                repository_freeze,
                context="during live-batch finalization",
            )
        if frozen_program_hashes() != frozen_components:
            raise RuntimeError(
                "A frozen program or schema component changed during finalization"
            )
        if _scenario_hashes(frozen_scenarios) != frozen_scenario_hashes:
            raise RuntimeError(
                "A frozen scenario object changed during live-batch finalization"
            )
        component_hash_sets = {
            json.dumps(trace.component_hashes, sort_keys=True) for trace in traces
        }
        manifest.update(
            {
                "state": "completed",
                "completed_at_utc": _utc_now(),
                "workflow_runs_completed": len(traces),
                "agent_calls_completed": sum(len(trace.steps) for trace in traces),
                "resolved_response_models": sorted(
                    {
                        str(step.provider_metadata["resolved_response_model"])
                        for trace in traces
                        for step in trace.steps
                        if step.provider_metadata.get("resolved_response_model")
                    }
                ),
                "component_hash_sets": [
                    json.loads(item) for item in sorted(component_hash_sets)
                ],
                "raw_archive_audit": raw_archive_audit,
                "budget_ledger": (
                    budget_ledger.snapshot()
                    if budget_ledger is not None
                    else manifest["budget_ledger"]
                ),
                "budget_ledger_audit": budget_audit,
                "trace_file_sha256": raw_archive_audit.get("trace_file_sha256"),
                "development_gate_decision": report["decision"],
            }
        )
        _write_private_json(manifest_path, manifest)
        return report
    except BaseException as exc:
        _close_backend_clients(backends)
        analysis_artifacts_invalidated = _invalidate_live_analysis_report(
            destination,
            abort_error_type=type(exc).__name__,
        )
        manifest.update(
            {
                "state": "aborted",
                "completed_at_utc": _utc_now(),
                "abort_error_type": type(exc).__name__,
                "analysis_artifacts_invalidated": analysis_artifacts_invalidated,
                "budget_ledger": (
                    budget_ledger.snapshot()
                    if budget_ledger is not None
                    else manifest["budget_ledger"]
                ),
                "budget_ledger_audit": _budget_audit(
                    budget_ledger, injected_test_backend
                ),
            }
        )
        _write_private_json(manifest_path, manifest)
        raise


class _RequestSizingBackend:
    """Offline all-execute backend that sizes the exact frozen provider request."""

    name = "request_sizing_no_external_io"

    def __init__(self, model_id: str) -> None:
        self.model_id = model_id
        self.configuration: dict[str, object] = {
            "test_only_no_external_io": True,
            "mode": "request_sizing",
        }
        self.request_utf8_bytes: list[int] = []

    def decide(
        self,
        *,
        context: StageContext,
        decision_mode: DecisionMode,
        candidate_action: ActionSpec,
        offered_actions: tuple[ActionSpec, ...],
        artifact: object,
        seed: int,
    ) -> AgentDecision:
        del seed
        request, _prompt = build_frozen_provider_request(
            model_id=self.model_id,
            context=context,
            decision_mode=decision_mode,
            candidate_action=candidate_action,
            offered_actions=offered_actions,
            artifact=artifact,  # type: ignore[arg-type]
        )
        canonical = json.dumps(request, sort_keys=True, separators=(",", ":"))
        self.request_utf8_bytes.append(len(canonical.encode("utf-8")))
        return AgentDecision.execute(candidate_action)


def _stage_one_cost_preflight(
    scenarios: Sequence[Scenario],
    specs: Sequence[RunSpec],
    requested_model_ids: Sequence[str],
) -> dict[str, object]:
    """Conservatively price all maximum-output calls without network access."""

    del requested_model_ids
    per_model: list[dict[str, object]] = []
    total_cost = 0
    total_calls = 0
    maximum_request_bytes = 0
    for model_id in FROZEN_MODEL_IDS:
        backend = _RequestSizingBackend(model_id)
        runner = ExperimentRunner(
            scenarios,
            backend,
            provenance_signing_key=b"k" * 32,
            provenance_key_id="offline-request-sizing-v1",
        )
        for spec in specs:
            runner.run(spec)
        smoke_context, smoke_action = _smoke_fixture("0" * 24)
        smoke_request, _ = build_frozen_provider_request(
            model_id=model_id,
            context=smoke_context,
            decision_mode=DecisionMode.EXECUTION_DECISION,
            candidate_action=smoke_action,
            offered_actions=(smoke_action,),
            artifact=None,
        )
        smoke_bytes = len(
            json.dumps(
                smoke_request, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        )
        request_sizes = [*backend.request_utf8_bytes, smoke_bytes]
        model_cost = sum(
            estimate_standard_cost_nano_usd(
                model_id,
                input_tokens=size,
                output_tokens=FROZEN_OUTPUT_RESERVATION_TOKENS,
            )
            for size in request_sizes
        )
        total_cost += model_cost
        total_calls += len(request_sizes)
        maximum_request_bytes = max(maximum_request_bytes, max(request_sizes))
        per_model.append(
            {
                "model_id": model_id,
                "stage_1_calls": len(backend.request_utf8_bytes),
                "smoke_calls": 1,
                "maximum_request_utf8_bytes": max(request_sizes),
                "total_request_utf8_bytes": sum(request_sizes),
                "byte_upper_bound_cost_nano_usd": model_cost,
                "byte_upper_bound_cost_usd": _nano_usd_string(model_cost),
            }
        )
    if total_calls != EXPECTED_RUNS * 4 + len(FROZEN_MODEL_IDS):
        raise RuntimeError("Offline sizing did not enumerate the frozen maximum calls")
    return {
        "method": (
            "each canonical provider-request UTF-8 byte is priced as one full-rate "
            "input token and every call is assigned the full 512 output tokens"
        ),
        "includes_out_of_study_smoke": True,
        "calls_sized": total_calls,
        "stage_1_calls_sized": EXPECTED_RUNS * 4,
        "smoke_calls_sized": len(FROZEN_MODEL_IDS),
        "maximum_request_utf8_bytes": maximum_request_bytes,
        "byte_upper_bound_cost_nano_usd": total_cost,
        "byte_upper_bound_cost_usd": _nano_usd_string(total_cost),
        "hard_ceiling_nano_usd": FROZEN_GROSS_CEILING_NANO_USD,
        "hard_ceiling_usd": _nano_usd_string(FROZEN_GROSS_CEILING_NANO_USD),
        "fits_authorization": total_cost <= FROZEN_GROSS_CEILING_NANO_USD,
        "models": per_model,
    }


def _smoke_fixture(nonce: str) -> tuple[StageContext, ActionSpec]:
    policy_id = "out_of_study.smoke.no_side_effect.v1"
    context = StageContext(
        role=Role.PLANNER,
        task=(
            "Perform an out-of-study provider compatibility check by selecting "
            "the single offered acknowledgement action."
        ),
        objective_view="Validate API access and strict response parsing only.",
        visible_facts={
            "healthcheck_nonce": nonce,
            "external_side_effects": False,
            "study_observation": False,
        },
        local_policy_id=policy_id,
        local_policy_contract=(
            "Execute the offered acknowledgement only when it has no external "
            "side effects and repeats the visible healthcheck nonce."
        ),
        restriction_visible=True,
        restriction_text="Do not perform tools, network actions, or study workflows.",
        shareable_message="Synthetic provider compatibility healthcheck.",
        public_evidence={"out_of_study": True, "no_side_effects": True},
        applicable_policy_ids=(policy_id,),
        applicable_policy_contracts=((
            policy_id,
            "Only the nonce-bound no-effect acknowledgement is permitted.",
        ),),
    )
    action = ActionSpec(
        role=Role.PLANNER,
        name="acknowledge_no_side_effect_healthcheck",
        terminal=False,
        parameters={"healthcheck_nonce": nonce, "external_side_effects": False},
    )
    return context, action


def _run_out_of_study_smoke(
    *,
    backends: Sequence[AgentBackend],
    model_ids: Sequence[str],
    destination: Path,
    repository_freeze: dict[str, object],
    batch_id: str,
    injected_test_backend: bool,
    budget_ledger: LiveBudgetLedger | None,
) -> dict[str, object]:
    if len(backends) != len(model_ids) or len(backends) != 2:
        raise ValueError("Smoke requires exactly one backend per frozen model")
    records: list[dict[str, object]] = []
    for index, (backend, model_id) in enumerate(zip(backends, model_ids), start=1):
        nonce = hashlib.sha256(
            (
                f"v0.2.1-smoke|{repository_freeze['commit_sha']}|{model_id}|{index}"
            ).encode()
        ).hexdigest()[:24]
        context, action = _smoke_fixture(nonce)
        set_run_metadata = getattr(backend, "set_run_metadata", None)
        if callable(set_run_metadata):
            set_run_metadata(
                {
                    "scheduled_workflow_run_order": 0,
                    "model_workflow_run_order": 0,
                    "repetition": 0,
                    "condition_id": f"out-of-study-smoke-{index:02d}",
                    "invocation_id": f"smoke-{nonce}",
                    "scenario_id": "out_of_study.provider_compatibility_smoke",
                    "mechanism": "none_out_of_study",
                    "mechanism_active": False,
                    "safety_variant": "safe_no_side_effect",
                    "protocol_commit_sha": repository_freeze["commit_sha"],
                    "protocol_sha256": repository_freeze["protocol_sha256"],
                    "batch_id": batch_id,
                }
            )
        decision: AgentDecision | None = None
        error_type: str | None = None
        provider_metadata: dict[str, object] = {}
        try:
            result = backend.decide(
                context=context,
                decision_mode=DecisionMode.EXECUTION_DECISION,
                candidate_action=action,
                offered_actions=(action,),
                artifact=None,
                seed=index,
            )
            if isinstance(result, AgentDecision):
                decision = result
                if isinstance(result.provider_metadata, dict):
                    provider_metadata = dict(result.provider_metadata)
        except Exception as exc:  # noqa: BLE001 - smoke records class only
            error_type = type(exc).__name__
            metadata = getattr(exc, "provider_metadata", None)
            if isinstance(metadata, dict):
                provider_metadata = dict(metadata)

        raw_checks = _smoke_raw_record_checks(
            backend=backend,
            provider_metadata=provider_metadata,
            injected_test_backend=injected_test_backend,
        )
        checks = {
            "one_attempt": True,
            "typed_decision": decision is not None,
            "execute_no_effect_acknowledgement": (
                decision is not None
                and decision.kind is AgentDecisionKind.EXECUTE
                and decision.action == action
            ),
            "response_completed": provider_metadata.get("status") == "completed",
            "exact_resolved_snapshot": (
                provider_metadata.get("resolved_response_model") == model_id
            ),
            "strict_schema_parser_valid": (
                provider_metadata.get("structured_output_valid") is True
            ),
            "standard_service_tier": (
                injected_test_backend
                or provider_metadata.get("service_tier") == FROZEN_SERVICE_TIER
            ),
            "valid_positive_usage": (
                decision is not None
                and type(decision.input_tokens) is int
                and decision.input_tokens > 0
                and type(decision.output_tokens) is int
                and decision.output_tokens > 0
            ),
            "private_raw_records_valid": raw_checks.get("pass") is True,
        }
        records.append(
            {
                "model_index": index,
                "requested_model_id": model_id,
                "resolved_model_id": provider_metadata.get(
                    "resolved_response_model"
                ),
                "attempt_count": 1,
                "error_type": error_type,
                "decision_kind": (
                    decision.kind.value if decision is not None else None
                ),
                "input_tokens": (
                    decision.input_tokens if decision is not None else None
                ),
                "output_tokens": (
                    decision.output_tokens if decision is not None else None
                ),
                "response_id": provider_metadata.get("response_id"),
                "request_id": provider_metadata.get("request_id"),
                "prompt_sha256": provider_metadata.get("prompt_sha256"),
                "provider_request_sha256": provider_metadata.get(
                    "provider_request_sha256"
                ),
                "raw_log_record": provider_metadata.get("raw_log_record"),
                "raw_record_checks": raw_checks,
                "checks": checks,
                "pass": all(checks.values()),
            }
        )

    budget_snapshot = budget_ledger.snapshot() if budget_ledger is not None else None
    budget_checks = {
        "shared_ledger_present": injected_test_backend or budget_ledger is not None,
        "exactly_two_reservations": (
            injected_test_backend
            or (
                isinstance(budget_snapshot, dict)
                and budget_snapshot.get("reservations_held_total") == 2
            )
        ),
        "no_active_reservation": (
            injected_test_backend
            or (
                isinstance(budget_snapshot, dict)
                and budget_snapshot.get("active_reservations") == 0
            )
        ),
        "within_hard_ceiling": (
            injected_test_backend
            or (
                isinstance(budget_snapshot, dict)
                and isinstance(
                    budget_snapshot.get("gross_exposure_nano_usd"), int
                )
                and int(budget_snapshot["gross_exposure_nano_usd"])
                <= FROZEN_GROSS_CEILING_NANO_USD
            )
        ),
    }
    attestation = {
        "schema_version": "0.2.1",
        "stage": "pre_stage_1_out_of_study_provider_smoke",
        "out_of_study": True,
        "included_in_stage_1_scheduled_runs": False,
        "included_in_estimands_or_gates": False,
        "included_in_model_behavior_claims": False,
        "uses_study_workflow_or_mechanism_content": False,
        "automatic_retries": 0,
        "replacement_calls": 0,
        "attempt_count": len(records),
        "expected_attempt_count": 2,
        "request_configuration": {
            "reasoning_effort": FROZEN_REASONING_EFFORT,
            "max_output_tokens": FROZEN_MAX_OUTPUT_TOKENS,
            "service_tier": FROZEN_SERVICE_TIER,
        },
        "calls": records,
        "budget_checks": budget_checks,
        "budget_after_smoke": budget_snapshot,
        "pass": (
            len(records) == 2
            and all(record["pass"] is True for record in records)
            and all(budget_checks.values())
        ),
    }
    _write_private_json(destination / "smoke_attestation.json", attestation)
    return attestation


def _smoke_raw_record_checks(
    *,
    backend: AgentBackend,
    provider_metadata: dict[str, object],
    injected_test_backend: bool,
) -> dict[str, object]:
    if injected_test_backend:
        return {
            "required": False,
            "pass": True,
            "reason": "injected_test_backend",
        }
    raw_dir = getattr(backend, "raw_log_dir", None)
    stem = provider_metadata.get("raw_log_record")
    checks = {
        "linked_record_name": isinstance(stem, str) and bool(stem),
        "request_present": False,
        "response_present": False,
        "request_record_hash_matches": False,
        "result_record_hash_matches": False,
        "frozen_request_configuration": False,
        "no_study_fixture_identifiers": False,
    }
    if not isinstance(raw_dir, Path) or not isinstance(stem, str) or not stem:
        return {"required": True, "pass": False, "checks": checks}
    request_path = raw_dir / f"{stem}.request.json"
    response_path = raw_dir / f"{stem}.response.json"
    checks["request_present"] = request_path.is_file()
    checks["response_present"] = response_path.is_file()
    try:
        request_record = json.loads(request_path.read_text(encoding="utf-8"))
        provider_request = request_record["provider_request"]
        request_text = json.dumps(provider_request, sort_keys=True)
        checks["request_record_hash_matches"] = (
            hashlib.sha256(request_path.read_bytes()).hexdigest()
            == provider_metadata.get("request_record_sha256")
        )
        checks["frozen_request_configuration"] = (
            provider_request.get("reasoning")
            == {"effort": FROZEN_REASONING_EFFORT}
            and provider_request.get("max_output_tokens")
            == FROZEN_MAX_OUTPUT_TOKENS
            and provider_request.get("service_tier") == FROZEN_SERVICE_TIER
            and provider_request.get("store") is False
        )
        forbidden = [
            *DEVELOPMENT_SCENARIO_IDS,
            *(mechanism.value for mechanism in Mechanism),
        ]
        checks["no_study_fixture_identifiers"] = not any(
            item in request_text for item in forbidden
        )
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        pass
    try:
        checks["result_record_hash_matches"] = (
            hashlib.sha256(response_path.read_bytes()).hexdigest()
            == provider_metadata.get("result_record_sha256")
        )
    except OSError:
        pass
    return {"required": True, "pass": all(checks.values()), "checks": checks}


def _assert_injected_backends_are_offline(
    backends: Sequence[AgentBackend], injected_test_backend: bool
) -> None:
    if injected_test_backend and any(
        getattr(backend, "configuration", {}).get("test_only_no_external_io")
        is not True
        for backend in backends
    ):
        raise ValueError(
            "The internal injected-backend path accepts only explicitly marked "
            "no-external-I/O test doubles"
        )


def _close_backend_clients(backends: Sequence[AgentBackend]) -> None:
    for backend in backends:
        client = getattr(backend, "_client", None)
        close = getattr(client, "close", None)
        if callable(close):
            try:
                close()
            except Exception:  # noqa: BLE001, S110 - cleanup cannot alter outcome
                pass


def _budget_audit(
    ledger: LiveBudgetLedger | None, injected_test_backend: bool
) -> dict[str, object]:
    if injected_test_backend:
        return {
            "required": False,
            "pass": True,
            "reason": "injected_test_backend",
            "committed_usd": "0.000000000",
        }
    if ledger is None:
        return {"required": True, "pass": False, "reason": "ledger_missing"}
    audit = audit_budget_ledger(ledger.path)
    snapshot = ledger.snapshot()
    ceiling_exact = (
        audit.get("ceiling_nano_usd") == FROZEN_GROSS_CEILING_NANO_USD
    )
    terminal_snapshot_matches = (
        audit.get("event_count") == snapshot.get("event_count")
        and audit.get("last_event_sha256")
        == snapshot.get("last_event_sha256")
        and audit.get("committed_nano_usd")
        == snapshot.get("committed_nano_usd")
        and audit.get("held_nano_usd") == snapshot.get("held_nano_usd")
        and audit.get("remaining_authority_nano_usd")
        == snapshot.get("remaining_authority_nano_usd")
        and audit.get("active_reservations")
        == snapshot.get("active_reservations")
    )
    audit["checks"]["hard_gross_ceiling_exact"] = ceiling_exact  # type: ignore[index]
    audit["checks"]["terminal_matches_live_snapshot"] = terminal_snapshot_matches  # type: ignore[index]
    audit["pass"] = (
        audit.get("pass") is True and ceiling_exact and terminal_snapshot_matches
    )
    return {"required": True, **audit}


def _nano_usd_string(value: int) -> str:
    whole, fractional = divmod(value, 1_000_000_000)
    return f"{whole}.{fractional:09d}"


def _default_backend_factory(
    model_id: str,
    raw_log_dir: Path,
    *,
    budget_ledger: LiveBudgetLedger | None,
    budget_phase: str,
) -> AgentBackend:
    if budget_ledger is None:
        raise ValueError("Production provider backends require the shared budget ledger")
    return OpenAIResponsesBackend(
        model_id=model_id,
        raw_log_dir=raw_log_dir,
        budget_ledger=budget_ledger,
        budget_phase=budget_phase,
    )


def _spec_hash(specs: Sequence[RunSpec]) -> str:
    payload = [
        {
            "condition_id": spec.condition_id,
            "seed": spec.seed,
            "invocation_id": spec.invocation_id,
        }
        for spec in specs
    ]
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _new_batch_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"stage1-{timestamp}-{uuid.uuid4().hex[:12]}"


def _scenario_hashes(scenarios: Sequence[Scenario]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for scenario in scenarios:
        if scenario.scenario_id in hashes:
            raise ValueError("Stage 1 scenario identifiers must be unique")
        canonical = json.dumps(
            asdict(scenario), sort_keys=True, separators=(",", ":"), default=str
        )
        hashes[scenario.scenario_id] = (
            "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        )
    return dict(sorted(hashes.items()))


def _assert_trace_matches_freeze(
    trace: RunTrace,
    *,
    batch_id: str,
    frozen_components: dict[str, object],
    frozen_scenario_hashes: dict[str, str],
) -> None:
    if trace.batch_id != batch_id:
        raise RuntimeError("Trace batch identity differs from the frozen live batch")
    expected_scenario_hash = frozen_scenario_hashes.get(trace.scenario_id)
    if trace.component_hashes.get("scenario") != expected_scenario_hash:
        raise RuntimeError("Trace scenario content differs from the frozen snapshot")
    if any(
        trace.component_hashes.get(key) != value
        for key, value in frozen_components.items()
    ):
        raise RuntimeError("Trace program/schema hashes differ from the batch preflight")


def _run_hard_qa_attestation(
    repository_freeze: dict[str, object],
) -> dict[str, object]:
    repository_root = _git_repository_root(required=True)
    assert repository_root is not None
    started_at = _utc_now()
    with tempfile.TemporaryDirectory(prefix="mas-safety-hard-qa-") as qa_temp:
        qa_temp_path = Path(qa_temp)
        junit_path = qa_temp_path / "pytest-report.xml"
        qa_home = qa_temp_path / "home"
        qa_home.mkdir(mode=0o700)
        qa_environment = {
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "LANG", "LC_ALL", "TMPDIR", "TZ", "SYSTEMROOT"}
        }
        qa_environment.update(
            {
                "HOME": str(qa_home),
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            }
        )
        command = (
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests",
            "--override-ini=addopts=",
            "-p",
            "no:cacheprovider",
            f"--junitxml={junit_path}",
        )
        try:
            process = subprocess.run(
                command,
                cwd=repository_root,
                env=qa_environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                "Frozen hard-QA test suite exceeded its 300-second limit"
            ) from exc
        try:
            test_cases = ElementTree.parse(junit_path).findall(".//testcase")
        except (OSError, ElementTree.ParseError) as exc:
            raise RuntimeError(
                "Frozen hard-QA suite did not produce a valid execution report"
            ) from exc
        executed_test_count = len(test_cases)
        sentinel_executed = any(
            case.attrib.get("name") == HARD_QA_SENTINEL_NAME for case in test_cases
        )
    completed_at = _utc_now()
    captured = f"{process.stdout}\n{process.stderr}"
    passed = (
        process.returncode == 0
        and executed_test_count == HARD_QA_EXPECTED_TESTS
        and sentinel_executed
    )
    attestation = {
        "required": True,
        "pass": passed,
        "command": [
            "python",
            "-m",
            "pytest",
            "-q",
            "tests",
            "--override-ini=addopts=",
            "-p",
            "no:cacheprovider",
            "--junitxml=<private-temporary-path>",
        ],
        "commit_sha": repository_freeze["commit_sha"],
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "return_code": process.returncode,
        "expected_test_count": HARD_QA_EXPECTED_TESTS,
        "executed_test_count": executed_test_count,
        "sentinel_executed": sentinel_executed,
        "ambient_pytest_controls_removed": True,
        "plugin_autoload_disabled": True,
        "captured_output_sha256": hashlib.sha256(
            captured.encode("utf-8")
        ).hexdigest(),
    }
    if not passed:
        raise RuntimeError(
            "Frozen hard-QA assertions, exact test count, or execution sentinel "
            "failed; no live provider client was created"
        )
    return attestation


def _assert_repository_freeze_unchanged(
    repository_freeze: dict[str, object], *, context: str
) -> None:
    if _repository_freeze_metadata() != repository_freeze:
        raise RuntimeError(
            f"Repository commit, worktree, or protocol hash changed {context}"
        )


def _raw_archive_audit(
    destination: Path,
    traces: Sequence[RunTrace],
    model_ids: Sequence[str],
    *,
    repository_freeze: dict[str, object],
    required: bool,
) -> dict[str, object]:
    if not required:
        return {
            "required": False,
            "pass": True,
            "reason": "injected_test_backend",
            "checks": {"explicit_test_exemption": True},
        }

    checks = {
        "model_directories_present": True,
        "every_step_has_unique_raw_link": True,
        "request_set_matches_trace_links": True,
        "one_response_or_error_per_request": True,
        "response_error_kind_matches_trace": True,
        "request_hashes_recompute_and_match_trace": True,
        "result_records_parse_hash_and_match_trace": True,
        "frozen_request_configuration_exact": True,
        "every_attempt_linked_to_budget_event": True,
        "raw_budget_links_match_ledger": True,
        "ledger_provider_attempt_set_matches_raw_records": True,
        "raw_usage_matches_ledger_and_trace": True,
        "smoke_budget_links_match_ledger": True,
        "private_response_service_tier_default": True,
        "no_orphan_or_unexpected_records": True,
        "private_file_permissions": True,
        "persisted_trace_matches_memory": True,
    }
    request_count = 0
    response_count = 0
    error_count = 0
    expected_call_count = sum(len(trace.steps) for trace in traces)
    trace_path = destination / "traces.jsonl"
    trace_file_sha256: str | None = None
    ledger_events_by_sequence: dict[int, dict[str, object]] = {}
    ledger_events_by_hash: dict[str, dict[str, object]] = {}
    ledger_terminal_reservations: dict[str, set[str]] = {
        "pre_stage_1_smoke": set(),
        "stage_1_live_feasibility": set(),
    }
    seen_stage_reservations: set[str] = set()
    seen_stage_result_reservations: set[str] = set()
    seen_stage_result_hashes: set[str] = set()
    try:
        ledger_path = destination / "budget_ledger.jsonl"
        ledger_events = [
            json.loads(line)
            for line in ledger_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        for event in ledger_events:
            sequence = event.get("sequence")
            event_hash = event.get("event_sha256")
            if (
                type(sequence) is not int
                or not isinstance(event_hash, str)
                or sequence in ledger_events_by_sequence
                or event_hash in ledger_events_by_hash
            ):
                checks["raw_budget_links_match_ledger"] = False
                continue
            ledger_events_by_sequence[sequence] = event
            ledger_events_by_hash[event_hash] = event
            if event.get("event") in {
                "reservation_settled",
                "reservation_forfeited",
            }:
                phase = event.get("phase")
                reservation_id = event.get("reservation_id")
                if (
                    isinstance(phase, str)
                    and phase in ledger_terminal_reservations
                    and isinstance(reservation_id, str)
                    and reservation_id
                    not in ledger_terminal_reservations[phase]
                ):
                    ledger_terminal_reservations[phase].add(reservation_id)
                else:
                    checks["ledger_provider_attempt_set_matches_raw_records"] = False
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError):
        checks["raw_budget_links_match_ledger"] = False
        checks["ledger_provider_attempt_set_matches_raw_records"] = False
        checks["smoke_budget_links_match_ledger"] = False
    try:
        trace_bytes = trace_path.read_bytes()
        trace_file_sha256 = hashlib.sha256(trace_bytes).hexdigest()
        persisted_traces = [
            json.loads(line)
            for line in trace_bytes.decode("utf-8").splitlines()
            if line.strip()
        ]
        if persisted_traces != [trace.to_dict() for trace in traces]:
            checks["persisted_trace_matches_memory"] = False
        if trace_path.stat().st_mode & 0o077:
            checks["private_file_permissions"] = False
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        checks["persisted_trace_matches_memory"] = False
    scheduled_orders = {
        trace.run_id: index for index, trace in enumerate(traces, start=1)
    }
    model_orders = {
        trace.run_id: index
        for model_id in model_ids
        for index, trace in enumerate(
            (item for item in traces if item.model_id == model_id), start=1
        )
    }

    seen_smoke_reservations: set[str] = set()
    seen_smoke_results: set[str] = set()
    smoke_required = (
        tuple(model_ids) == FROZEN_MODEL_IDS
        or bool(ledger_terminal_reservations["pre_stage_1_smoke"])
    )
    if smoke_required:
        for model_index, model_id in enumerate(model_ids, start=1):
            smoke_dir = (
                destination
                / "smoke_raw_responses"
                / f"model-{model_index:02d}"
            )
            if not smoke_dir.is_dir():
                checks["smoke_budget_links_match_ledger"] = False
                continue
            smoke_files = [path for path in smoke_dir.iterdir() if path.is_file()]
            smoke_requests = [
                path for path in smoke_files if path.name.endswith(".request.json")
            ]
            smoke_responses = [
                path for path in smoke_files if path.name.endswith(".response.json")
            ]
            if (
                len(smoke_requests) != 1
                or len(smoke_responses) != 1
                or len(smoke_files) != 2
            ):
                checks["smoke_budget_links_match_ledger"] = False
                continue
            request_path = smoke_requests[0]
            response_path = smoke_responses[0]
            stem = request_path.name.removesuffix(".request.json")
            if response_path.name.removesuffix(".response.json") != stem:
                checks["smoke_budget_links_match_ledger"] = False
                continue
            if any(path.stat().st_mode & 0o077 for path in smoke_files):
                checks["private_file_permissions"] = False
            try:
                request_record = json.loads(request_path.read_text(encoding="utf-8"))
                response_record = json.loads(
                    response_path.read_text(encoding="utf-8")
                )
                provider_request = request_record["provider_request"]
                request_hash = hashlib.sha256(
                    json.dumps(
                        provider_request, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ).hexdigest()
                budget_reservation = request_record["budget_reservation"]
                budget_event = response_record["budget_event"]
                provider_response = response_record["provider_response"]
            except (OSError, KeyError, TypeError, json.JSONDecodeError):
                checks["smoke_budget_links_match_ledger"] = False
                continue
            if not (
                isinstance(provider_request, dict)
                and provider_request.get("model") == model_id
                and provider_request.get("reasoning")
                == {"effort": FROZEN_REASONING_EFFORT}
                and provider_request.get("max_output_tokens")
                == FROZEN_MAX_OUTPUT_TOKENS
                and provider_request.get("service_tier")
                == FROZEN_SERVICE_TIER
                and provider_request.get("store") is False
            ):
                checks["frozen_request_configuration_exact"] = False
            if not (
                isinstance(provider_response, dict)
                and provider_response.get("model") == model_id
                and provider_response.get("status") == "completed"
            ):
                checks["smoke_budget_links_match_ledger"] = False
            if not (
                isinstance(provider_response, dict)
                and provider_response.get("service_tier")
                == FROZEN_SERVICE_TIER
            ):
                checks["private_response_service_tier_default"] = False
            reservation_id = (
                budget_reservation.get("reservation_id")
                if isinstance(budget_reservation, dict)
                else None
            )
            reservation_sequence = (
                budget_reservation.get("event_sequence")
                if isinstance(budget_reservation, dict)
                else None
            )
            ledger_reservation = (
                ledger_events_by_sequence.get(reservation_sequence)
                if type(reservation_sequence) is int
                else None
            )
            reservation_fields = (
                "reservation_id",
                "phase",
                "model_id",
                "call_stem",
                "request_sha256",
                "request_utf8_bytes",
                "input_token_bound",
                "output_token_bound",
                "reserved_nano_usd",
            )
            reservation_matches = (
                isinstance(budget_reservation, dict)
                and isinstance(reservation_id, str)
                and reservation_id not in seen_smoke_reservations
                and budget_reservation.get("phase") == "pre_stage_1_smoke"
                and budget_reservation.get("model_id") == model_id
                and budget_reservation.get("call_stem") == stem
                and budget_reservation.get("request_sha256") == request_hash
                and request_record.get("provider_request_sha256") == request_hash
                and isinstance(ledger_reservation, dict)
                and ledger_reservation.get("event") == "reservation_held"
                and all(
                    ledger_reservation.get(key) == budget_reservation.get(key)
                    for key in reservation_fields
                )
            )
            if not reservation_matches:
                checks["smoke_budget_links_match_ledger"] = False
            elif isinstance(reservation_id, str):
                seen_smoke_reservations.add(reservation_id)

            event_hash = (
                budget_event.get("event_sha256")
                if isinstance(budget_event, dict)
                else None
            )
            event_sequence = (
                budget_event.get("sequence")
                if isinstance(budget_event, dict)
                else None
            )
            result_matches = (
                isinstance(budget_event, dict)
                and isinstance(reservation_id, str)
                and reservation_id not in seen_smoke_results
                and budget_event.get("reservation_id") == reservation_id
                and budget_event.get("phase") == "pre_stage_1_smoke"
                and budget_event.get("model_id") == model_id
                and budget_event.get("call_stem") == stem
                and budget_event.get("request_sha256") == request_hash
                and budget_event.get("event") == "reservation_settled"
                and isinstance(event_hash, str)
                and ledger_events_by_hash.get(event_hash) == budget_event
                and type(event_sequence) is int
                and ledger_events_by_sequence.get(event_sequence) == budget_event
            )
            if not result_matches:
                checks["smoke_budget_links_match_ledger"] = False
            elif isinstance(reservation_id, str):
                seen_smoke_results.add(reservation_id)

            usage = (
                provider_response.get("usage")
                if isinstance(provider_response, dict)
                else None
            )
            if not (
                isinstance(usage, dict)
                and isinstance(budget_event, dict)
                and type(usage.get("input_tokens")) is int
                and type(usage.get("output_tokens")) is int
                and usage.get("input_tokens") == budget_event.get("input_tokens")
                and usage.get("output_tokens") == budget_event.get("output_tokens")
            ):
                checks["raw_usage_matches_ledger_and_trace"] = False

        if not (
            seen_smoke_reservations
            == ledger_terminal_reservations["pre_stage_1_smoke"]
            and seen_smoke_results
            == ledger_terminal_reservations["pre_stage_1_smoke"]
        ):
            checks["smoke_budget_links_match_ledger"] = False

    for model_index, model_id in enumerate(model_ids, start=1):
        raw_dir = destination / "raw_responses" / f"model-{model_index:02d}"
        if not raw_dir.is_dir():
            checks["model_directories_present"] = False
            continue
        model_trace_steps = [
            (trace, step)
            for trace in traces
            if trace.model_id == model_id
            for step in trace.steps
        ]
        links = [
            step.provider_metadata.get("raw_log_record")
            for _trace, step in model_trace_steps
        ]
        string_links = [item for item in links if isinstance(item, str) and item]
        if len(string_links) != len(model_trace_steps) or len(
            set(string_links)
        ) != len(string_links):
            checks["every_step_has_unique_raw_link"] = False
        call_orders = [
            step.provider_metadata.get("call_order")
            for _trace, step in model_trace_steps
        ]
        if sorted(item for item in call_orders if isinstance(item, int)) != list(
            range(1, len(model_trace_steps) + 1)
        ):
            checks["request_hashes_recompute_and_match_trace"] = False

        files = [path for path in raw_dir.iterdir() if path.is_file()]
        requests = {
            path.name.removesuffix(".request.json"): path
            for path in files
            if path.name.endswith(".request.json")
        }
        responses = {
            path.name.removesuffix(".response.json"): path
            for path in files
            if path.name.endswith(".response.json")
        }
        errors = {
            path.name.removesuffix(".error.json"): path
            for path in files
            if path.name.endswith(".error.json")
        }
        request_count += len(requests)
        response_count += len(responses)
        error_count += len(errors)

        if set(requests) != set(string_links):
            checks["request_set_matches_trace_links"] = False
        if any((stem in responses) == (stem in errors) for stem in requests):
            checks["one_response_or_error_per_request"] = False
        if (set(responses) | set(errors)) != set(requests):
            checks["no_orphan_or_unexpected_records"] = False
        expected_names = {
            path.name for path in (*requests.values(), *responses.values(), *errors.values())
        }
        if {path.name for path in files} != expected_names:
            checks["no_orphan_or_unexpected_records"] = False
        if any(path.stat().st_mode & 0o077 for path in files):
            checks["private_file_permissions"] = False

        trace_step_by_link = {
            str(step.provider_metadata.get("raw_log_record")): (trace, step)
            for trace, step in model_trace_steps
            if isinstance(step.provider_metadata.get("raw_log_record"), str)
        }
        for stem, request_path in requests.items():
            trace_step = trace_step_by_link.get(stem)
            if trace_step is None:
                checks["request_hashes_recompute_and_match_trace"] = False
                continue
            trace, step = trace_step
            try:
                request_record = json.loads(request_path.read_text(encoding="utf-8"))
                provider_request = request_record["provider_request"]
                prompt = provider_request["input"]
                prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
                request_hash = hashlib.sha256(
                    json.dumps(
                        provider_request, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ).hexdigest()
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                checks["request_hashes_recompute_and_match_trace"] = False
                continue
            if not (
                provider_request.get("reasoning")
                == {"effort": FROZEN_REASONING_EFFORT}
                and provider_request.get("max_output_tokens")
                == FROZEN_MAX_OUTPUT_TOKENS
                and provider_request.get("service_tier") == FROZEN_SERVICE_TIER
                and provider_request.get("store") is False
            ):
                checks["frozen_request_configuration_exact"] = False
            budget_reservation = request_record.get("budget_reservation")
            if not (
                isinstance(budget_reservation, dict)
                and budget_reservation.get("model_id") == model_id
                and budget_reservation.get("call_stem") == stem
                and budget_reservation.get("request_sha256") == request_hash
            ):
                checks["every_attempt_linked_to_budget_event"] = False
            reservation_id = (
                budget_reservation.get("reservation_id")
                if isinstance(budget_reservation, dict)
                else None
            )
            reservation_sequence = (
                budget_reservation.get("event_sequence")
                if isinstance(budget_reservation, dict)
                else None
            )
            ledger_reservation = (
                ledger_events_by_sequence.get(reservation_sequence)
                if type(reservation_sequence) is int
                else None
            )
            reservation_fields = (
                "reservation_id",
                "phase",
                "model_id",
                "call_stem",
                "request_sha256",
                "request_utf8_bytes",
                "input_token_bound",
                "output_token_bound",
                "reserved_nano_usd",
            )
            if not (
                isinstance(budget_reservation, dict)
                and isinstance(reservation_id, str)
                and reservation_id not in seen_stage_reservations
                and budget_reservation.get("phase")
                == "stage_1_live_feasibility"
                and isinstance(ledger_reservation, dict)
                and ledger_reservation.get("event") == "reservation_held"
                and all(
                    ledger_reservation.get(key) == budget_reservation.get(key)
                    for key in reservation_fields
                )
            ):
                checks["raw_budget_links_match_ledger"] = False
            elif isinstance(reservation_id, str):
                seen_stage_reservations.add(reservation_id)
            metadata = step.provider_metadata
            repetition_match = re.fullmatch(
                r"stage1-r(\d{2})-[0-9a-f]{12}", trace.invocation_id
            )
            expected_run_metadata = {
                "scheduled_workflow_run_order": scheduled_orders[trace.run_id],
                "model_workflow_run_order": model_orders[trace.run_id],
                "repetition": (
                    int(repetition_match.group(1)) if repetition_match else None
                ),
                "condition_id": trace.condition_id,
                "invocation_id": trace.invocation_id,
                "scenario_id": trace.scenario_id,
                "mechanism": trace.mechanism.value,
                "mechanism_active": trace.mechanism_active,
                "safety_variant": trace.safety_variant.value,
                "protocol_commit_sha": repository_freeze["commit_sha"],
                "protocol_sha256": repository_freeze["protocol_sha256"],
                "batch_id": trace.batch_id,
            }
            if not (
                request_record.get("record_version") == "0.2.0"
                and request_record.get("provider_call_order")
                == metadata.get("call_order")
                and request_record.get("local_pairing_seed")
                == trace.seed + step.step_index
                and request_record.get("prompt_sha256") == prompt_hash
                and request_record.get("provider_request_sha256") == request_hash
                and metadata.get("prompt_sha256") == prompt_hash
                and metadata.get("provider_request_sha256") == request_hash
                and metadata.get("request_record_sha256")
                == hashlib.sha256(request_path.read_bytes()).hexdigest()
                and request_record.get("run_metadata") == expected_run_metadata
                and all(
                    metadata.get(key) == value
                    for key, value in expected_run_metadata.items()
                )
                and metadata.get("local_pairing_seed")
                == trace.seed + step.step_index
            ):
                checks["request_hashes_recompute_and_match_trace"] = False
            model_response_received = metadata.get("model_response_received")
            if not (
                (
                    model_response_received is True
                    and stem in responses
                    and stem not in errors
                )
                or (
                    model_response_received is False
                    and stem in errors
                    and stem not in responses
                )
            ):
                checks["response_error_kind_matches_trace"] = False
            result_kind = metadata.get("result_record_kind")
            result_path = (
                responses.get(stem)
                if result_kind == "response"
                else errors.get(stem)
                if result_kind == "error"
                else None
            )
            if result_path is None:
                checks["result_records_parse_hash_and_match_trace"] = False
                continue
            try:
                result_record = json.loads(result_path.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError):
                checks["result_records_parse_hash_and_match_trace"] = False
                continue
            if not (
                result_record.get("record_version") == "0.2.0"
                and metadata.get("result_record_sha256")
                == hashlib.sha256(result_path.read_bytes()).hexdigest()
            ):
                checks["result_records_parse_hash_and_match_trace"] = False
            budget_event = result_record.get("budget_event")
            if not (
                isinstance(budget_event, dict)
                and budget_event.get("reservation_id")
                == reservation_id
                and budget_event.get("call_stem") == stem
                and budget_event.get("request_sha256") == request_hash
            ):
                checks["every_attempt_linked_to_budget_event"] = False
            budget_event_hash = (
                budget_event.get("event_sha256")
                if isinstance(budget_event, dict)
                else None
            )
            budget_event_sequence = (
                budget_event.get("sequence")
                if isinstance(budget_event, dict)
                else None
            )
            ledger_result_by_hash = (
                ledger_events_by_hash.get(budget_event_hash)
                if isinstance(budget_event_hash, str)
                else None
            )
            ledger_result_by_sequence = (
                ledger_events_by_sequence.get(budget_event_sequence)
                if type(budget_event_sequence) is int
                else None
            )
            if not (
                isinstance(budget_event, dict)
                and isinstance(budget_event_hash, str)
                and budget_event_hash not in seen_stage_result_hashes
                and isinstance(reservation_id, str)
                and reservation_id not in seen_stage_result_reservations
                and budget_event.get("phase") == "stage_1_live_feasibility"
                and ledger_result_by_hash == budget_event
                and ledger_result_by_sequence == budget_event
                and budget_event.get("event")
                in {"reservation_settled", "reservation_forfeited"}
            ):
                checks["raw_budget_links_match_ledger"] = False
            elif (
                isinstance(budget_event_hash, str)
                and isinstance(reservation_id, str)
            ):
                seen_stage_result_hashes.add(budget_event_hash)
                seen_stage_result_reservations.add(reservation_id)
            if result_kind == "response":
                provider_response = result_record.get("provider_response")
                if not (
                    isinstance(provider_response, dict)
                    and result_record.get("transport_request_id")
                    == metadata.get("request_id")
                    and provider_response.get("id") == metadata.get("response_id")
                    and provider_response.get("model")
                    == metadata.get("resolved_response_model")
                    and provider_response.get("status") == metadata.get("status")
                ):
                    checks["result_records_parse_hash_and_match_trace"] = False
                if not (
                    isinstance(provider_response, dict)
                    and provider_response.get("service_tier")
                    == FROZEN_SERVICE_TIER
                ):
                    checks["private_response_service_tier_default"] = False
                usage = (
                    provider_response.get("usage")
                    if isinstance(provider_response, dict)
                    else None
                )
                if not (
                    isinstance(usage, dict)
                    and isinstance(budget_event, dict)
                    and budget_event.get("event") == "reservation_settled"
                    and type(usage.get("input_tokens")) is int
                    and type(usage.get("output_tokens")) is int
                    and usage.get("input_tokens")
                    == budget_event.get("input_tokens")
                    == step.token_usage.get("input")
                    and usage.get("output_tokens")
                    == budget_event.get("output_tokens")
                    == step.token_usage.get("output")
                ):
                    checks["raw_usage_matches_ledger_and_trace"] = False
            else:
                provider_error_response = result_record.get("provider_error_response")
                if not (
                    result_record.get("error_type") == metadata.get("error_type")
                    and result_record.get("transport_request_id")
                    == metadata.get("request_id")
                    and (provider_error_response is not None)
                    is (metadata.get("response_received") is True)
                ):
                    checks["result_records_parse_hash_and_match_trace"] = False
                if not (
                    isinstance(budget_event, dict)
                    and budget_event.get("event") == "reservation_forfeited"
                    and step.token_usage.get("input") == 0
                    and step.token_usage.get("output") == 0
                ):
                    checks["raw_usage_matches_ledger_and_trace"] = False

    checks["request_set_matches_trace_links"] = bool(
        checks["request_set_matches_trace_links"]
        and request_count == expected_call_count
    )
    if not (
        seen_stage_reservations
        == ledger_terminal_reservations["stage_1_live_feasibility"]
        and seen_stage_result_reservations
        == ledger_terminal_reservations["stage_1_live_feasibility"]
    ):
        checks["ledger_provider_attempt_set_matches_raw_records"] = False
    return {
        "required": True,
        "pass": all(checks.values()),
        "checks": checks,
        "expected_agent_calls": expected_call_count,
        "request_record_count": request_count,
        "response_record_count": response_count,
        "error_record_count": error_count,
        "trace_file_sha256": trace_file_sha256,
    }


def _repetition_from(spec: RunSpec) -> int:
    match = re.fullmatch(r"stage1-r(\d{2})-[0-9a-f]{12}", spec.invocation_id)
    if match is None:
        raise ValueError("Stage 1 invocation ID does not encode its repetition")
    repetition = int(match.group(1))
    if not 1 <= repetition <= EXPECTED_REPETITIONS:
        raise ValueError("Stage 1 invocation repetition is outside the frozen matrix")
    return repetition


def _assert_private_output_destination(destination: Path) -> None:
    repository_root = _git_repository_root(required=False)
    if repository_root is None:
        return
    resolved = destination.resolve()
    try:
        relative = resolved.relative_to(repository_root)
    except ValueError:
        return
    if len(relative.parts) < 3 or relative.parts[:2] != ("outputs", "private"):
        raise ValueError(
            "Live output inside the repository must be a batch-specific child of "
            "outputs/private/"
        )


def _acquire_provider_authority_lock(
    *,
    repository_root: Path | None,
    repository_freeze: dict[str, object],
    batch_id: str,
    destination: Path,
) -> dict[str, object]:
    """Consume the one paid-run authority for this exact protocol commit."""

    if repository_root is None:
        raise RuntimeError("Could not anchor the commit-scoped provider authority")
    commit_sha = repository_freeze.get("commit_sha")
    if not isinstance(commit_sha, str) or not commit_sha:
        raise ValueError("Provider authority requires a frozen commit identity")
    authority_dir = repository_root / "outputs" / "private" / "authorities"
    authority_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = authority_dir / f"{commit_sha}.authority.json"
    payload = {
        "schema_version": "0.2.1",
        "protocol_version": "v0.2.1-live",
        "commit_sha": commit_sha,
        "batch_id": batch_id,
        "created_at_utc": _utc_now(),
        "authorized_gross_ceiling_usd": "20.000000000",
        "scope": "one_pre_stage_1_smoke_plus_stage_1_invocation",
        "rerun_under_same_commit_authorized": False,
        "output_destination_sha256": hashlib.sha256(
            str(destination.resolve()).encode("utf-8")
        ).hexdigest(),
    }
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    try:
        descriptor = os.open(
            lock_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError as exc:
        raise RuntimeError(
            "This protocol commit has already consumed its single paid-run authority; "
            "do not start another provider batch without a new prospective commit"
        ) from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_directory(authority_dir)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    try:
        lock_path.chmod(0o600)
        authority_dir.chmod(0o700)
    except OSError:
        pass
    return {
        "required": True,
        "scope": payload["scope"],
        "commit_sha": commit_sha,
        "batch_id": batch_id,
        "rerun_under_same_commit_authorized": False,
        "lock_record_sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
        "private_lock_location": "outputs/private/authorities/<commit>.authority.json",
    }


def _repository_freeze_metadata() -> dict[str, object]:
    repository_root = _git_repository_root(required=True)
    assert repository_root is not None
    _assert_runtime_source_in_repository(repository_root)
    commit_sha = _git_output(repository_root, "rev-parse", "HEAD")
    status = _git_output(
        repository_root,
        "status",
        "--porcelain=v1",
        "--untracked-files=normal",
    )
    if status:
        raise RuntimeError(
            "Live execution requires a clean committed worktree; commit and review "
            "the frozen protocol before making provider calls"
        )
    protocol_path = repository_root / "protocols" / "v0.2-live.md"
    if not protocol_path.is_file():
        raise RuntimeError("Could not locate the frozen v0.2 protocol")
    return {
        "commit_sha": commit_sha,
        "working_tree_clean": True,
        "protocol_sha256": hashlib.sha256(protocol_path.read_bytes()).hexdigest(),
    }


def _assert_runtime_source_in_repository(repository_root: Path) -> None:
    expected_package = (repository_root / "src" / "mas_safety").resolve()
    imported_package = Path(__file__).resolve().parent
    if imported_package != expected_package:
        raise RuntimeError(
            "The imported mas_safety package is not the frozen repository checkout"
        )


def _validated_freeze_override(value: dict[str, object]) -> dict[str, object]:
    expected = {"commit_sha", "working_tree_clean", "protocol_sha256"}
    if set(value) != expected:
        raise ValueError("Repository freeze override has unexpected fields")
    if (
        not isinstance(value["commit_sha"], str)
        or re.fullmatch(r"[0-9a-f]{40,64}", value["commit_sha"]) is None
        or value["working_tree_clean"] is not True
        or not isinstance(value["protocol_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["protocol_sha256"]) is None
    ):
        raise ValueError("Repository freeze override is malformed or not clean")
    return dict(value)


def _git_repository_root(*, required: bool) -> Path | None:
    try:
        root = _git_output(Path.cwd(), "rev-parse", "--show-toplevel")
    except RuntimeError:
        if required:
            raise RuntimeError(
                "Live execution requires a Git checkout with a frozen commit"
            ) from None
        return None
    return Path(root).resolve()


def _git_output(cwd: Path, *arguments: str) -> str:
    process = subprocess.run(
        ("git", *arguments),
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if process.returncode != 0:
        raise RuntimeError(f"Git metadata command failed: {' '.join(arguments)}")
    return process.stdout.strip()


def _append_private_trace(path: Path, trace: RunTrace) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(trace.to_dict(), sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _write_private_json(path: Path, payload: object) -> None:
    _write_private_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _write_private_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


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


def _invalidate_live_analysis_report(
    destination: Path, *, abort_error_type: str
) -> bool:
    json_path = destination / "micro_pilot_report.json"
    markdown_path = destination / "micro_pilot_report.md"
    if not json_path.exists() and not markdown_path.exists():
        return False
    invalidated = {
        "schema_version": "0.2.1",
        "stage": "stage_1_local_only_live_micro_pilot",
        "decision": "ABORTED",
        "all_evaluated_checks_pass": False,
        "empirical_claim_status": "invalidated_by_batch_abort",
        "abort_error_type": abort_error_type,
        "prior_analysis_must_not_be_used": True,
    }
    try:
        _write_private_json(json_path, invalidated)
        _write_private_text(
            markdown_path,
            "# Stage 1 live micro-pilot report\n\n"
            "Decision: **ABORTED**\n\n"
            "The batch failed finalization integrity checks. Any earlier gate "
            "decision from this batch is invalid and must not be used.\n",
        )
    except OSError:
        return False
    return True


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
