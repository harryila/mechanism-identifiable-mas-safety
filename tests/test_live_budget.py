from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

import pytest

import mas_safety.live as live_module
from mas_safety.enums import (
    AgentDecisionKind,
    DecisionMode,
    Defense,
    Mechanism,
    SafetyVariant,
)
from mas_safety.live import _run_live_development_for_test
from mas_safety.live_backends import OpenAIResponsesBackend
from mas_safety.live_budget import (
    FROZEN_INPUT_RESERVATION_TOKENS,
    FROZEN_MODEL_IDS,
    FROZEN_OUTPUT_RESERVATION_TOKENS,
    BudgetAccountingError,
    BudgetCeilingExceeded,
    LiveBudgetLedger,
    audit_budget_ledger,
    estimate_standard_cost_nano_usd,
)
from mas_safety.models import ActionSpec, AgentDecision
from mas_safety.runner import ExperimentRunner, RunSpec
from mas_safety.scenarios import load_scenarios

TEST_FREEZE = {
    "commit_sha": "c" * 40,
    "working_tree_clean": True,
    "protocol_sha256": "d" * 64,
}


def _reservation_cost(model_id: str) -> int:
    return estimate_standard_cost_nano_usd(
        model_id,
        input_tokens=FROZEN_INPUT_RESERVATION_TOKENS,
        output_tokens=FROZEN_OUTPUT_RESERVATION_TOKENS,
    )


def test_budget_boundary_allows_exact_ceiling_and_denies_one_nano_less_room(
    tmp_path: Path,
) -> None:
    model_id = FROZEN_MODEL_IDS[0]
    reservation_cost = _reservation_cost(model_id)
    ledger = LiveBudgetLedger(
        tmp_path / "exact.jsonl", ceiling_nano_usd=reservation_cost
    )
    reservation = ledger.reserve(
        phase="pre_stage_1_smoke",
        model_id=model_id,
        call_stem="call-000001-boundary",
        request_sha256="a" * 64,
        request_utf8_bytes=100,
    )
    assert ledger.snapshot()["gross_exposure_nano_usd"] == reservation_cost
    with pytest.raises(BudgetCeilingExceeded, match="hard USD 20 ceiling"):
        ledger.reserve(
            phase="pre_stage_1_smoke",
            model_id=model_id,
            call_stem="call-000002-denied",
            request_sha256="b" * 64,
            request_utf8_bytes=100,
        )
    ledger.cancel_before_provider_call(reservation, reason="unit_test_no_network")
    assert ledger.snapshot()["gross_exposure_nano_usd"] == 0
    assert audit_budget_ledger(ledger.path)["pass"] is True

    too_small = LiveBudgetLedger(
        tmp_path / "too-small.jsonl", ceiling_nano_usd=reservation_cost - 1
    )
    with pytest.raises(BudgetCeilingExceeded):
        too_small.reserve(
            phase="pre_stage_1_smoke",
            model_id=model_id,
            call_stem="call-000001-denied",
            request_sha256="c" * 64,
            request_utf8_bytes=100,
        )


def test_shared_cross_model_ledger_settles_full_uncached_rates(tmp_path: Path) -> None:
    ledger = LiveBudgetLedger(tmp_path / "shared.jsonl")
    expected = 0
    for index, model_id in enumerate(FROZEN_MODEL_IDS, start=1):
        reservation = ledger.reserve(
            phase="stage_1_live_feasibility",
            model_id=model_id,
            call_stem=f"call-{index:06d}-shared",
            request_sha256=str(index) * 64,
            request_utf8_bytes=500,
        )
        ledger.settle(reservation, input_tokens=123, output_tokens=17)
        expected += estimate_standard_cost_nano_usd(
            model_id, input_tokens=123, output_tokens=17
        )
    snapshot = ledger.snapshot()
    assert snapshot["committed_nano_usd"] == expected
    assert snapshot["active_reservations"] == 0
    assert snapshot["reservations_settled"] == 2
    assert audit_budget_ledger(ledger.path)["pass"] is True


def test_missing_provider_usage_forfeits_reservation_and_aborts(
    tmp_path: Path,
) -> None:
    class Response:
        output_text = json.dumps(
            {
                "decision": "execute",
                "selected_action_id": "unused",
                "reason": None,
                "missing_information": [],
            }
        )
        id = "resp_missing_usage"
        model = FROZEN_MODEL_IDS[1]
        status = "completed"
        service_tier = "default"
        usage = None

        def model_dump(self, *, mode: str = "python") -> dict[str, object]:
            del mode
            return {
                "id": self.id,
                "model": self.model,
                "status": self.status,
                "service_tier": self.service_tier,
                "output_text": self.output_text,
            }

    class Responses:
        @staticmethod
        def create(**_kwargs: object) -> Response:
            return Response()

    class Client:
        responses = Responses()

    ledger = LiveBudgetLedger(tmp_path / "ledger.jsonl")
    backend = OpenAIResponsesBackend(
        model_id=FROZEN_MODEL_IDS[1],
        raw_log_dir=tmp_path / "raw",
        client=Client(),
        sdk_version="test-sdk",
        budget_ledger=ledger,
    )
    context, action = live_module._smoke_fixture("n" * 24)
    with pytest.raises(BudgetAccountingError, match="omitted valid usage"):
        backend.decide(
            context=context,
            decision_mode=DecisionMode.EXECUTION_DECISION,
            candidate_action=action,
            offered_actions=(action,),
            artifact=None,
            seed=1,
        )
    snapshot = ledger.snapshot()
    assert snapshot["reservations_forfeited"] == 1
    assert snapshot["active_reservations"] == 0
    assert snapshot["committed_nano_usd"] == _reservation_cost(FROZEN_MODEL_IDS[1])
    assert audit_budget_ledger(ledger.path)["pass"] is True


def test_budget_hash_chain_detects_tampering(tmp_path: Path) -> None:
    ledger = LiveBudgetLedger(tmp_path / "ledger.jsonl")
    reservation = ledger.reserve(
        phase="pre_stage_1_smoke",
        model_id=FROZEN_MODEL_IDS[1],
        call_stem="call-000001-tamper",
        request_sha256="d" * 64,
        request_utf8_bytes=100,
    )
    ledger.settle(reservation, input_tokens=5, output_tokens=2)
    assert audit_budget_ledger(ledger.path)["pass"] is True
    content = ledger.path.read_text(encoding="utf-8")
    ledger.path.write_text(content.replace('"input_tokens": 5', '"input_tokens": 6'))
    tampered = audit_budget_ledger(ledger.path)
    assert tampered["pass"] is False
    assert tampered["checks"]["hash_chain_valid"] is False


def test_budget_audit_rejects_a_truncated_settlement_suffix(tmp_path: Path) -> None:
    ledger = LiveBudgetLedger(tmp_path / "truncated.jsonl")
    reservation = ledger.reserve(
        phase="pre_stage_1_smoke",
        model_id=FROZEN_MODEL_IDS[0],
        call_stem="call-000001-truncated",
        request_sha256="e" * 64,
        request_utf8_bytes=100,
    )
    ledger.settle(reservation, input_tokens=5, output_tokens=2)
    events = ledger.path.read_text(encoding="utf-8").splitlines(keepends=True)
    assert len(events) == 3
    ledger.path.write_text("".join(events[:-1]), encoding="utf-8")

    truncated = audit_budget_ledger(ledger.path)

    assert truncated["pass"] is False
    assert truncated["active_reservations"] == 1


def test_provider_authority_lock_is_one_shot_per_protocol_commit(
    tmp_path: Path,
) -> None:
    repository_root = tmp_path / "repository"
    freeze = {
        "commit_sha": "a" * 40,
        "working_tree_clean": True,
        "protocol_sha256": "b" * 64,
    }
    first = live_module._acquire_provider_authority_lock(
        repository_root=repository_root,
        repository_freeze=freeze,
        batch_id="stage1-first",
        destination=repository_root / "outputs" / "private" / "first",
    )
    lock_path = (
        repository_root
        / "outputs"
        / "private"
        / "authorities"
        / f"{freeze['commit_sha']}.authority.json"
    )
    original = lock_path.read_bytes()

    with pytest.raises(
        RuntimeError, match="already consumed its single paid-run authority"
    ):
        live_module._acquire_provider_authority_lock(
            repository_root=repository_root,
            repository_freeze=freeze,
            batch_id="stage1-second",
            destination=repository_root / "outputs" / "private" / "second",
        )

    assert first["rerun_under_same_commit_authorized"] is False
    assert lock_path.read_bytes() == original
    assert json.loads(original)["batch_id"] == "stage1-first"


def test_budget_abort_marker_escapes_runner_instead_of_becoming_trace_data() -> None:
    class DeniedBackend:
        name = "denied-live-test"
        model_id = FROZEN_MODEL_IDS[0]
        configuration: ClassVar[dict[str, str]] = {"mode": "no_external_io"}

        @staticmethod
        def decide(**_kwargs: object) -> AgentDecision:
            raise BudgetCeilingExceeded("denied before provider I/O")

    scenario = load_scenarios()[0]
    runner = ExperimentRunner(
        [scenario],
        DeniedBackend(),
        provenance_signing_key=b"k" * 32,
        provenance_key_id="test-budget-abort-v1",
    )
    spec = RunSpec(
        scenario.scenario_id,
        Mechanism.INTENT_DECOMPOSITION,
        Defense.LOCAL_ONLY,
        SafetyVariant.SAFE,
    )
    with pytest.raises(BudgetCeilingExceeded):
        runner.run(spec)


def test_failed_two_call_smoke_starts_zero_stage_one_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    class SmokeBackend:
        name = "openai_responses"

        def __init__(self, model_id: str, raw_log_dir: Path) -> None:
            self.model_id = model_id
            self.raw_log_dir = raw_log_dir
            raw_log_dir.mkdir(parents=True)
            self.configuration = {"test_only_no_external_io": True}

        @staticmethod
        def set_run_metadata(_metadata: dict[str, object]) -> None:
            return None

        def decide(self, **kwargs: object) -> AgentDecision:
            calls.append(str(self.raw_log_dir))
            action = kwargs["candidate_action"]
            assert isinstance(action, ActionSpec)
            return AgentDecision(
                kind=AgentDecisionKind.EXECUTE,
                action=action,
                provider_metadata={
                    "status": "completed",
                    "resolved_response_model": self.model_id,
                    "structured_output_valid": len(calls) != 1,
                },
                input_tokens=10,
                output_tokens=3,
            )

    monkeypatch.setattr(
        live_module,
        "_stage_one_cost_preflight",
        lambda *_args: {
            "byte_upper_bound_cost_nano_usd": 0,
            "fits_authorization": True,
        },
    )
    output = tmp_path / "smoke-failed"
    with pytest.raises(RuntimeError, match="smoke failed"):
        _run_live_development_for_test(
            scenarios=load_scenarios(),
            model_ids=("model-alpha-2026-08-01", "model-beta-2026-08-01"),
            output_dir=output,
            provenance_signing_key=b"k" * 32,
            provenance_key_id="test-smoke-failure-v1",
            backend_factory=lambda model, raw: SmokeBackend(model, raw),
            repository_freeze_override=TEST_FREEZE,
        )
    manifest = json.loads((output / "model_call_manifest.json").read_text())
    assert len(calls) == 2
    assert all("smoke_raw_responses" in item for item in calls)
    assert manifest["state"] == "smoke_failed"
    assert manifest["smoke_calls_completed"] == 2
    assert manifest["workflow_runs_completed"] == 0
    assert not (output / "raw_responses").exists()


def test_production_rejects_any_model_order_other_than_frozen(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="exact ordered frozen"):
        live_module.run_live_development(
            scenarios=load_scenarios(),
            model_ids=tuple(reversed(FROZEN_MODEL_IDS)),
            output_dir=tmp_path / "never-created",
            provenance_signing_key=b"k" * 32,
            provenance_key_id="test-model-order-v1",
        )
    assert not (tmp_path / "never-created").exists()
