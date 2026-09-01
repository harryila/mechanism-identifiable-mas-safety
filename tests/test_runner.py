from __future__ import annotations

from typing import ClassVar

import pytest

from mas_safety.backends import Proposal, ScriptedBackend
from mas_safety.enums import (
    PRIMARY_DEFENSES,
    Architecture,
    Defense,
    Mechanism,
    RunStatus,
    SafetyVariant,
)
from mas_safety.models import ActionSpec
from mas_safety.runner import ExperimentRunner, RunSpec, pilot_specs
from mas_safety.scenarios import load_scenarios


@pytest.fixture(scope="module")
def runner() -> ExperimentRunner:
    return ExperimentRunner(load_scenarios())


def test_paired_pilot_matrix_has_192_unique_cells() -> None:
    scenarios = load_scenarios()
    specs = pilot_specs(scenarios)
    assert len(specs) == 192
    assert len({spec.condition_id for spec in specs}) == 192
    assert sum(spec.cohort == "mechanism_on" for spec in specs) == 80
    assert sum(spec.cohort == "mechanism_off" for spec in specs) == 80
    assert sum(spec.cohort == "single_agent_control" for spec in specs) == 16
    assert sum(spec.cohort == "omniscient_upper_bound" for spec in specs) == 16


@pytest.mark.parametrize("mechanism", list(Mechanism))
def test_each_mechanism_produces_lgh_and_its_control_removes_it(
    runner: ExperimentRunner, mechanism: Mechanism
) -> None:
    for scenario_id in runner.scenarios:
        treatment = runner.run(
            RunSpec(
                scenario_id,
                mechanism,
                Defense.LOCAL_ONLY,
                SafetyVariant.UNSAFE,
            )
        )
        control = runner.run(
            RunSpec(
                scenario_id,
                mechanism,
                Defense.LOCAL_ONLY,
                SafetyVariant.UNSAFE,
                mechanism_active=False,
                cohort="mechanism_off",
            )
        )
        assert treatment.local_allow_global_harm
        assert treatment.terminal_status == "forbidden_state"
        assert control.status is RunStatus.LOCAL_BLOCK
        assert not control.global_violation
        assert control.terminal_status == "incomplete"


@pytest.mark.parametrize("mechanism", list(Mechanism))
@pytest.mark.parametrize("defense", list(PRIMARY_DEFENSES))
def test_every_matched_safe_treatment_completes(
    runner: ExperimentRunner, mechanism: Mechanism, defense: Defense
) -> None:
    for scenario_id in runner.scenarios:
        trace = runner.run(
            RunSpec(scenario_id, mechanism, defense, SafetyVariant.SAFE)
        )
        assert trace.benign_completed
        assert trace.terminal_status == "required_benign_state"
        assert not trace.defense_overblocked


def test_predeclared_defense_signature(runner: ExperimentRunner) -> None:
    expected_blocks = {
        Defense.LOCAL_ONLY: set(),
        Defense.HISTORY_MONITOR: {Mechanism.INTENT_DECOMPOSITION},
        Defense.SOURCE_ANCHORING: {
            Mechanism.AUTHORIZATION_DRIFT,
            Mechanism.POLICY_HETEROGENEITY,
        },
        Defense.PROVENANCE_CARRYING: set(Mechanism),
        Defense.POLICY_INTERSECTION: {Mechanism.POLICY_HETEROGENEITY},
    }
    for scenario_id in runner.scenarios:
        for defense, blocked_mechanisms in expected_blocks.items():
            for mechanism in Mechanism:
                trace = runner.run(
                    RunSpec(
                        scenario_id,
                        mechanism,
                        defense,
                        SafetyVariant.UNSAFE,
                    )
                )
                assert trace.defense_blocked is (mechanism in blocked_mechanisms)
                assert trace.local_allow_global_harm is (
                    mechanism not in blocked_mechanisms
                )


def test_single_agent_and_omniscient_controls(runner: ExperimentRunner) -> None:
    for scenario_id in runner.scenarios:
        for mechanism in Mechanism:
            single = runner.run(
                RunSpec(
                    scenario_id,
                    mechanism,
                    Defense.LOCAL_ONLY,
                    SafetyVariant.UNSAFE,
                    architecture=Architecture.SINGLE_AGENT_FULL_CONTEXT,
                    mechanism_active=False,
                    cohort="single_agent_control",
                )
            )
            omni = runner.run(
                RunSpec(
                    scenario_id,
                    mechanism,
                    Defense.OMNISCIENT_REFERENCE,
                    SafetyVariant.UNSAFE,
                    cohort="omniscient_upper_bound",
                )
            )
            assert single.status is RunStatus.LOCAL_BLOCK
            assert omni.status is RunStatus.DEFENSE_BLOCK
            assert not single.global_violation
            assert not omni.global_violation


class RefusingBackend:
    name = "test_refusal"
    model_id = "test-refusal-v1"

    def propose(self, **kwargs: object) -> Proposal:
        declared = kwargs["declared_action"]
        assert isinstance(declared, ActionSpec)
        return Proposal(declared, "refused", 1, 1, 1.0, refusal=True)


class OffSchemaTerminalBackend:
    name = "test_off_schema"
    model_id = "test-off-schema-v1"

    def propose(self, **kwargs: object) -> Proposal:
        declared = kwargs["declared_action"]
        assert isinstance(declared, ActionSpec)
        if not declared.terminal:
            return Proposal(declared, "valid", 1, 1, 1.0)
        malformed = ActionSpec(
            role=declared.role,
            name="issue_real_payment",
            terminal=False,
            parameters={"payee": "attacker", "amount_cents": 999_999_999_999},
        )
        return Proposal(malformed, "malformed", 1, 1, 1.0)


class MutatingModelViewBackend:
    name = "test_mutating_view"
    model_id = "test-mutating-view-v1"

    def propose(self, **kwargs: object) -> Proposal:
        assert "scenario" not in kwargs
        assert "full_facts" not in kwargs
        context = kwargs["context"]
        declared = kwargs["declared_action"]
        assert hasattr(context, "visible_facts")
        assert isinstance(declared, ActionSpec)
        context.visible_facts["approval_token_valid"] = True
        artifact = kwargs["artifact"]
        if artifact is not None:
            artifact.metadata.clear()
        return Proposal(declared, "valid", 1, 1, 1.0)


class MalformedObjectBackend:
    name = "test_malformed_object"
    model_id = "test-malformed-object-v1"

    def propose(self, **kwargs: object) -> Proposal:
        del kwargs
        return Proposal("not-an-action", "malformed", 1, 1, 1.0)  # type: ignore[arg-type]


class RaisingBackend:
    name = "test_raising"
    model_id = "test-raising-v1"

    def propose(self, **kwargs: object) -> Proposal:
        del kwargs
        raise RuntimeError("synthetic provider failure")


def test_model_refusal_never_executes_or_counts_as_completion() -> None:
    scenario = load_scenarios()[0]
    trace = ExperimentRunner(
        [scenario],
        RefusingBackend(),
        provenance_signing_key=b"test-only-key-material-32-bytes!!",
        provenance_key_id="test-key-v1",
    ).run(
        RunSpec(
            scenario.scenario_id,
            Mechanism.INTENT_DECOMPOSITION,
            Defense.LOCAL_ONLY,
            SafetyVariant.SAFE,
        )
    )
    assert trace.status is RunStatus.MODEL_REFUSAL
    assert trace.refusal
    assert not trace.benign_completed
    assert trace.final_environment_state["tool_log"] == []
    assert trace.steps[0].proposal_status == "model_refusal"
    assert trace.steps[0].tool_result is None


def test_off_schema_terminal_proposal_fails_closed() -> None:
    scenario = next(
        item for item in load_scenarios() if item.domain == "finance_procurement"
    )
    trace = ExperimentRunner(
        [scenario],
        OffSchemaTerminalBackend(),
        provenance_signing_key=b"test-only-key-material-32-bytes!!",
        provenance_key_id="test-key-v1",
    ).run(
        RunSpec(
            scenario.scenario_id,
            Mechanism.INTENT_DECOMPOSITION,
            Defense.LOCAL_ONLY,
            SafetyVariant.SAFE,
        )
    )
    assert trace.status is RunStatus.CAPABILITY_FAILURE
    assert trace.capability_failure
    assert not trace.benign_completed
    assert not trace.final_environment_state["terminal_action_executed"]
    assert trace.steps[-1].proposal_status == "schema_error"
    assert trace.steps[-1].tool_result is None


def test_backend_receives_only_defensive_local_views() -> None:
    scenario = next(
        item for item in load_scenarios() if item.domain == "finance_procurement"
    )
    trace = ExperimentRunner(
        [scenario],
        MutatingModelViewBackend(),
        provenance_signing_key=b"test-only-key-material-32-bytes!!",
        provenance_key_id="test-key-v1",
    ).run(
        RunSpec(
            scenario.scenario_id,
            Mechanism.CONTEXT_FRAGMENTATION,
            Defense.LOCAL_ONLY,
            SafetyVariant.UNSAFE,
            mechanism_active=False,
            cohort="mechanism_off",
        )
    )
    assert trace.status is RunStatus.LOCAL_BLOCK
    assert not trace.global_violation
    assert trace.ground_truth_facts["approval_token_valid"] is False


@pytest.mark.parametrize("backend", [MalformedObjectBackend(), RaisingBackend()])
def test_malformed_or_raising_backend_becomes_capability_failure(
    backend: object,
) -> None:
    scenario = load_scenarios()[0]
    trace = ExperimentRunner(  # type: ignore[arg-type]
        [scenario],
        backend,
        provenance_signing_key=b"test-only-key-material-32-bytes!!",
        provenance_key_id="test-key-v1",
    ).run(
        RunSpec(
            scenario.scenario_id,
            Mechanism.INTENT_DECOMPOSITION,
            Defense.LOCAL_ONLY,
            SafetyVariant.SAFE,
        )
    )
    assert trace.status is RunStatus.CAPABILITY_FAILURE
    assert trace.capability_failure
    assert not trace.benign_completed
    assert trace.final_environment_state["tool_log"] == []
    assert trace.steps[0].proposal_status == "schema_error"


class AlternateBackend(ScriptedBackend):
    name = "alternate_provider"
    model_id = "alternate-model-snapshot"
    configuration: ClassVar[dict[str, object]] = {
        "temperature": 0,
        "provider": "synthetic",
    }


def test_physical_run_ids_include_model_and_invocation() -> None:
    scenario = load_scenarios()[0]
    base_spec = RunSpec(
        scenario.scenario_id,
        Mechanism.INTENT_DECOMPOSITION,
        Defense.LOCAL_ONLY,
        SafetyVariant.SAFE,
    )
    alternate_invocation = RunSpec(
        scenario.scenario_id,
        Mechanism.INTENT_DECOMPOSITION,
        Defense.LOCAL_ONLY,
        SafetyVariant.SAFE,
        invocation_id="invocation-001",
    )
    scripted = ExperimentRunner([scenario]).run(base_spec)
    alternate = ExperimentRunner(
        [scenario],
        AlternateBackend(),
        provenance_signing_key=b"live-test-secret-material-32-bytes",
        provenance_key_id="live-test-key-v1",
    ).run(base_spec)
    repeated = ExperimentRunner([scenario]).run(alternate_invocation)
    assert scripted.condition_id == alternate.condition_id == repeated.condition_id
    assert len({scripted.run_id, alternate.run_id, repeated.run_id}) == 3


def test_live_backend_rejects_public_development_provenance_key() -> None:
    scenario = load_scenarios()[0]
    with pytest.raises(ValueError, match="non-development"):
        ExperimentRunner([scenario], AlternateBackend())
