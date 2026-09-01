from __future__ import annotations

from mas_safety.defenses import DefenseEngine
from mas_safety.enums import Architecture, Defense, Mechanism, Role, SafetyVariant
from mas_safety.mechanisms import build_mechanism_setup
from mas_safety.models import ActionSpec, Artifact
from mas_safety.policies import PolicyEngine
from mas_safety.runner import ExperimentRunner, RunSpec
from mas_safety.scenarios import load_scenarios


def test_tampered_provenance_fails_closed() -> None:
    scenario = load_scenarios()[0]
    trace = ExperimentRunner([scenario]).run(
        RunSpec(
            scenario.scenario_id,
            Mechanism.CONTEXT_FRAGMENTATION,
            Defense.PROVENANCE_CARRYING,
            SafetyVariant.SAFE,
        )
    )
    terminal_step = trace.steps[-1]
    metadata = dict(terminal_step.artifact_input["metadata"])
    claims = dict(metadata["signed_claims"])
    claims[scenario.permissibility_fact] = False
    metadata["signed_claims"] = claims
    tampered = Artifact(
        terminal_step.artifact_input["artifact_id"],
        "transformer_output",
        "simulated://tampered",
        metadata,
    )
    setup = build_mechanism_setup(
        scenario,
        Mechanism.CONTEXT_FRAGMENTATION,
        SafetyVariant.SAFE,
        active=True,
        architecture=Architecture.MULTI_AGENT,
    )
    context = setup.contexts[-1]
    action = ActionSpec(Role.ACTUATOR, scenario.actions[-1].name, True, {})
    engine = DefenseEngine(
        scenario, PolicyEngine(scenario), expected_run_id=trace.run_id
    )
    decision = engine.evaluate(
        Defense.PROVENANCE_CARRYING,
        action=action,
        context=context,
        public_history=[],
        artifact=tampered,
        source_anchor=setup.source_anchor,
        full_facts=scenario.facts_for(SafetyVariant.SAFE),
    )
    assert not decision.allowed
    assert "verification" in decision.reason.lower()


def test_provenance_sidecar_is_hidden_from_model_view() -> None:
    scenario = load_scenarios()[0]
    trace = ExperimentRunner([scenario]).run(
        RunSpec(
            scenario.scenario_id,
            Mechanism.CONTEXT_FRAGMENTATION,
            Defense.PROVENANCE_CARRYING,
            SafetyVariant.SAFE,
        )
    )
    terminal_step = trace.steps[-1]
    assert terminal_step.artifact_input is not None
    assert terminal_step.artifact_model_view is not None
    runtime_metadata = terminal_step.artifact_input["metadata"]
    model_metadata = terminal_step.artifact_model_view["metadata"]
    defense_metadata = terminal_step.defense_input["artifact_metadata"]
    assert "signed_claims" in runtime_metadata
    assert "signed_claims" in defense_metadata
    assert "signed_claims" not in model_metadata
    assert "signature" not in model_metadata
    assert "signature_algorithm" not in model_metadata
    assert "signature_key_id" not in model_metadata
    assert "origin_scenario" not in model_metadata
    assert scenario.scenario_id not in terminal_step.artifact_model_view["artifact_id"]
    assert scenario.scenario_id not in terminal_step.artifact_model_view["content_ref"]


def test_history_monitor_never_reads_private_context_facts() -> None:
    scenario = load_scenarios()[0]
    setup = build_mechanism_setup(
        scenario,
        Mechanism.CONTEXT_FRAGMENTATION,
        SafetyVariant.UNSAFE,
        active=True,
        architecture=Architecture.MULTI_AGENT,
    )
    private_keys = set().union(*(item.visible_facts.keys() for item in setup.contexts))
    public_keys = set().union(*(item.public_evidence.keys() for item in setup.contexts))
    assert scenario.global_invariant["authorization_fact"] in private_keys
    assert scenario.global_invariant["authorization_fact"] not in public_keys


def test_provenance_rejects_cross_run_replay() -> None:
    scenario = load_scenarios()[0]
    runner = ExperimentRunner([scenario])
    safe = runner.run(
        RunSpec(
            scenario.scenario_id,
            Mechanism.CONTEXT_FRAGMENTATION,
            Defense.PROVENANCE_CARRYING,
            SafetyVariant.SAFE,
        )
    )
    unsafe = runner.run(
        RunSpec(
            scenario.scenario_id,
            Mechanism.CONTEXT_FRAGMENTATION,
            Defense.PROVENANCE_CARRYING,
            SafetyVariant.UNSAFE,
        )
    )
    replayed_data = safe.steps[-1].artifact_input
    assert replayed_data is not None
    replayed = Artifact(**replayed_data)
    setup = build_mechanism_setup(
        scenario,
        Mechanism.CONTEXT_FRAGMENTATION,
        SafetyVariant.UNSAFE,
        active=True,
        architecture=Architecture.MULTI_AGENT,
    )
    engine = DefenseEngine(
        scenario, PolicyEngine(scenario), expected_run_id=unsafe.run_id
    )
    decision = engine.evaluate(
        Defense.PROVENANCE_CARRYING,
        action=scenario.actions[-1],
        context=setup.contexts[-1],
        public_history=[],
        artifact=replayed,
        source_anchor=setup.source_anchor,
        full_facts=scenario.facts_for(SafetyVariant.UNSAFE),
    )
    assert not decision.allowed
    assert "different physical run" in decision.reason
