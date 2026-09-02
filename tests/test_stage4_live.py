from __future__ import annotations

import copy
import json
from collections import Counter, defaultdict
from dataclasses import replace

import pytest

from mas_safety.stage4_live import (
    EXPECTED_PAIR_COUNT,
    EXPECTED_RUN_COUNT,
    STAGE4_MECHANISMS,
    ConfirmatoryWorkflow,
    build_stage4_schedule,
    load_confirmatory_workflows,
    validate_stage4_schedule,
    verify_schedule_manifest,
)


WORKFLOWS = (
    ConfirmatoryWorkflow("confirmatory.h1", "healthcare"),
    ConfirmatoryWorkflow("confirmatory.h2", "healthcare"),
    ConfirmatoryWorkflow("confirmatory.e1", "education"),
    ConfirmatoryWorkflow("confirmatory.e2", "education"),
    ConfirmatoryWorkflow("confirmatory.p1", "public_services"),
    ConfirmatoryWorkflow("confirmatory.p2", "public_services"),
    ConfirmatoryWorkflow("confirmatory.f1", "finance_procurement"),
    ConfirmatoryWorkflow("confirmatory.f2", "finance_procurement"),
)
MODELS = ("provider/model-a@2026-08-01", "provider/model-b@2026-08-15")


def test_schedule_has_exact_matrix_adjacency_and_counterbalance() -> None:
    schedule = build_stage4_schedule(WORKFLOWS, MODELS, seed="stage4-test-seed")

    assert len(schedule.runs) == EXPECTED_RUN_COUNT
    assert len({run.pair_id for run in schedule.runs}) == EXPECTED_PAIR_COUNT
    assert len({run.run_id for run in schedule.runs}) == EXPECTED_RUN_COUNT

    orders_by_stratum: dict[tuple[str, str, str], list[bool]] = defaultdict(list)
    global_orders: list[bool] = []
    matrix = Counter()
    for pair_index in range(EXPECTED_PAIR_COUNT):
        first, second = schedule.runs[pair_index * 2 : pair_index * 2 + 2]
        assert first.pair_id == second.pair_id
        assert first.pair_index == second.pair_index == pair_index
        assert (first.within_pair_position, second.within_pair_position) == (0, 1)
        assert {first.mechanism_on, second.mechanism_on} == {False, True}
        assert first.mechanism_on is first.on_first
        global_orders.append(first.on_first)
        orders_by_stratum[
            (first.scenario_id, first.mechanism, first.model_id)
        ].append(first.on_first)
        for run in (first, second):
            matrix[
                (
                    run.scenario_id,
                    run.mechanism,
                    run.mechanism_on,
                    run.safety_variant,
                    run.repetition,
                    run.model_id,
                )
            ] += 1

    assert Counter(global_orders) == {True: 192, False: 192}
    assert len(orders_by_stratum) == 8 * 4 * 2
    assert all(Counter(orders) == {True: 3, False: 3} for orders in orders_by_stratum.values())
    assert len(matrix) == EXPECTED_RUN_COUNT
    assert set(matrix.values()) == {1}
    assert {run.mechanism for run in schedule.runs} == set(STAGE4_MECHANISMS)


def test_schedule_is_canonical_stable_and_self_verifying() -> None:
    schedule = build_stage4_schedule(WORKFLOWS, MODELS, seed="stable-seed")
    reordered = build_stage4_schedule(
        tuple(reversed(WORKFLOWS)), tuple(reversed(MODELS)), seed="stable-seed"
    )

    assert schedule == reordered
    assert schedule.schedule_hash == reordered.schedule_hash
    assert schedule.schedule_hash == (
        "sha256:866c2a784c2d9e9dae9f3cca744021623098701347fc154ff12ed455cadd6c1b"
    )
    assert verify_schedule_manifest(schedule.to_manifest())

    tampered = copy.deepcopy(schedule.to_manifest())
    tampered["runs"][0]["mechanism_on"] = not tampered["runs"][0]["mechanism_on"]
    assert not verify_schedule_manifest(tampered)

    different_seed = build_stage4_schedule(WORKFLOWS, MODELS, seed="other-seed")
    assert different_seed.schedule_hash != schedule.schedule_hash
    assert different_seed.runs != schedule.runs


def test_schedule_validation_fails_closed_on_pair_tampering() -> None:
    schedule = build_stage4_schedule(WORKFLOWS, MODELS, seed="stage4-test-seed")
    runs = list(schedule.runs)
    runs[1] = replace(runs[1], pair_id="stage4-pair-tampered")
    tampered = replace(schedule, runs=tuple(runs))

    with pytest.raises(ValueError, match="not adjacent"):
        validate_stage4_schedule(tampered)


def test_schedule_validation_rejects_arm_labeled_run_id_swap() -> None:
    schedule = build_stage4_schedule(WORKFLOWS, MODELS, seed="stage4-test-seed")
    runs = list(schedule.runs)
    first_run_id, second_run_id = runs[0].run_id, runs[1].run_id
    runs[0] = replace(runs[0], run_id=second_run_id)
    runs[1] = replace(runs[1], run_id=first_run_id)
    tampered = replace(schedule, runs=tuple(runs))

    with pytest.raises(ValueError, match="run ID does not match its mechanism arm"):
        validate_stage4_schedule(tampered)


def test_exact_workflow_and_model_requirements_are_enforced() -> None:
    with pytest.raises(ValueError, match="exactly 8 workflows"):
        build_stage4_schedule(WORKFLOWS[:-1], MODELS, seed="seed")
    with pytest.raises(ValueError, match="exactly 2 immutable model IDs"):
        build_stage4_schedule(WORKFLOWS, MODELS[:1], seed="seed")
    with pytest.raises(ValueError, match="exactly two workflows"):
        wrong_domains = (*WORKFLOWS[:-1], ConfirmatoryWorkflow("extra", "healthcare"))
        build_stage4_schedule(wrong_domains, MODELS, seed="seed")


def test_generic_loader_reads_only_top_level_schedule_metadata(tmp_path) -> None:
    for index, workflow in enumerate(reversed(WORKFLOWS)):
        payload = {
            "scenario_id": workflow.scenario_id,
            "domain": workflow.domain,
            "opaque_scenario_body": {"not": "used by schedule construction"},
        }
        (tmp_path / f"scenario-{index}.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )
    (tmp_path / "README.md").write_text("ignored", encoding="utf-8")

    loaded = load_confirmatory_workflows(tmp_path)

    assert loaded == build_stage4_schedule(
        WORKFLOWS, MODELS, seed="seed"
    ).workflows
