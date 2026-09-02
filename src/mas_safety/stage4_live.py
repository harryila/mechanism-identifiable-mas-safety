"""Prospective, offline Stage 4 schedule construction.

This module deliberately contains no provider client and does not import the
Stage 1 live runner.  It implements only the deterministic schedule contract
from ``docs/confirmatory_workflow_construction_rubric.md``.  A production
``run-stage4-confirmatory`` entry point must not be registered until the later
Stage 4 freeze supplies and binds the exact scenario package, prompts, schemas,
model snapshots and parameters, retry rules, provider-error rules, Stage 4
budget, one-shot authority, private output location, and nondevelopment key.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


SCHEDULE_SCHEMA_VERSION = "stage4-confirmatory-schedule-v1"

STAGE4_DOMAINS: tuple[str, ...] = (
    "healthcare",
    "education",
    "public_services",
    "finance_procurement",
)

STAGE4_MECHANISMS: tuple[str, ...] = (
    "intent_decomposition",
    "context_fragmentation",
    "authorization_drift",
    "policy_heterogeneity",
)

STAGE4_SAFETY_VARIANTS: tuple[str, ...] = ("unsafe", "safe")
STAGE4_REPETITIONS: tuple[int, ...] = (1, 2, 3)

EXPECTED_WORKFLOW_COUNT = 8
EXPECTED_MODEL_COUNT = 2
EXPECTED_PAIR_COUNT = 384
EXPECTED_RUN_COUNT = 768

_DOMAIN_ORDER = {domain: index for index, domain in enumerate(STAGE4_DOMAINS)}


@dataclass(frozen=True, slots=True)
class ConfirmatoryWorkflow:
    """The schedule-visible identity of one independently authored workflow."""

    scenario_id: str
    domain: str

    def __post_init__(self) -> None:
        if not self.scenario_id or self.scenario_id != self.scenario_id.strip():
            raise ValueError("scenario_id must be a nonempty, trimmed string")
        if self.domain not in STAGE4_DOMAINS:
            raise ValueError(
                f"domain must be one of {STAGE4_DOMAINS}, got {self.domain!r}"
            )


@dataclass(frozen=True, slots=True)
class Stage4ScheduledRun:
    """One workflow-level run in an adjacent mechanism-on/off pair."""

    sequence_index: int
    pair_index: int
    within_pair_position: int
    run_id: str
    pair_id: str
    scenario_id: str
    domain: str
    mechanism: str
    mechanism_on: bool
    safety_variant: str
    repetition: int
    model_id: str
    on_first: bool


@dataclass(frozen=True, slots=True)
class Stage4Schedule:
    """A complete deterministic Stage 4 execution schedule."""

    schema_version: str
    seed: str
    workflows: tuple[ConfirmatoryWorkflow, ...]
    model_ids: tuple[str, ...]
    runs: tuple[Stage4ScheduledRun, ...]

    def hash_payload(self) -> dict[str, Any]:
        """Return the canonical payload covered by :attr:`schedule_hash`."""

        return {
            "schema_version": self.schema_version,
            "seed": self.seed,
            "workflows": [asdict(workflow) for workflow in self.workflows],
            "model_ids": list(self.model_ids),
            "runs": [asdict(run) for run in self.runs],
        }

    @property
    def schedule_hash(self) -> str:
        return "sha256:" + hashlib.sha256(
            _canonical_json_bytes(self.hash_payload())
        ).hexdigest()

    def to_manifest(self) -> dict[str, Any]:
        """Return a JSON-serializable manifest including the self-check hash."""

        manifest = self.hash_payload()
        manifest["schedule_hash"] = self.schedule_hash
        return manifest


def load_confirmatory_workflows(
    directory: str | Path,
) -> tuple[ConfirmatoryWorkflow, ...]:
    """Load only schedule metadata from eight confirmatory scenario JSON files.

    The outcome-blind author owns the scenario contents.  Schedule construction
    reads only the top-level ``scenario_id`` and ``domain`` fields and does not
    depend on prompts, policies, traces, or any development outcome.
    """

    root = Path(directory)
    if not root.is_dir():
        raise ValueError(f"confirmatory scenario directory does not exist: {root}")

    paths = sorted(path for path in root.glob("*.json") if path.is_file())
    workflows: list[ConfirmatoryWorkflow] = []
    for path in paths:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot load confirmatory scenario {path}: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"confirmatory scenario must be a JSON object: {path}")
        scenario_id = value.get("scenario_id")
        domain = value.get("domain")
        if not isinstance(scenario_id, str) or not isinstance(domain, str):
            raise ValueError(
                f"confirmatory scenario needs string scenario_id and domain: {path}"
            )
        workflows.append(ConfirmatoryWorkflow(scenario_id, domain))

    return _canonical_workflows(workflows)


def build_stage4_schedule(
    workflows: Iterable[ConfirmatoryWorkflow],
    model_ids: Sequence[str],
    *,
    seed: str,
) -> Stage4Schedule:
    """Build the exact 768-run, 384-pair prospective Stage 4 schedule.

    Pair ordering is a version-stable SHA-256 ordering, not Python's randomized
    hash and not a version-dependent pseudorandom-number generator.  Within each
    ``scenario x mechanism x model`` stratum, exactly three of the six
    ``safety x repetition`` pairs are mechanism-on first.
    """

    if not seed or seed != seed.strip():
        raise ValueError("seed must be a nonempty, trimmed string")

    canonical_workflows = _canonical_workflows(workflows)
    canonical_models = _canonical_model_ids(model_ids)

    pair_plans: list[dict[str, Any]] = []
    for workflow in canonical_workflows:
        for mechanism in STAGE4_MECHANISMS:
            for model_id in canonical_models:
                on_first_cells = _on_first_cells(
                    seed, workflow.scenario_id, mechanism, model_id
                )
                for safety_variant in STAGE4_SAFETY_VARIANTS:
                    for repetition in STAGE4_REPETITIONS:
                        pair_key = {
                            "scenario_id": workflow.scenario_id,
                            "domain": workflow.domain,
                            "mechanism": mechanism,
                            "safety_variant": safety_variant,
                            "repetition": repetition,
                            "model_id": model_id,
                        }
                        pair_id = _pair_id(pair_key)
                        pair_plans.append(
                            {
                                **pair_key,
                                "pair_id": pair_id,
                                "on_first": (safety_variant, repetition)
                                in on_first_cells,
                            }
                        )

    pair_plans.sort(
        key=lambda plan: _stable_digest(seed, "pair-block-order", plan["pair_id"])
    )

    runs: list[Stage4ScheduledRun] = []
    for pair_index, plan in enumerate(pair_plans):
        arm_order = (True, False) if plan["on_first"] else (False, True)
        for within_pair_position, mechanism_on in enumerate(arm_order):
            arm_name = "on" if mechanism_on else "off"
            run_id = f"{plan['pair_id']}-{arm_name}"
            runs.append(
                Stage4ScheduledRun(
                    sequence_index=len(runs),
                    pair_index=pair_index,
                    within_pair_position=within_pair_position,
                    run_id=run_id,
                    pair_id=plan["pair_id"],
                    scenario_id=plan["scenario_id"],
                    domain=plan["domain"],
                    mechanism=plan["mechanism"],
                    mechanism_on=mechanism_on,
                    safety_variant=plan["safety_variant"],
                    repetition=plan["repetition"],
                    model_id=plan["model_id"],
                    on_first=plan["on_first"],
                )
            )

    schedule = Stage4Schedule(
        schema_version=SCHEDULE_SCHEMA_VERSION,
        seed=seed,
        workflows=canonical_workflows,
        model_ids=canonical_models,
        runs=tuple(runs),
    )
    validate_stage4_schedule(schedule)
    return schedule


def validate_stage4_schedule(schedule: Stage4Schedule) -> None:
    """Fail closed unless all frozen Stage 4 schedule invariants hold."""

    if schedule.schema_version != SCHEDULE_SCHEMA_VERSION:
        raise ValueError(f"unsupported schedule schema: {schedule.schema_version!r}")
    if not schedule.seed or schedule.seed != schedule.seed.strip():
        raise ValueError("schedule seed must be a nonempty, trimmed string")
    if schedule.workflows != _canonical_workflows(schedule.workflows):
        raise ValueError("schedule workflows are not in canonical order")
    if schedule.model_ids != _canonical_model_ids(schedule.model_ids):
        raise ValueError("schedule model IDs are not in canonical order")
    if len(schedule.runs) != EXPECTED_RUN_COUNT:
        raise ValueError(
            f"Stage 4 requires {EXPECTED_RUN_COUNT} runs, got {len(schedule.runs)}"
        )

    run_ids: set[str] = set()
    pair_ids: set[str] = set()
    observed_cells: set[tuple[Any, ...]] = set()
    stratum_pairs: dict[tuple[str, str, str], list[bool]] = {}
    stratum_on_first_cells: dict[
        tuple[str, str, str], set[tuple[str, int]]
    ] = {}
    global_on_first = 0
    workflow_domains = {
        workflow.scenario_id: workflow.domain for workflow in schedule.workflows
    }
    observed_pair_order: list[str] = []

    for pair_index in range(EXPECTED_PAIR_COUNT):
        pair = schedule.runs[pair_index * 2 : pair_index * 2 + 2]
        if len(pair) != 2:
            raise ValueError(f"pair {pair_index} is incomplete")
        first, second = pair
        if first.sequence_index != pair_index * 2:
            raise ValueError("run sequence indexes are not contiguous")
        if second.sequence_index != pair_index * 2 + 1:
            raise ValueError("run sequence indexes are not contiguous")
        if first.pair_index != pair_index or second.pair_index != pair_index:
            raise ValueError("pair indexes are not contiguous")
        if first.within_pair_position != 0 or second.within_pair_position != 1:
            raise ValueError("within-pair positions must be 0 then 1")
        if first.pair_id != second.pair_id:
            raise ValueError(f"pair {pair_index} is not adjacent")

        common_fields = (
            "scenario_id",
            "domain",
            "mechanism",
            "safety_variant",
            "repetition",
            "model_id",
            "on_first",
        )
        if any(getattr(first, field) != getattr(second, field) for field in common_fields):
            raise ValueError(f"pair {pair_index} differs outside mechanism arm")
        if {first.mechanism_on, second.mechanism_on} != {False, True}:
            raise ValueError(f"pair {pair_index} does not contain one on and one off run")
        if first.mechanism_on != first.on_first:
            raise ValueError(f"pair {pair_index} order flag does not match run order")

        pair_key = {
            "scenario_id": first.scenario_id,
            "domain": first.domain,
            "mechanism": first.mechanism,
            "safety_variant": first.safety_variant,
            "repetition": first.repetition,
            "model_id": first.model_id,
        }
        expected_pair_id = _pair_id(pair_key)
        if first.pair_id != expected_pair_id:
            raise ValueError(f"pair {pair_index} has a noncanonical pair_id")
        for run in pair:
            arm_name = "on" if run.mechanism_on else "off"
            expected_run_id = f"{expected_pair_id}-{arm_name}"
            if run.run_id != expected_run_id:
                raise ValueError(
                    f"pair {pair_index} run ID does not match its mechanism arm"
                )

        pair_ids.add(first.pair_id)
        observed_pair_order.append(first.pair_id)
        if first.on_first:
            global_on_first += 1
        stratum_key = (first.scenario_id, first.mechanism, first.model_id)
        stratum_pairs.setdefault(stratum_key, []).append(first.on_first)
        if first.on_first:
            stratum_on_first_cells.setdefault(stratum_key, set()).add(
                (first.safety_variant, first.repetition)
            )

        for run in pair:
            if run.run_id in run_ids:
                raise ValueError(f"duplicate run_id: {run.run_id}")
            run_ids.add(run.run_id)
            if run.mechanism not in STAGE4_MECHANISMS:
                raise ValueError(f"unknown Stage 4 mechanism: {run.mechanism!r}")
            if run.safety_variant not in STAGE4_SAFETY_VARIANTS:
                raise ValueError(f"unknown Stage 4 safety variant: {run.safety_variant!r}")
            if run.repetition not in STAGE4_REPETITIONS:
                raise ValueError(f"unknown Stage 4 repetition: {run.repetition!r}")
            if run.scenario_id not in workflow_domains:
                raise ValueError(f"unknown Stage 4 scenario: {run.scenario_id!r}")
            if run.domain != workflow_domains[run.scenario_id]:
                raise ValueError(
                    f"run domain does not match workflow {run.scenario_id!r}"
                )
            if run.model_id not in schedule.model_ids:
                raise ValueError(f"unknown Stage 4 model ID: {run.model_id!r}")
            observed_cells.add(
                (
                    run.scenario_id,
                    run.mechanism,
                    run.mechanism_on,
                    run.safety_variant,
                    run.repetition,
                    run.model_id,
                )
            )

    if len(pair_ids) != EXPECTED_PAIR_COUNT:
        raise ValueError(
            f"Stage 4 requires {EXPECTED_PAIR_COUNT} unique pairs, got {len(pair_ids)}"
        )
    if global_on_first != EXPECTED_PAIR_COUNT // 2:
        raise ValueError(
            "Stage 4 requires exactly 192 mechanism-on-first and 192 "
            "mechanism-off-first pairs"
        )
    expected_pair_order = sorted(
        observed_pair_order,
        key=lambda pair_id: _stable_digest(
            schedule.seed, "pair-block-order", pair_id
        ),
    )
    if observed_pair_order != expected_pair_order:
        raise ValueError("pair blocks are not in the deterministic frozen order")

    expected_stratum_count = EXPECTED_WORKFLOW_COUNT * len(STAGE4_MECHANISMS) * 2
    if len(stratum_pairs) != expected_stratum_count:
        raise ValueError(
            f"expected {expected_stratum_count} workflow x mechanism x model strata, "
            f"got {len(stratum_pairs)}"
        )
    for stratum, orders in stratum_pairs.items():
        if len(orders) != 6 or sum(orders) != 3:
            raise ValueError(
                f"stratum {stratum!r} must have six pairs with 3/3 order balance"
            )
        expected_on_first = _on_first_cells(schedule.seed, *stratum)
        if stratum_on_first_cells.get(stratum, set()) != expected_on_first:
            raise ValueError(
                f"stratum {stratum!r} does not match deterministic arm ordering"
            )

    expected_cells = {
        (
            workflow.scenario_id,
            mechanism,
            mechanism_on,
            safety_variant,
            repetition,
            model_id,
        )
        for workflow in schedule.workflows
        for mechanism in STAGE4_MECHANISMS
        for mechanism_on in (False, True)
        for safety_variant in STAGE4_SAFETY_VARIANTS
        for repetition in STAGE4_REPETITIONS
        for model_id in schedule.model_ids
    }
    if observed_cells != expected_cells:
        missing = expected_cells - observed_cells
        unexpected = observed_cells - expected_cells
        raise ValueError(
            f"schedule matrix mismatch: {len(missing)} missing, "
            f"{len(unexpected)} unexpected cells"
        )


def verify_schedule_manifest(manifest: dict[str, Any]) -> bool:
    """Verify the hash of a serialized schedule manifest without executing it."""

    claimed_hash = manifest.get("schedule_hash")
    if not isinstance(claimed_hash, str):
        return False
    payload = {key: value for key, value in manifest.items() if key != "schedule_hash"}
    actual_hash = "sha256:" + hashlib.sha256(
        _canonical_json_bytes(payload)
    ).hexdigest()
    return claimed_hash == actual_hash


def _canonical_workflows(
    workflows: Iterable[ConfirmatoryWorkflow],
) -> tuple[ConfirmatoryWorkflow, ...]:
    values = tuple(workflows)
    if len(values) != EXPECTED_WORKFLOW_COUNT:
        raise ValueError(
            f"Stage 4 requires exactly {EXPECTED_WORKFLOW_COUNT} workflows, "
            f"got {len(values)}"
        )
    scenario_ids = [workflow.scenario_id for workflow in values]
    if len(set(scenario_ids)) != len(scenario_ids):
        raise ValueError("Stage 4 scenario_id values must be unique")
    domain_counts = {domain: 0 for domain in STAGE4_DOMAINS}
    for workflow in values:
        domain_counts[workflow.domain] += 1
    if any(count != 2 for count in domain_counts.values()):
        raise ValueError(
            "Stage 4 requires exactly two workflows in every frozen domain; "
            f"got {domain_counts}"
        )
    return tuple(
        sorted(values, key=lambda workflow: (_DOMAIN_ORDER[workflow.domain], workflow.scenario_id))
    )


def _canonical_model_ids(model_ids: Sequence[str]) -> tuple[str, ...]:
    values = tuple(model_ids)
    if len(values) != EXPECTED_MODEL_COUNT:
        raise ValueError(
            f"Stage 4 requires exactly {EXPECTED_MODEL_COUNT} immutable model IDs, "
            f"got {len(values)}"
        )
    if any(not value or value != value.strip() for value in values):
        raise ValueError("model IDs must be nonempty, trimmed strings")
    if len(set(values)) != len(values):
        raise ValueError("the two immutable model IDs must be distinct")
    return tuple(sorted(values))


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _stable_digest(seed: str, namespace: str, *parts: str) -> bytes:
    framed = [SCHEDULE_SCHEMA_VERSION, seed, namespace, *parts]
    return hashlib.sha256(_canonical_json_bytes(framed)).digest()


def _on_first_cells(
    seed: str,
    scenario_id: str,
    mechanism: str,
    model_id: str,
) -> set[tuple[str, int]]:
    cells = [
        (safety_variant, repetition)
        for safety_variant in STAGE4_SAFETY_VARIANTS
        for repetition in STAGE4_REPETITIONS
    ]
    ordered = sorted(
        cells,
        key=lambda cell: _stable_digest(
            seed,
            "arm-order",
            scenario_id,
            mechanism,
            model_id,
            cell[0],
            str(cell[1]),
        ),
    )
    return set(ordered[:3])


def _pair_id(pair_key: dict[str, Any]) -> str:
    return "stage4-pair-" + hashlib.sha256(
        _canonical_json_bytes(pair_key)
    ).hexdigest()
