from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .enums import (
    Architecture,
    DecisionValue,
    Defense,
    Mechanism,
    Role,
    RunStatus,
    SafetyVariant,
)

Json = dict[str, Any]


@dataclass(frozen=True)
class ActionSpec:
    role: Role
    name: str
    terminal: bool
    parameters: Json = field(default_factory=dict)


@dataclass(frozen=True)
class PolicySpec:
    policy_id: str
    predicate: str
    parameters: Json = field(default_factory=dict)


@dataclass(frozen=True)
class Scenario:
    schema_version: str
    scenario_id: str
    title: str
    domain: str
    source_principal: str
    principals: tuple[Json, ...]
    authority_chain: tuple[Json, ...]
    required_legitimate_work: str
    full_objective: str
    local_tasks: dict[Role, str]
    unsafe_facts: Json
    safe_fact_overrides: Json
    permissibility_fact: str
    permissibility_diff_path: str
    derived_fact_rules: Json
    global_invariant: Json
    actions: tuple[ActionSpec, ...]
    policies: dict[str, PolicySpec]
    context_fragments: dict[Role, tuple[str, ...]]
    source_restriction: str
    provenance_claim_keys: tuple[str, ...]
    public_evidence_by_role: dict[Role, Json]

    def facts_for(self, variant: SafetyVariant) -> Json:
        facts = dict(self.unsafe_facts)
        if variant is SafetyVariant.SAFE:
            facts.update(self.safe_fact_overrides)
        for target, rule in self.derived_fact_rules.items():
            if not isinstance(rule, str) or not rule.startswith("$"):
                raise ValueError(f"Unsupported derived fact rule {target}={rule!r}")
            facts[target] = facts[rule[1:]]
        return facts


@dataclass(frozen=True)
class Artifact:
    artifact_id: str
    kind: str
    content_ref: str
    metadata: Json = field(default_factory=dict)


@dataclass(frozen=True)
class StageContext:
    role: Role
    task: str
    objective_view: str
    visible_facts: Json
    local_policy_id: str
    restriction_visible: bool
    restriction_text: str | None
    shareable_message: str
    public_evidence: Json
    applicable_policy_ids: tuple[str, ...]


@dataclass(frozen=True)
class Decision:
    value: DecisionValue
    predicate_id: str
    reason: str
    evidence_keys: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.value is DecisionValue.ALLOW


@dataclass(frozen=True)
class ToolResult:
    ok: bool
    tool_name: str
    state_delta: Json
    message: str


@dataclass
class StepTrace:
    step_index: int
    agent_id: str
    role: Role
    local_policy_id: str
    applicable_policy_ids: tuple[str, ...]
    facts_visible: Json
    objective_view: str
    restriction_visible: bool
    delegation_message: str
    artifact_input: Json | None
    artifact_model_view: Json | None
    artifact_output: Json | None
    declared_action: Json
    proposed_action: Json
    local_decision: Decision
    defense_decision: Decision
    defense_input: Json
    tool_result: ToolResult | None
    shareable_public_evidence: Json
    refusal: bool = False
    capability_failure: bool = False
    token_usage: Json = field(default_factory=lambda: {"input": 0, "output": 0})
    latency_ms: float = 0.0
    raw_model_output: str | None = None
    proposal_status: str = "valid_proposal"
    tool_status: str | None = None


@dataclass
class RunTrace:
    schema_version: str
    run_id: str
    condition_id: str
    scenario_id: str
    domain: str
    source_principal: str
    principals: tuple[Json, ...]
    authority_chain: tuple[Json, ...]
    cohort: str
    ground_truth_facts: Json
    permissibility_diff_path: str
    mechanism: Mechanism
    mechanism_active: bool
    intervention_coordinate: str
    transformation_diff_allowlist: tuple[str, ...]
    transformation_delta: tuple[str, ...]
    defense: Defense
    safety_variant: SafetyVariant
    architecture: Architecture
    backend: str
    model_id: str
    backend_configuration: Json
    provenance_key_id: str
    seed: int
    invocation_id: str
    steps: list[StepTrace]
    final_environment_state: Json
    terminal_status: str
    status: RunStatus
    global_violation: bool
    all_local_allow: bool
    local_allow_global_harm: bool
    benign_completed: bool
    defense_overblocked: bool
    defense_blocked: bool
    refusal: bool
    capability_failure: bool
    total_token_usage: Json
    total_latency_ms: float
    component_hashes: Json

    def to_dict(self) -> Json:
        return _jsonable(asdict(self))


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if hasattr(value, "value"):
        return value.value
    return value
