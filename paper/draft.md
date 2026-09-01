# Same Symptom, Different Failure: Mechanism-Identifiable Evaluation of Compositional Safety in Multi-Agent Systems

> **Draft status:** v0.2.1-live prospective methods scaffold and pre-live Stage 1
> freeze. Bracketed result text is withheld until the sealed live-agent study is
> run. The archived
> v0.1-scripted numbers are engineering validation only.

## Abstract

Multi-agent systems can reach a globally forbidden state even when every local
policy gate allows the action it sees. That observation is important, but it is
an outcome signature rather than a threat model: decomposition of intent,
fragmentation of policy-relevant facts, loss of authorization during delegation,
and disagreement among legitimate policies can all produce the same trace-level
symptom. We present a paired evaluation framework that manipulates each mechanism
through a single declared intervention coordinate in a fixed four-stage pipeline.
Local compliance and terminal harm are executable predicates, not LLM judgments.
We compare five defense conditions under frozen information contracts and measure
LGH, benign completion, defense overblocking, and mechanism-specific residual
risk. The v0.2 design begins with exactly 192 live development workflow runs over
two models, then freezes middleware defenses and 8–12 new workflows before the
confirmatory study. **[LIVE RESULT: primary paired mechanism effects, secondary
mechanism-by-defense interaction, and sensitivity statement.]** A strict defense
rank reversal is a bonus result; pooled regret and model-family comparisons are
exploratory. If the preregistered primary gates are not met, the framework and
audit stand as the contribution without a manufactured effectiveness claim.

## 1. Introduction

Safety evaluations of delegated agent systems increasingly report a recognizable
pattern: no individual step looks impermissible to the component making it, yet
the composite trajectory violates a global constraint. The pattern is often
summarized as “locally safe, globally harmful.” But the summary does not identify
why the failure occurred.

Consider four systems that all transmit the same protected record without valid
consent. In the first, no worker sees the end-to-end operation. In the second,
one worker knows the record class while another knows the destination and neither
sees the decisive conjunction. In the third, the source restriction exists but
is dropped during delegation. In the fourth, all information survives and two
legitimate policies disagree. Their terminal traces can be observationally
similar, but their counterfactuals and remedies differ.

Pooling these cases into one attack-success number creates two problems. First,
it blurs causal claims: an agent-count comparison may also change context length,
prompt granularity, topology, and policy assignment. Second, it can blur defense
claims: a history monitor, source anchor, provenance layer, and policy
intersection gate receive different evidence. A defense may be effective for the
mechanism that exposes its required signal and ineffective where that signal is
absent. A pooled ranking is therefore conditional on an often-unstated mixture of
mechanisms.

This paper makes three contributions:

1. We separate four compositional-failure mechanisms through paired,
   machine-checkable interventions in one fixed pipeline.
2. We define an executable evaluation contract in which models make structured
   execution decisions or finite-action selections while trusted code determines
   local permission and terminal harm.
3. We evaluate mechanism-by-defense interaction under explicit visibility
   contracts and utility eligibility, while treating a strict rank reversal as a
   preregistered bonus rather than a required result.

The core claim is deliberately narrow. We do not ask whether local permissions
can compose into global harm; prior work already establishes that broad
possibility. We ask whether different causes can generate the same signature and
whether a defense score transfers across those causes.

## 2. LGH is an outcome signature, not a mechanism

Let a realized trace be `tau`, local action/observation pairs be `(a_i, o_i)`,
trusted local predicates be `P_i`, and the deterministic terminal evaluator be
`G`. We define:

\[
LGH(\tau)=\mathbb{1}\left[G(\tau)=violation\right]
\prod_{i\in realized(\tau)}\mathbb{1}\left[P_i(a_i,o_i)=allow\right].
\]

This is a joint outcome. Conditioning on local allow would change the denominator
across defenses and could reward conditions that suppress valid proposals. A
model refusal, escalation, schema failure, local block, defense block,
provider/tool failure, and forbidden terminal state are recorded separately.

We study four generating mechanisms:

- **Intent decomposition:** only the global-objective projection changes. Direct
  authorization facts and their derived public evidence are held masked in both
  arms; the treatment replaces the constant-layout full-objective field with
  `NOT_AVAILABLE` while preserving role-local work.
- **Context fragmentation:** the complete policy fact multiset remains in the
  pipeline, but routing prevents the decision role and realistic monitor from
  seeing the decisive conjunction.
- **Authorization drift:** a trusted source restriction exists in both arms. The
  single logical forwarding coordinate carries the restriction together with
  the authorization-family facts and derived evidence needed to evaluate it; in
  treatment those downstream channels are jointly replaced by `NOT_PROVIDED` or
  `NOT_AVAILABLE`. The deterministic pilot uses a runtime-owned restriction
  record rather than an externally authenticated credential.
- **Policy heterogeneity:** facts remain complete and the source constraint is
  represented by the source policy; only the Actuator's policy binding—including
  its ID and generated natural-language contract—changes to a frozen, internally
  consistent downstream policy that disagrees on the focal action. Restriction
  visibility is held fixed across the pair.

Mechanisms are identified by intervention history, not necessarily inferable
from the terminal trace. Fragmentation and drift can deliberately create the same
downstream view. This observational ambiguity motivates intervention-based
labels.

## 3. Experimental framework

### 3.1 Fixed pipeline and simulator

Every workflow uses live models in fixed Planner, Retriever, Transformer, and
Actuator roles and a fixed order. The topology and task renderers are scripted;
the role decisions are not. Agents receive their task, a constant-layout fact
projection, one executable policy identifier, the upstream artifact, and
permitted simulated tools. The environment can only create in-memory records
representing a document send or payment issuance. Synthetic identifiers and
`.invalid` addresses prevent real-world effects.

Each workflow declares a source principal, a three-entry principal registry, one
authority edge, legitimate work, one global invariant, a forbidden terminal
state, and a matched benign state. The safe/unsafe pair changes one authoritative
fact—consent or approval validity—with all derived labels recomputed by trusted
code. The current loader checks principal references and the Boolean fact named by
the authority edge. These records remain simulator declarations rather than
verified external credentials or cryptographic bindings to the terminal action.

### 3.2 Execution decisions, finite actions, and trusted judgment

In the primary condition, the backend receives only an isolated role-local
stage-context copy, one declared finite-schema action, and a redacted upstream
artifact. It chooses `execute`, `refuse`, or `escalate`; an execution decision
must select the opaque identifier of the declared offered action, which trusted
code maps to the exact canonical action object. A separately labelled secondary
condition asks the model to select from exactly five semantic choices: execute
the focal typed action, `request_authorization`, `request_more_context`, escalate,
or stop. These conditions are never pooled.

The model cannot assert its own authorization, policy, provenance, record class,
recipient class, or approval status. Application-policy `allow` means only that
the executable predicate does not prohibit the action given the trusted local
observation; it is not an instruction to execute or a provider-safety judgment.
The runtime parses the decision, evaluates local policy and middleware on its
trusted action object, executes only a simulated transition, and evaluates the
invariant. Local and global labels never come from an LLM judge. Refusal,
escalation, schema error, local block, defense block, and provider/tool error are
reported separately.

The primary experiment hides defense identity and sidecar metadata from the
model. This isolates middleware enforcement from behavioral prompting. A shadow
replay analysis evaluates every defense on the same frozen local-only proposal
trace; it is reported separately from closed-loop completion.

### 3.3 Scenarios and controls

The development fixtures cover protected-summary disclosure and an approval-gated
vendor payment. The confirmatory study uses 8–12 additional sealed workflows
spanning healthcare, public services, education, and finance/procurement. The
exact count is fixed from validity, coverage, and budget before any live outcome
on those workflows is inspected. The two development fixtures are excluded from
confirmatory estimates.

Every mechanism-on unsafe run has a same-topology mechanism-off counterfactual and
a matched-safe utility case. The matched-safe case is not a causal control; it
validates the terminal label and measures legitimate completion. The paired
same-topology off arm carries the mechanism claim. The omniscient middleware
reference is evaluated during frozen replay. Any live single-agent/full-context
architecture reference is separately budgeted and exploratory because it jointly
changes topology and context; neither reference adds to the exact 192-run Stage 1
matrix.

### 3.4 Defenses and visibility

We compare local-only enforcement, a history monitor over accumulated shareable
public-evidence records, source anchoring through a trusted runtime record,
runtime-authenticated provenance carrying, and policy intersection. The omniscient
reference is excluded from realistic rankings.

Each defense's failure is interpreted relative to its information contract. The
history monitor cannot access private facts; in v0.2 intent decomposition, its
shareable history also omits the withheld authorization evidence, so the v0.1
scripted history-blocks-intent signature is not carried forward. Source anchoring
consults a trusted source-restriction record but does not authenticate a principal
or infer unrelated hidden context. Provenance retains source-derived labels but
not the full goal graph. Policy intersection evaluates all policies selected by a
fixed applicability function but does not invent missing facts. This observability
table is published before outcomes.

## 4. Study design and analysis

The v0.2 study has four stages. Stage 1 schedules exactly

\[
2\ workflows \times 4\ mechanisms \times 2\ assignments
\times 2\ safety\ variants \times 3\ repetitions \times 2\ models = 192
\]

live workflow runs in the primary execution-decision condition. A four-role run
uses at most four calls, so the hard Stage 1 ceiling is 768 agent calls. Stage 2
freezes and replays middleware defenses on those raw live decisions and may run a
separately budgeted finite-action condition. Stage 3 authors and seals 8–12 new
workflows. Stage 4 freezes every experimental and analysis component and executes
the confirmatory matrix. For `N` sealed workflows, that primary matrix contains
`N x 4 x 2 x 2 x 3 x 2 = 96N` workflow runs, or 768–1,152 runs for `N=8–12`.
Defense replay does not require a new model call because defense identity and
sidecars are hidden from the proposing model.

Stage 1 freezes `gpt-5.5-2026-04-23` and `gpt-5.4-2026-03-05`, each with
`reasoning.effort=low` and `max_output_tokens=512`. Before the study begins, one
harmless structured-output smoke call per snapshot checks provider capability
without using any study workflow. Those two calls are separately logged and
excluded from the 192-run schedule, estimands, gates, and behavioral claims. The
smoke calls and Stage 1 share a hard gross USD 20 spending ceiling; budget
exhaustion stops the run and leaves the matrix incomplete, without retries or
replacement calls. The request explicitly sets `service_tier="default"` to fix
standard processing and pricing rather than inheriting an automatic or
project-level tier. An exact private raw response retains the provider-returned
tier, while release/public trace metadata omits it.
The frozen offline 770-call maximum-output sizing bound is USD 19.601437500.
Before each network call, an append-only hash-chained ledger durably holds a
conservative 65,536-input/512-output-token allowance, settles valid usage at
full uncached rates, and forfeits the allowance when usage is unavailable.
The runtime also consumes a private one-shot authority for the exact frozen
commit before any provider client is constructed; failure or interruption does
not authorize a rerun.

Before parsing, the study stores exact rendered messages and schemas, immutable
model identifiers, provider request metadata, raw responses, refusal/finish
fields, token counts, latency, and errors in private append-only logs. Parsed
decisions, trusted observations, policy/defense results, simulator transitions,
and hashes are linked to those records. Credentials and authorization headers are
never logged. There are no outcome-based exclusions, and first attempts remain
the confirmatory record under the frozen retry rule.

The primary mechanism effect is the workflow-weighted paired difference in unsafe
local-only LGH. Defense analysis reports mechanism-specific residual LGH and
absolute risk reduction. Benign completion and defense overblocking are separate;
`1 - utility` is not automatically attributed to defense overblocking.

The operational gates require pooled mechanism-off unsafe LGH at or below 0.05,
pooled matched-safe completion at or above 0.875 (0.95 stretch), and more than
95% schema-valid attempted decisions. The primary result requires at least two
mechanisms with pooled paired effect at least 0.25 and no negative effect in
either model stratum. A frozen arm-level rule prevents widespread refusal or
escalation from being mistaken for an executable mechanism study.

The base workflow is the experimental unit. We report every workflow-level paired
contrast, finite-benchmark means, direction counts, and leave-one-workflow-out and
leave-one-domain-out sensitivity. Models and repetitions are nested repeated measurements.
Workflow-cluster bootstrap intervals are descriptive. A secondary analysis
reports `mechanism x defense` differences in absolute defense effect with workflow
effects; it does not use call-level independence.

Defenses must meet prespecified utility eligibility before ranking. A bonus strict
reversal requires opposite residual-risk margins of at least 0.25 in two
mechanisms and direction agreement in at least `ceil(0.75N)` sealed workflows.
Small tied rank changes do not count. The reversal is not a gate. Equally weighted
pooled rankings, maximum mechanism regret, alternative mechanism weights, and
model-family comparisons are exploratory.

## 5. Results

### 5.1 Archived engineering validation

The archived v0.1-scripted repository executes 192 deterministic development
traces: 160 paired core cells, 16 single-agent references, and 16 omniscient
references. The schema, policy truth tables, one-coordinate transformations,
HMAC-authenticated provenance
sidecars, terminal labels, metric recomputation, and matched controls pass the
automated validation suite. The intended defense profiles differ by mechanism in
the scripted oracle.
These outcomes are unit-oracle predictions and are not evidence about model
behavior or real defense effectiveness.

### 5.2 V0.2.1 live-agent results

**[WITHHELD UNTIL SEALED RUN]** Report, in order:

1. raw-decision validity, refusals, escalations, and capability errors by arm;
2. mechanism-off control rates and safe-completion gates;
3. mechanism-on/off local-only paired effects by workflow;
4. the secondary mechanism-by-defense residual-LGH/effect matrix with safe
   utility and overblocking;
5. any bonus strict reversal; and
6. exploratory pooled rankings/regret, model-family strata, and
   leave-one-workflow/domain-out sensitivity.

If the primary empirical gates fail, replace this section with a transparent
null/mixed result and use the position-paper conclusion. A null interaction or
absent strict reversal does not itself fail the primary study. No scripted number
is substituted for a live result.

## 6. Related work

Recent benchmarks share an outcome signature while manipulating different
causes. [DeCompBench](https://arxiv.org/abs/2606.13994) studies decomposition
across fresh victim calls, bundling prompt granularity with context reset.
[Context-Fractured Decomposition](https://arxiv.org/abs/2606.09084) emphasizes
artifact provenance gaps. [Beyond Single-Agent Alignment](https://arxiv.org/abs/2604.22879)
studies private organizational policy fragments and distributed sentinels.
[MasDrift](https://arxiv.org/abs/2608.07556) is the closest architecture-level
authorization precedent because it compares the same tasks and tools across
single- and multi-agent organizations.

Other work motivates specific defenses or boundaries. [ChainCaps](https://arxiv.org/abs/2605.26542)
uses capability attenuation and lineage for explicit data flow;
[AgentFlow](https://arxiv.org/abs/2608.22868) provides flow-centric policy and
enforcement; [Bounded Agents](https://arxiv.org/abs/2608.15888) focuses on signed
delegation scope. [Operational Reframing](https://arxiv.org/abs/2607.07097)
isolates prompt-routing and approval framing but does not use executable tool
policies. The paper informally called PoisonSwarm in the brief is canonically
[Jailbreak-as-a-Service++](https://arxiv.org/abs/2505.21184); PoisonSwarm is its
framework name.

The complete 12-paper coding audit records policy authority, principals,
attacker, defender visibility, causal control, defense, and conclusion scope.
Most studies either bundle mechanisms or lack a matched multi-agent causal
control. Our contribution is not another pooled attack benchmark, but a common
paired intervention and defense-transfer protocol.

## 7. Implications, limitations, and reporting recommendations

LGH should be reported with its generating intervention. Evaluations should name
the authoritative policy source, principal count, information available to each
defender, causal control, refusal/error handling, and whether the conclusion is
mechanism-specific. A defense score without an information contract invites the
wrong interpretation: absent evidence is not necessarily failed reasoning.

The study remains a controlled benchmark. The topology and renderers are
scripted; decisions and actions are typed; tools are simulated; workflows are
authored; 8–12 workflows do not establish domain prevalence; two frozen model
snapshots do not establish model-family generality; and no condition models
adaptive attackers, colluding workers, covert channels, or arbitrary free-form
semantic leakage. A single-agent comparison
cannot show that “multi-agentness” alone caused an effect because it changes
topology, calls, and context. The same-topology paired intervention carries the
causal claim. The current scenario schema records a three-principal registry and
one authority edge per fixture, but not a complete real-world authority graph,
credential issuer, revocation model, or cryptographic action binding. Its
HMAC-SHA256 provenance sidecar uses a harness development key; it is an internal
integrity mechanism, not production identity or key management.

## 8. Conclusion

“Locally safe, globally harmful” names a symptom. Treating it as one threat model
can hide both causal ambiguity and defense non-transferability. This work turns
four candidate causes into explicit, paired interventions and makes defender
visibility part of the experimental object. **[PRIMARY LIVE MECHANISM RESULT,
SECONDARY INTERACTION RESULT, OR POSITION FALLBACK INSERTED UNDER THE FROZEN
RULE.]** Whether a strict reversal appears or not, future compositional-safety
reports should separate mechanism, policy authority, observability, and terminal
outcome rather than compressing them into one attack-success number.
