# Same Symptom, Different Failure: Mechanism-Identifiable Evaluation of Compositional Safety in Multi-Agent Systems

> **Draft status:** methods-complete scaffold. Bracketed result text is withheld
> until the sealed live-model study is run. Deterministic pilot numbers are
> engineering validation only.

## Abstract

Multi-agent systems can reach a globally forbidden state even when every local
policy gate allows the action it sees. That observation is important, but it is
an outcome signature rather than a threat model: decomposition of intent,
fragmentation of policy-relevant facts, loss of authorization during delegation,
and disagreement among legitimate policies can all produce the same trace-level
symptom. We present a paired evaluation framework that manipulates each mechanism
through a single declared intervention coordinate in a fixed four-stage pipeline.
Local compliance and terminal harm are executable predicates, not LLM judgments.
We compare five defense families under frozen information contracts and measure
LGH, benign completion, defense overblocking, and mechanism-specific residual
risk. The confirmatory design pairs every mechanism-on cell with a mechanism-off
counterfactual and matched safe case, for 640 logical cells per model invocation
across eight held-out workflows. **[LIVE RESULT: mechanism effects, qualifying
reversal, and sensitivity statement.]** If the preregistered empirical gates are
not met, the framework and audit stand as the contribution without a manufactured
effectiveness claim.

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
2. We define an executable evaluation contract in which models propose typed
   actions while trusted code determines local permission and terminal harm.
3. We evaluate defense transfer by mechanism, with explicit visibility contracts,
   utility eligibility, and a preregistered criterion for a genuine defense
   reversal.

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
model refusal, schema failure, local block, defense block, tool failure, and
forbidden terminal state are recorded separately.

We study four generating mechanisms:

- **Intent decomposition:** only the global-objective projection changes. The
  treatment replaces the constant-layout global field with `NOT_AVAILABLE` while
  preserving role-local work.
- **Context fragmentation:** the complete policy fact multiset remains in the
  pipeline, but routing prevents the decision role and realistic monitor from
  seeing the decisive conjunction.
- **Authorization drift:** a trusted source restriction exists in both arms;
  only its downstream propagation slot changes from the restriction to
  `NOT_PROVIDED`. The deterministic pilot uses a runtime-owned restriction
  record rather than an externally authenticated credential.
- **Policy heterogeneity:** facts remain complete and the source constraint is
  represented by the source policy; only the Actuator's policy binding changes
  from that policy to a frozen, internally consistent downstream policy that
  disagrees on the focal action. Restriction visibility is held fixed across the
  pair.

Mechanisms are identified by intervention history, not necessarily inferable
from the terminal trace. Fragmentation and drift can deliberately create the same
downstream view. This observational ambiguity motivates intervention-based
labels.

## 3. Experimental framework

### 3.1 Fixed pipeline and simulator

Every workflow uses a scripted Planner, Retriever, Transformer, and Actuator in a
fixed order. Agents receive their task, a constant-layout fact projection, one
executable policy identifier, the upstream artifact, and permitted simulated
tools. The environment can only create in-memory records representing a document
send or payment issuance. Synthetic identifiers and `.invalid` addresses prevent
real-world effects.

Each workflow declares a source principal, a three-entry principal registry, one
authority edge, legitimate work, one global invariant, a forbidden terminal
state, and a matched benign state. The safe/unsafe pair changes one authoritative
fact—consent or approval validity—with all derived labels recomputed by trusted
code. The current loader checks principal references and the Boolean fact named by
the authority edge. These records remain simulator declarations rather than
verified external credentials or cryptographic bindings to the terminal action.

### 3.2 Typed proposal and trusted judgment

The backend receives only an isolated role-local stage-context copy, the declared
finite-schema action, a redacted upstream artifact, and a seed; it does not receive
the scenario object or authoritative full-fact map. Its proposal must canonically
equal the declared action. It cannot assert its own authorization, policy,
provenance, record class, recipient class, or approval status. The runtime parses the
proposal, evaluates the local policy and defense on the trusted declared action,
executes that action in the simulator, and evaluates the invariant. Local and
global labels never come from an LLM judge.

The primary experiment hides defense identity and sidecar metadata from the
model. This isolates middleware enforcement from behavioral prompting. A shadow
replay analysis evaluates every defense on the same frozen local-only proposal
trace; it is reported separately from closed-loop completion.

### 3.3 Scenarios and controls

The development fixtures cover protected-summary disclosure and an approval-gated
vendor payment. The confirmatory study uses eight additional sealed workflows—two
each in healthcare, public services, education, and finance/procurement. The two
development fixtures are excluded from those eight unless the final paper labels
the analysis exploratory.

Every mechanism-on unsafe run has four distinct comparisons:

1. its same-topology mechanism-off counterfactual;
2. its matched-safe utility case;
3. a single-agent/full-context architecture reference; and
4. an omniscient reference monitor.

The matched-safe case is not a causal control. It validates the terminal label and
measures legitimate completion. The single-agent reference jointly changes
topology and context and therefore does not identify the mechanism; the paired
same-topology control does. These mechanism-off cells are the pilot's aligned
four-agent controls; no separate `aligned_multi_agent` cohort is included in the
192-trace count. They are mechanism-specific rather than one shared neutral
fixture.

### 3.4 Defenses and visibility

We compare local-only enforcement, a history monitor over accumulated shareable
public-evidence records, source anchoring through a trusted runtime record,
runtime-authenticated provenance carrying, and policy intersection. The omniscient
reference is excluded from realistic rankings.

Each defense's failure is interpreted relative to its information contract. The
history monitor cannot access private facts. Source anchoring consults a trusted
source-restriction record but does not authenticate a principal or infer unrelated
hidden context. Provenance retains source-derived labels but not the full goal
graph. Policy intersection evaluates
all policies selected by a fixed applicability function but does not invent
missing facts. This observability table is published before outcomes.

## 4. Study design and analysis

The confirmatory matrix is:

\[
8\ workflows \times 4\ mechanisms \times 2\ assignments
\times 5\ defenses \times 2\ permissibility\ variants = 640
\]

logical cells per model invocation. The original 320-cell treatment slice is
retained, but causal claims use the paired 640-cell design. Architecture controls
and the omniscient upper bound are additional. We first freeze one model snapshot
for every role; a second model family is a replication, not a source of role
heterogeneity.

The primary mechanism effect is the workflow-weighted paired difference in unsafe
local-only LGH. Defense analysis reports mechanism-specific residual LGH and
absolute risk reduction. Benign completion and defense overblocking are separate;
`1 - utility` is not automatically attributed to defense overblocking.

The base workflow is the experimental unit. We report all eight paired contrasts,
finite-benchmark means, direction counts, and leave-one-workflow/domain-out
sensitivity. Workflow-cluster bootstrap intervals are descriptive. A secondary
regression includes mechanism, assignment, defense, their interactions, and
workflow effects; it does not use run-level independence.

Defenses must meet prespecified utility eligibility before ranking. A qualifying
reversal requires opposite residual-risk margins of at least 0.25 in two
mechanisms and direction agreement in six of eight workflows. Small tied rank
changes do not count. The equally weighted pooled winner's maximum mechanism
regret makes the mixture dependence explicit.

## 5. Results

### 5.1 Engineering validation

The current repository executes 192 deterministic development traces: 160 paired
core cells, 16 single-agent references, and 16 omniscient references. The schema,
policy truth tables, one-coordinate transformations, HMAC-authenticated provenance
sidecars, terminal labels, metric recomputation, and matched controls pass the
automated validation suite. The intended defense profiles differ by mechanism in
the scripted oracle.
These outcomes are unit-oracle predictions and are not evidence about model
behavior or real defense effectiveness.

### 5.2 Held-out live-model results

**[WITHHELD UNTIL SEALED RUN]** Report, in order:

1. proposal validity, refusals, and capability errors by arm;
2. mechanism-on/off local-only paired effects by workflow;
3. the mechanism-by-defense residual-LGH matrix with safe utility;
4. qualifying reversal tests and workflow direction counts;
5. pooled rankings, maximum regret, and alternative mechanism weights; and
6. leave-one-workflow/domain-out and second-model replication sensitivity.

If any empirical go/no-go gate fails, replace this section with a transparent
null/mixed result and use the position-paper conclusion. No scripted number is
substituted for a live result.

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

The study remains a controlled benchmark. The planner and topology are scripted;
actions are typed; tools are simulated; workflows are authored; eight workflows
do not establish domain prevalence; one snapshot does not establish model-family
generality; and no condition models adaptive attackers, colluding workers, covert
channels, or arbitrary free-form semantic leakage. A single-agent comparison
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
visibility part of the experimental object. **[LIVE RESULT OR POSITION FALLBACK
CONCLUSION INSERTED UNDER PREREGISTERED RULE.]** Whether the empirical reversal
appears or not, future compositional-safety reports should separate mechanism,
policy authority, observability, and terminal outcome rather than compressing them
into one attack-success number.
