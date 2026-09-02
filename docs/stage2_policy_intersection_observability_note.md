# Stage 2 policy-intersection observability note

**Recorded:** 2026-09-01
**Status:** additive post-release implementation audit; no historical run,
result, checksum, protocol, or tag has been changed or rerun.

## Finding

The v0.2.2 policy-intersection condition was documented as receiving only the
runtime-selected applicable policy IDs and current gate-visible facts. The
runner serialized exactly those fields in `defense_input`, but that serialized
view was not the evaluator's capability boundary: the frozen runner passed the
full role-local `StageContext` to `DefenseEngine`, which forwarded it to the
policy evaluator.

Two policy families consequently read fields outside the declared
policy-intersection view:

- intent decomposition's `objective_authorization_guard` read
  `objective_view`; and
- authorization drift's `restriction_guard` read `restriction_visible`.

Context fragmentation's `visible_invariant_guard` and policy heterogeneity's
`global_invariant_guard`/`allow_if_all` used gate-visible facts only. The shared
legacy entry point was nevertheless structurally over-capable.

## Historical interpretation

The published rows and aggregates remain exact outputs of the frozen v0.2.2
program. They are not data-corruption errors, and no corrected counterfactual
values can be asserted because a capability-minimal evaluator and its
missing-input semantics were not prospectively frozen.

Policy-intersection results involving intent decomposition or authorization
drift must therefore not be interpreted as evidence for the narrower
policy-IDs-plus-gate-facts information contract. This qualification also applies
to their safe-utility and overblocking diagnostics, pooled policy ordering, and
the five of six policy-intersection mechanism-pair interactions that contain
intent or authorization drift. The public manifest counts imply that 57 of 123
terminal policy-intersection opportunities used the two affected predicate
families (34 intent plus 23 authorization); this is arithmetic on released
counts, not a replay.

Stage 1, its core mechanism-on/off result, Stage 2 aggregation and denominators,
and the local, history-monitor, source-anchoring, provenance-carrying, and
omniscient-reference programs are unaffected by this finding. The broad
development observation that defense coverage varied by mechanism still has
unaffected support, but the four-defense matrix should not be described as
uniformly enforcing every declared information contract.

## Prospective boundary

Stage 1/2 artifacts remain immutable. Stage 3 now uses a separate,
evaluation-free Stage 4 projector whose exact observation types cannot accept a
rich `StageContext`. That projector establishes the view boundary only; it does
not produce defense decisions.

Before any post-Stage-4 defense replay is frozen, a separate pure evaluator must:

- accept only the typed projected view and trusted terminal action;
- freeze missing/unknown-fact semantics;
- reject unknown policies and missing or extra input fields;
- pass noninterference tests for every undeclared field; and
- be total across all sealed workflow, mechanism, assignment, and safety cells.

Only that separately versioned evaluator may be applied to future Stage 4
traces. Historical Stage 2 rows cannot enter, correct, or replace a Stage 4
numerator or denominator.
