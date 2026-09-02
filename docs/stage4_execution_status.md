# Stage 4 execution status

**Status: offline implementation only; production execution is not frozen or
authorized.**

`src/mas_safety/stage4_live.py` constructs and validates the prospective
768-run schedule without importing the Stage 1 live orchestration and without
containing a provider client. `src/mas_safety/stage4_analysis.py` implements the
workflow-clustered primary and sensitivity summaries. These modules can be
tested with synthetic labels, but they cannot make a model call.

`src/mas_safety/stage4_observability.py` separately projects exact,
capability-minimal defense views and rejects rich runtime contexts. It is
deliberately evaluation-free. Before any post-live defense replay, a distinct
pure evaluator must be prospectively frozen over those typed views, including
missing-fact semantics, totality, and noninterference tests. The historical
Stage 2 evaluator is not a substitute; its policy-intersection boundary is
qualified in the
[`post-release observability note`](stage2_policy_intersection_observability_note.md).

There is intentionally no `run-stage4-confirmatory` command yet. Registering
that command would be premature until one exact Stage 4 freeze manifest binds
all of the following before any confirmatory call:

- all eight audited scenario packages and their hashes;
- exact prompts, response schemas, simulator fixtures, and hashes;
- two immutable provider model snapshot IDs and all request parameters;
- the complete ordered schedule, deterministic seed, and schedule hash;
- pair adjacency, timeout, retry, and provider-error retention rules;
- an independent Stage 4 call budget and hard cost ceiling;
- a Stage 4-only one-shot execution authority and canonical authority path;
- a Stage 4-only private raw-output path and preservation rules;
- the nondevelopment credential boundary (never the Stage 1 credential);
- primary success/failure gates and frozen analysis serialization; and
- public-release redaction, checksumming, and verification rules.

The eventual CLI must fail closed when any bound hash or identity differs,
when the one-shot receipt already exists, when its independent budget is
missing or exceeded, when its output target is not the canonical private
Stage 4 location, or when the credential is not the separately designated
nondevelopment credential. Stage 1 and Stage 2 authorities, budgets, outputs,
and protocols are not valid substitutes.

Provider failures cannot be silently dropped by the analysis module. The
future freeze must decide their treatment prospectively; only then may retained
raw runs be converted into the complete binary outcome table required by the
analysis API.
