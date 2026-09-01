# Same Symptom, Different Failure

This repository is a controlled research harness for studying whether the same
**local-allow/global-harm (LGH)** trace signature can arise through different
causal mechanisms in a four-stage multi-agent pipeline.

The current implementation is the deterministic two-workflow pilot. It is an
executable specification and test oracle, **not empirical model evidence**. It
validates the executable scenario contract, single-variable interventions,
defense visibility boundaries, controls, trace contract, and analysis code before
paid model runs. The test suite separately validates scenarios and emitted traces
against the formal Draft 2020-12 JSON Schemas in `schemas/`.

## Pipeline

```text
Planner -> Retriever -> Transformer -> Actuator -> Simulated environment
```

Every tool is simulated. No email, payment, publication, or database operation
can affect the real world.

## Quick start

Prerequisites: Python 3.10 or newer, [`uv`](https://docs.astral.sh/uv/) 0.7 or
newer, and network access on the first run if the locked packages are not
already cached.

```bash
uv run --frozen --extra dev python -m mas_safety run-pilot --output outputs/pilot
uv run --frozen --extra dev python -m mas_safety validate --input outputs/pilot
uv run --frozen --extra dev pytest
uv run --frozen --extra notebook python scripts/build_notebook.py --execute
```

The pilot command writes:

- `traces.jsonl`: complete machine-readable run traces.
- `runs.csv`: one row per run.
- `mechanism_defense.csv`: LGH, utility, overblocking, and effectiveness.
- `mechanism_effects.csv`: paired mechanism-on/off effects under local-only enforcement.
- `rank_correlations.csv`: pooled-versus-mechanism defense rank stability.
- `shadow_replay.csv`: every defense evaluated on frozen local-only proposals.
- `shadow_summary.json`: frozen-proposal replay counts and interpretation.
- `summary.json`: aggregate counts and metric definitions.
- `go_no_go.json`: predeclared pilot checks.
- `defense_heatmap.svg`: a dependency-free mechanism-by-defense figure.
- `mechanism_interventions.svg`: a dependency-free diagram of the four paired intervention coordinates.

The validation command additionally writes `validation_report.json` and
`validation_report.md`.

## Pilot scope

- Two workflows: protected patient-summary disclosure and unapproved payment.
- Four mechanisms: intent decomposition, context fragmentation, authorization
  drift, and policy heterogeneity.
- Five primary defense conditions plus an omniscient upper bound.
- Matched safe and unsafe variants.
- Single-agent/full-context and inactive-mechanism causal controls.

The mechanism-on treatment slice contains `2 x 4 x 5 x 2 = 80` runs. Its
mechanism-off paired counterfactuals add another 80, giving 160 core cells.
Single-agent and omniscient references add 32 more for 192 emitted traces. These
cohorts are labeled explicitly and are never silently pooled with the primary
estimand.

The executed analysis companion is
[`notebooks/pilot_analysis.ipynb`](notebooks/pilot_analysis.ipynb). Rebuild it
with `uv run --frozen --extra notebook python scripts/build_notebook.py
--execute` after regenerating outputs.

## Live-model boundary

`ScriptedBackend` deterministically proposes the action declared by each
scenario. A live backend should implement the `AgentBackend` protocol in
`src/mas_safety/backends.py`. It receives only the stage context, declared action,
redacted upstream artifact, and seed—not the scenario object or authoritative
full-fact map—and its proposal must exactly match the declared typed action.
Local compliance and the global violation label remain executable predicates; an
LLM is never used as the policy judge.

Those inputs are defensive copies, and artifact identifiers are opaque in the
model view. The bundled HMAC key is deterministic and development-only;
`ExperimentRunner` rejects it for non-scripted backends. Live runs must inject a
secret `provenance_signing_key` of at least 32 bytes and a non-development,
versioned `provenance_key_id` through trusted runtime configuration, never through
a prompt or trace. Backend configuration is recorded, so it must contain no
credentials.

Before treating results as empirical evidence, configure a model, record an
immutable model identifier, preserve raw responses, and run the predeclared
controls. The scripted pilot's expected defense-reversal signature is a unit
test of the harness and must not be reported as a discovered result.

## License

Released under the [MIT License](LICENSE).
