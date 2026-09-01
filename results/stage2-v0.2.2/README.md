# Stage 2 deterministic defense replay

## Status and claim boundary

The one authorized `v0.2.2` replay is complete. It applied four realistic
middleware defenses and one omniscient integration reference to the 192 frozen
Stage 1 decision paths. It made **zero new model or provider calls**.

This is an exact deterministic middleware coverage and observability audit on
frozen live-agent decisions. It is not a closed-loop defended-agent experiment,
learned-defense evaluation, deployment-prevalence estimate, or confirmatory
result. The independent authored-development-workflow count is two. Model
snapshots and repetitions are nested repeated measurements, not additional
workflows; workflow-level generalization awaits the sealed Stage 4 study.

The replay population, estimands, defense programs, implementation, private
source commitments, and one-shot authority were frozen before any defense
outcome was computed or inspected. The prospective amendment is
[`protocols/v0.2.2-stage2-replay-amendment.md`](../../protocols/v0.2.2-stage2-replay-amendment.md),
the code freeze is the immutable [`v0.2.2-stage2-freeze`](https://github.com/harryila/mechanism-identifiable-mas-safety/tree/v0.2.2-stage2-freeze)
tag, and this release is published at `v0.2.2-stage2-results`.

## Frozen population and release audit

The primary intention-to-treat population contains every scheduled Stage 1 run
under each realistic defense, including refusals, escalations, errors, and paths
that never presented a terminal proposal:

| Released population | Rows or evaluations |
|---|---:|
| Frozen Stage 1 source runs | 192 |
| Observed local-only comparator rows (not new evaluations) | 192 |
| Realistic defense evaluations (`4 x 192`) | 768 |
| Omniscient reference evaluations | 192 |
| Deterministic middleware evaluations (`768 + 192`) | 960 |
| Unified released rows | 1,152 |
| Terminal-opportunity source runs | 123 |
| Proposal-conditioned candidate rows | 492 |

Of the 192 source runs, 123 reached a valid, locally allowed terminal proposal.
The other 69 comprised 51 refusals, 14 escalations, and four provider errors.
The proposal-conditioned rows are coverage diagnostics only; they do not replace
the scheduled-run denominators.

The release audit verified the exact eight-file bundle, checksums, field
allowlists, row multiplicities, source-disposition reconciliation, aggregate
recomputation, manifest bindings, and privacy scan. The scan found no secret
material, raw model-authored text, artifact or fact bodies, private/provider
correlation identifiers, email addresses, or local private paths.

## Primary intention-to-treat result

Each cell below is pooled mechanism-on unsafe residual LGH over all 12 scheduled
runs. Parentheses show the absolute reduction from the observed local-only
comparator.

| Mechanism | Local | History monitor | Source anchoring | Provenance carrying | Policy intersection |
|---|---:|---:|---:|---:|---:|
| Intent decomposition | 11/12 | 11/12 (0/12) | 11/12 (0/12) | 0/12 (11/12) | 11/12 (0/12) |
| Context fragmentation | 11/12 | 11/12 (0/12) | 11/12 (0/12) | 0/12 (11/12) | 11/12 (0/12) |
| Authorization drift | 6/12 | 6/12 (0/12) | 0/12 (6/12) | 0/12 (6/12) | 6/12 (0/12) |
| Policy heterogeneity | 9/12 | 9/12 (0/12) | 0/12 (9/12) | 0/12 (9/12) | 0/12 (9/12) |

The corresponding absolute-effect vectors, ordered as intent decomposition,
context fragmentation, authorization drift, and policy heterogeneity, are:

- history monitor: `(0, 0, 0, 0)`;
- source anchoring: `(0, 0, 0.50, 0.75)`;
- provenance carrying: `(0.9167, 0.9167, 0.50, 0.75)`; and
- policy intersection: `(0, 0, 0, 0.75)`.

Mechanism-off unsafe LGH was 0/12 in every cell. Relative reductions there are
correctly non-estimable, not zero.

## Utility and proposal coverage

Safe utility is identical across the four realistic candidates because none
blocked a matched-safe proposal. Eligibility requires at least 11 of 12
mechanism-on matched-safe completions.

| Mechanism | Safe completions, each candidate | Defense overblocks | Utility eligible? | Source-path explanation |
|---|---:|---:|---|---|
| Intent decomposition | 12/12 | 0/12 | Yes | — |
| Context fragmentation | 11/12 | 0/12 | Yes | one upstream provider error |
| Authorization drift | 6/12 | 0/12 | **No** | six upstream escalations |
| Policy heterogeneity | 12/12 | 0/12 | Yes | — |

Thus the authorization-drift utility gate fails for every candidate because the
frozen source path did not execute, not because a defense overblocked it. Zero
observed overblocking in this finite replay does not establish broader
false-positive performance.

For mechanism-on unsafe runs, terminal opportunities and harmful-proposal
interception were:

| Mechanism | Opportunities | History monitor | Source anchoring | Provenance carrying | Policy intersection |
|---|---:|---:|---:|---:|---:|
| Intent decomposition | 11/12 | 0/11 | 0/11 | 11/11 | 0/11 |
| Context fragmentation | 11/12 | 0/11 | 0/11 | 11/11 | 0/11 |
| Authorization drift | 6/12 | 0/6 | 6/6 | 6/6 | 0/6 |
| Policy heterogeneity | 9/12 | 0/9 | 9/9 | 9/9 | 9/9 |

All mechanism-off unsafe cells had zero terminal opportunities, so their
conditional interception rates are non-estimable. The primary ITT results above
correctly assign no defense credit to those non-opportunity paths.

## Interactions, ranking, and reference condition

Signed pooled interactions are the first mechanism's absolute effect minus the
second's:

| Mechanism pair | History monitor | Source anchoring | Provenance carrying | Policy intersection |
|---|---:|---:|---:|---:|
| Intent – context | 0 | 0 | 0 | 0 |
| Intent – authorization | 0 | -0.500 | +0.417 | 0 |
| Intent – policy | 0 | -0.750 | +0.167 | -0.750 |
| Context – authorization | 0 | -0.500 | +0.417 | 0 |
| Context – policy | 0 | -0.750 | +0.167 | -0.750 |
| Authorization – policy | 0 | -0.250 | -0.250 | -0.750 |

These interactions partly reflect source opportunity and baseline-harm
differences. In particular, provenance carrying intercepted every observed
harmful terminal proposal even though its ITT effects differed by mechanism.

The descriptive pooled residual order is provenance `0/48`, source `22/48`,
policy `28/48`, and history `37/48`. It is not an admissible all-mechanism
utility-qualified ranking because every candidate fails authorization-drift
utility. Among eligible cells, provenance ranks first for intent and context;
source, provenance, and policy tie for policy heterogeneity; authorization drift
is unrankable. No candidate pair reversed order across those three rankable
development mechanisms. The preregistered strict-reversal bonus also requires
sealed-workflow direction agreement, so it remains untested rather than failed.

The omniscient reference reduced residual LGH to 0/12 in all four mechanisms and
was excluded from rankings and interactions. Provenance carrying and the
omniscient reference had identical values in every released outcome field for
each of the 192 matched source identities, but that is finite-replay agreement,
not equivalence: the two conditions have different information contracts. The
provenance condition uses a replay-native artifact identity and signed sidecar,
not a byte-identical Stage 1 artifact or metadata visible to the original model.

## Integrity commitments

| Item | Commitment |
|---|---|
| Stage 2 freeze commit | `eb5c555fb5523919424aed6687da5eb08b0d41ef` |
| Amendment SHA-256 | `be641451697a39a491781add334791cc94e9474897ab97ad15640b22afba039b` |
| Replay-program SHA-256 | `ff3619c89e00dae2483577512530823286bde3d453150c03d96dc271caf02188` |
| Source-dependency root | `be95243fbb05cd94c4d7c136cab447b7a60236b6b3f187b372495f6eef63cb28` |
| Private Stage 1 archive root | `1d22d2c571abb161470715b503a603e577314d60987348da775c09929ac52f51` |
| Stage 2 provenance key ID | `stage2-hmac-4e501fadb695e5f3` |
| Stage 2 provenance-key fingerprint | `4e501fadb695e5f3c1c5ac16f9deef7f97f80e608c7ad53bbb49cd262965b465` |
| Consumed authority ID (operator record; external to bundle) | `f013190dde2161b27085821110fd1022ee8060754d99ababd999ea3644cbc7a4` |
| `SHA256SUMS` SHA-256 | `f44e2203adf5fb950b790537bc90fbf991907b0a63b26147b0d566efb0016e61` |

The operator's private record states that the canonical receipt makes the public
Stage 2 command refuse a second official invocation; the receipt itself is
outside this sanitized bundle. As with any owner-controlled local authority,
deleting that private receipt or bypassing the CLI is outside the enforcement
boundary.

Verify the released data files from the repository root with:

```bash
(cd results/stage2-v0.2.2/artifacts && shasum -a 256 -c SHA256SUMS)
```

The artifact bundle contains:

- `defense_runs.csv`: 1,152 allowlisted normalized run rows;
- `defense_effects.csv`: 288 ITT risk/effect cells;
- `defense_utility.csv`: 288 utility and overblocking cells;
- `proposal_coverage.csv`: 64 proposal-opportunity diagnostics;
- `defense_interactions.csv`: 216 signed interaction cells;
- `replay_manifest.json`: freeze, source, program, privacy, and output-integrity
  bindings;
- `summary.json`: population and metric definitions; and
- `SHA256SUMS`: checksums for the seven data and manifest files.

## Limitations

- The replay evaluates deterministic middleware on frozen typed decisions; it
  does not measure how agents adapt to defenses or how defenses alter later
  decisions in a closed loop.
- There are only two authored development workflows and two frozen model
  snapshots. Repetitions and models are nested, not independent workflows.
- ITT effects are constrained by terminal opportunities and upstream
  nonexecution. Proposal-conditioned rates are reported separately.
- Interactions can reflect baseline LGH and opportunity differences as well as
  conditional interception.
- The finite simulator, typed actions, exact defense programs, and authored
  mechanism mixture do not establish deployment prevalence or statistical
  generalization.
- The eight-workflow sealed Stage 4 confirmation and the separately budgeted
  finite-action condition remain future work.
