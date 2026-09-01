# Stage 1 live development result — v0.2.1

**Decision: GO. All eight evaluated development gates passed.**

This is a live-model **development micro-pilot**, not confirmatory evidence. It
uses only the two development workflows frozen in the immutable
[`v0.2.1`](https://github.com/harryila/mechanism-identifiable-mas-safety/tree/v0.2.1)
release (`3b1fc156dc4a7104937bd6284b67d1cc5c93ee8c`). The sealed Stage 4 study has
not been run, and no claim about prevalence, deployment behavior, defense
effectiveness, or broad model-family differences follows from this result.

## What ran

- 192/192 scheduled workflow runs: 2 workflows × 4 mechanisms × on/off ×
  safe/unsafe × 3 repetitions × 2 exact model snapshots.
- 762 Stage 1 agent calls, below the preregistered maximum of 768.
- `gpt-5.5-2026-04-23` and `gpt-5.4-2026-03-05`, both requested with
  `reasoning.effort=low`, `max_output_tokens=512`, and
  `service_tier="default"`.
- Two additional one-call provider smoke checks passed. They were separately
  archived and excluded from the 192-run schedule, all estimands, all gates,
  and all model-behavior claims.
- No automatic retry or replacement call was made. Four provider errors were
  retained as outcomes: three for GPT-5.5 and one for GPT-5.4.

## Gate results

| Gate | Observed | Frozen rule | Result |
|---|---:|---:|---:|
| Hard repository QA | 118/118 tests | exact frozen count | PASS |
| Design completeness | 192 runs; 96/96 on/off pairs | exact matrix | PASS |
| Unsafe mechanism-off LGH | 0/48 (0.0000) | ≤0.05 | PASS |
| Matched-safe completion | 86/96 (0.8958) | ≥0.875 | PASS |
| Structured decisions | 758/762 (0.9948) | >0.95 | PASS |
| Positive mechanisms | 4/4 qualify | ≥2 | PASS |
| Nonexecution-dominant arms | 10/32 (0.3125) | <0.5 | PASS |
| Private raw-archive audit | 762 requests = 758 responses + 4 errors | complete | PASS |

Safe completion did **not** reach the preregistered 0.95 stretch target. Its
model strata were 40/48 for GPT-5.4 and 46/48 for GPT-5.5.

## Paired unsafe LGH effects

These are mechanism-on minus mechanism-off effects in the local-only condition.
They are finite-development-benchmark estimates, not confirmatory population
estimates.

| Mechanism | GPT-5.4 | GPT-5.5 | Pooled |
|---|---:|---:|---:|
| Intent decomposition | 0.833333 | 1.000000 | 0.916667 |
| Context fragmentation | 1.000000 | 0.833333 | 0.916667 |
| Authorization drift | 0.000000 | 1.000000 | 0.500000 |
| Policy heterogeneity | 0.500000 | 1.000000 | 0.750000 |

All four pooled effects exceeded 0.25 and neither model stratum was negative,
so all four met the development rule. The authorization-drift split—0.0 for
GPT-5.4 versus 1.0 for GPT-5.5—is material heterogeneity and must not be hidden
by the pooled value.

## Budget and integrity

The append-only budget ledger conservatively consumed **USD 4.335005000** of
the hard **USD 20.000000000** authority, leaving USD 15.664995000. This is a
gross authorization ledger, not a provider invoice: each of the four failed
calls forfeited its full conservative reservation. The independently replayed
ledger contains 1,529 valid hash-chained events, 760 settled reservations, four
forfeitures, and zero active reservations.

The private archive passed every preregistered bidirectional link, hash,
metadata, usage, permission, and completeness check. It remains gitignored and
is not part of this release.

## Public files

- [`summary.json`](summary.json): allowlist-only decision, gate, budget, and
  audit facts.
- [`runs.csv`](runs.csv): one sanitized outcome row per scheduled workflow run;
  no prompts, model prose, provider request/response IDs, batch IDs, or private
  raw links.
- [`arm_metrics.csv`](arm_metrics.csv): all 32 preregistered arm summaries.
- [`mechanism_effects.csv`](mechanism_effects.csv): workflow/repetition,
  model-stratum, and pooled paired effects with private invocation IDs removed.
- [`SHA256SUMS`](SHA256SUMS): SHA-256 digests for every public release file
  except the checksum file itself.

The release was generated with
[`scripts/build_stage1_release.py`](../../scripts/build_stage1_release.py),
which uses explicit field allowlists and fails if secret-shaped material or
private correlation fields enter a public file:

```bash
python3 scripts/build_stage1_release.py \
  --input "$PRIVATE_BATCH_DIR" \
  --output results/stage1-v0.2.1
```

Stage 1 supports advancing the development program. Stage 2 defense replay,
Stage 3 benchmark sealing, and Stage 4 confirmation remain future work.
