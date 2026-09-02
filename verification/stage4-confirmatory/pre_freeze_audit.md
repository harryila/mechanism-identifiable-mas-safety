# Stage 4 provider-free pre-freeze audit

**Assessment: PASS for the implemented invariants after two remediations, with
the publication/operator trust boundary explicitly qualified. The freeze is
still a draft and no Stage 4 empirical result exists.**

Audit date: 2026-09-02. The pre-audit public baseline was commit
`171ec78e96126a4876eac1f1853ad30f449724ad`. The remediated implementation
rehearsed by this report is commit
`b241a795f6360c8830ffc3930479d0d1de3b8409`. Its draft freeze-manifest SHA-256
is `0bbb66e0b4c8cd57017eccc8e47a130dd9e7d260f47afcca284b076c86d9fa44`.

Two separate review processes inspected disjoint halves of the execution
chain. Neither process was an external human auditor. Both were instructed not
to inspect outcomes, use credentials, contact a provider, or make model calls.
There was no Stage 4 result directory to inspect.

## Invariant results

| Invariant | Result | Evidence summary |
|---|---|---|
| Schedule row to actual `RunSpec` | PASS | Independent schedule reconstruction, strict scalar typing, 768 unique run bindings, binding hash, and exact schedule-ordered execution are checked before and after execution. |
| Committed prompt to actual SDK request | PASS, scoped | The offline commitment builder and live backend use the same renderer. Actual role/order/hash/byte identity is checked against one of 3,072 schedule-indexed commitments and independently replayed during release. This proves SDK keyword arguments and archive identity, not provider-received wire bytes. |
| Authority before client construction | PASS | Freshness is rechecked, the receipt is exclusively created and synced, and only then is the backend factory invoked. Tests spy on this order and show preflight failure creates no client or state. |
| Provider failure and budget accounting | PASS after repair | Admission precedes network I/O; every held reservation settles or forfeits once; failure/retry/abort rules are exact. Invalid returned usage now carries its durable forfeiture event into the raw response record and yields the intended typed budget abort. |
| Trace to LGH/safe-completion labels | PASS | Exact runtime identity, raw/ledger/call links, deterministic trace semantics, and source commitment are validated. The release builder replays raw decisions through the frozen runner and recomputes labels. |
| Gate arithmetic and denominators | PASS | Internal analysis/decision code and the self-contained public verifier independently agree on exact rational thresholds and schedule-derived populations. |
| Private archive to sanitized release | PASS after repair | Archive hashes, execution events, call bijection, replay, projection allowlist, secret scan, no-replace publication, and public verification are enforced. Release construction now recomputes and exactly compares every field in the private decision artifact. |
| Intentional corruption detection | QUALIFIED PASS | Localized and partially coordinated mutations across schedule, requests, raw results, ledger, trace, outcomes, decision, archive, and public files are rejected. A coordinated replacement of all public rows and all derived public checksums remains inside the publication trust boundary until an external post-result anchor exists. |

The exact trust boundaries and responsible files are mapped in
[`docs/stage4_trusted_computing_base.md`](../../docs/stage4_trusted_computing_base.md).

## Defects found and repaired

1. When returned usage was malformed or exceeded the Stage 4 request-byte
   condition, the ledger durably wrote a forfeiture but the backend archived a
   null budget event because settlement raised before assignment. The batch was
   still fail-closed and charged the full reservation, but the raw-response to
   terminal-ledger link and abort classification were wrong. The exception now
   carries the already-written event, the backend archives it, and provider-free
   backend/executor regressions check the exact link and typed abort.
2. The release builder hashed and schema-checked private `decision.json` but
   semantically compared only its top-level `decision`. It now reconstructs the
   typed commitments/outcomes with source-byte-loaded frozen modules, recomputes
   the complete decision, and performs a type-sensitive exact comparison. A
   coherently rehashed private-detail mutation is rejected by regression test.

Neither repair changes the schedule, hypotheses, estimands, outcome rules,
provider matrix, public four-file schema, or budget values. The provider-free
draft freeze and detached checksum were regenerated after both repairs.

## Arithmetic spot checks

- Schedule: 768 unique runs and 384 adjacent two-row pairs.
- Off/unsafe gate: 192 scheduled rows; at most 9 LGH events pass.
- Matched-safe gate: 384 scheduled rows; at least 336 completions pass.
- Structured decisions: exact `20 * valid > 19 * attempted`; exactly 95% fails.
- Refusal/escalation: 32 arms of 24; at least 18 defines a dominant arm.
- Mechanism effect: 48 unsafe pairs per mechanism; a sum of at least 12 meets
  the 0.25 threshold before the model/workflow/domain consistency gates.

## Budget-contract decision

The proposed canonical-request-byte reservation was **not** adopted. OpenAI's
[token-counting documentation](https://developers.openai.com/api/docs/guides/token-counting)
says exact input counts include request-structure formatting tokens that may not
appear in locally tokenized fields and directs callers to
`POST /responses/input_tokens` for the exact count. No reviewed provider
contract states that reported input tokens can never exceed local canonical
request bytes. A post-response check therefore cannot justify a smaller
pre-call hold when a transport failure returns no usage.

Independent arithmetic reproduced the frozen amounts:

| Scope | GPT-5.4 | GPT-5.5 | Total |
|---|---:|---:|---:|
| Byte-priced input plus 512-token output cap on every potential call | USD 26.552610 | USD 53.105220 | USD 79.657830 |
| Current completion-safe authority | USD 85.674540 | USD 171.349080 | USD 257.023620 |

The first row would also be the hypothetical completion-safe amount under a
byte-sized reservation, so that change would still not make the 768-run matrix
safe under USD 20. The current reservation policy and USD 257.023620 minimum
remain unchanged.

## External wheel-environment rehearsal

A disposable environment was created outside the repository from the exact
remediated commit. No API or provenance credential was present.

- Python: 3.10.18 in isolated `-I -B` mode.
- Installation: non-editable wheel; project 0.2.2 and `openai==3.6.0`.
- Rehearsal wheel SHA-256:
  `299bb1d157626df751b9255f9121bbb64ef2974dcb13171b3784dd16b49eca73`.
- All 28 manifest-tracked installed project source files matched both the
  manifest and clean repository bytes.
- No installed project `__pycache__`, `.pyc`, or `.pyo` existed before or after
  the rehearsal.
- The canonical execution command passed the process-boundary checks and then
  exited with the expected `stage4_execution_preflight_failed` error.
- Direct read-only preflight reported zero calls, no client, no authority, and
  no ledger. Static manifest and schedule/runtime checks passed. Its blockers
  were exactly the unresolved draft/finalization categories: credential and
  provenance identities, budget, storage, one-shot authority, final
  commit/parent/tag binding, and account-specific snapshot access.
- The private output directory and one-shot receipt were absent before and
  after the command.

The rehearsal environment is not the eventual production environment. The
protocol still requires a newly provisioned environment from the final frozen
commit after every finalization field is resolved.

## Provider-free verification record

- Full repository suite: **411 passed**.
- Focused execution-chain suites: **144 passed**.
- Focused outcome/release suite: **88 passed**.
- Candidate freeze rebuild/check: `pass=true`, `provider_calls_made=0`.
- Stage 1 public verifier: PASS (with its documented attestation limits).
- Stage 2 public verifier: PASS (1,152 rows recomputed).
- Stage 3 construction, detached seal, and repository binding: PASS.
- Stage 4 public verifier: `NOT_RUN: release_not_present` and
  `No Stage 4 empirical result was verified.`

## Remaining blockers

The project is ready for a budget decision, not yet ready to execute. It still
needs a separately authorized sufficient ceiling, a fresh unexposed Stage
4-only credential, a fresh provenance key, real encrypted/immutable storage
attestations, constrained finalization, a clean final freeze commit and
annotated tag, and one-shot authority. Account-specific snapshot access remains
deliberately untested until the first scheduled calls.
