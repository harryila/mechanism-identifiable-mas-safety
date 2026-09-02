# Stage 4 trusted computing base

This note is a reviewer map for the Stage 4 confirmatory execution. It does not
authorize execution and is not empirical evidence. The checked-in Stage 4
freeze remains a deliberately unexecutable draft.

The implementation is designed to make each important transition checkable by
more than the component that produced it. It cannot eliminate trust in the
operator, machine, provider, or storage system. The table below identifies the
code that owns each transition, the independent check, and the failure mode.

| Invariant | Producing path | Independent check | Failure behavior |
|---|---|---|---|
| Schedule row becomes exactly one `RunSpec` | `stage4_live.py` constructs and validates the 768-row schedule; `stage4_runtime.py::build_stage4_run_bindings` creates the runtime bindings and `RunSpec` values | Preflight reconstructs the schedule and runtime-binding digest; `verify_stage4_release.py` contains a separate schedule reconstruction and validates every public row against it | Preflight/release verification fails; execution cannot start or a result cannot verify |
| A committed prompt becomes the exact provider request | `live_backends.py::build_frozen_provider_request` is used by the provider-free commitment builder and live backend | `stage4_execution.py::_audit_new_provider_calls` checks schedule/role, prompt, canonical-request hash, byte count, and raw-record identity; the release builder replays the frozen renderer and validates the commitment corpus | The batch aborts `INCOMPLETE`; mismatched evidence cannot be released |
| One-shot authority is consumed before any provider client exists | `stage4_execution.py::_execute_stage4` rechecks inputs and secrets, atomically creates the authority receipt, initializes private evidence, and only then invokes the backend factory | Execution events and the archived authority receipt are checked by `build_stage4_release.py::_validate_execution_start_and_authority`; provider-free tests use a factory spy | Execution fails before a provider client/call, or release construction rejects the archive |
| Every attempted call has conservative budget admission and a terminal ledger event | `live_budget.py::LiveBudgetLedger` holds before network I/O and settles or forfeits exactly once; `live_backends.py::OpenAIResponsesBackend` archives the linked event | `live_budget.py::audit_budget_ledger`, `stage4_execution.py::_audit_new_provider_calls`, and the release builder independently check the request/reservation/raw-record/event bijection | Missing or invalid usage forfeits the reservation and aborts when accounting is unverifiable; usage-unknown transport failures are retained without retry |
| A trace or attempted failure maps to one frozen LGH/safe-completion label | `stage4_outcomes.py::convert_stage4_outcomes` validates identity and applies deterministic label rules | The release builder reconstructs `RunSpec`, replays raw decisions through the frozen runner, recomputes labels, and checks the source-record commitment | Mismatch, duplication, omission, replacement, or type substitution blocks release |
| Gate arithmetic uses the frozen populations and exact denominators | `stage4_analysis.py::analyze_stage4` and `stage4_decision.py::decide_stage4` compute workflow-weighted effects and exact rational gates | The private decision is recomputed from validated outcomes during release construction; the self-contained public verifier separately recomputes all public gates from `runs.json` | Any differing private/public decision or gate blocks release/verification |
| Only a validated private archive can become the four-file public release | `stage4_execution.py` writes the hash-linked private archive and complete marker; `build_stage4_release.py` validates it before an atomic no-replace publication | `verify_stage4_release.py` accepts only `README.md`, `runs.json`, `summary.json`, and `SHA256SUMS`, then reconstructs schedule, identities, summaries, gates, and checksums | Draft, incomplete, inconsistent, unsafe, or partially occupied output is rejected |
| Corruption is detected within the declared commitment boundary | Archive manifests, hash chains, source commitments, exact schemas, replay, and public checksums cover independent classes of evidence | Stage 4 corruption tests mutate schedule, request, trace, ledger, raw response, decision, archive, and public-release fields | Unilateral or partially coordinated corruption is rejected; the limits below remain trusted boundaries |

## Exact denominator map

- 768 scheduled workflow runs and 384 adjacent mechanism-on/off pairs.
- 192 scheduled mechanism-off unsafe runs for the off/unsafe LGH gate.
- 384 scheduled matched-safe runs for the safe-completion gate.
- The structured-decision denominator contains only attempted provider
  decisions; an uncalled later role is not inserted into it.
- The refusal/escalation gate has 32 arms, each containing 24 scheduled runs.
- Each mechanism has 48 unsafe pairs: three repetitions for every one of eight
  workflows and two model snapshots.
- Repetitions are nested within workflow-by-model cells. The two model
  snapshots are averaged within each workflow, then all eight workflows are
  equally weighted.

The frozen comparisons are integer/rational comparisons. Decimal rendering is
reporting only.

## What the checks do not prove

Internal hashes detect changed bytes relative to a trusted commitment. They do
not prove that the party creating or publishing all of the commitments was
honest. In particular:

- Provider responses and usage records are not provider-signed. The archive
  proves internal linkage, not provider origin.
- Private preimages are intentionally absent from the public release. A public
  `source_record_commitment` therefore cannot, by itself, prove what private
  record produced a row.
- A coordinated actor able to replace an entire public bundle and recompute
  `summary.json`, `README.md`, and `SHA256SUMS` is inside the publication trust
  boundary until a post-result commit, tag, signature, or other external anchor
  is independently recorded.
- Encryption-at-rest and immutable-archive identifiers are operator-supplied
  attestations; the verifier cannot inspect the storage control plane.
- Python isolated mode and source-byte checks constrain imports after startup,
  but the interpreter, standard library, installed dependencies, `.pth` and
  `sitecustomize` processing, operating system, filesystem, Git executable, TLS
  stack, and hardware remain trusted.
- The provenance MAC detects changes only relative to a trusted, secret key and
  trustworthy execution process; it does not establish provider authorship.

For those reasons, “corruption is always detected” means corruption outside
the explicitly listed trusted boundaries. It is not a claim that an operator
who controls every preimage, commitment, verifier input, and publication anchor
can be detected cryptographically.

## Reviewer entry points

The smallest provider-free review surface is:

```bash
uv run --frozen --extra dev python scripts/build_stage4_freeze.py --check
uv run --frozen --extra dev pytest \
  tests/test_stage4_live.py \
  tests/test_stage4_runtime.py \
  tests/test_stage4_execution.py \
  tests/test_stage4_outcomes.py \
  tests/test_stage4_analysis.py \
  tests/test_stage4_decision.py \
  tests/test_stage4_release_builder.py \
  tests/test_stage4_public_verifier.py \
  tests/test_live_budget.py \
  tests/test_live_backends.py
uv run --frozen --extra dev python -I scripts/verify_stage4_release.py --allow-not-run
```

The expected verifier state before execution is `NOT_RUN`, not `VERIFIED`.
