# Stage 4 execution status

**Status: provider-free implementation candidate; the draft is deliberately
unexecutable, and no Stage 4 provider call has been authorized or made.**

The prospective protocol is
[`v0.4-stage4-confirmatory`](../protocols/v0.4-stage4-confirmatory.md). Its
candidate manifest, complete 768-row schedule, and exact 3,072-potential-call
offline request commitment corpus live under [`manifests/`](../manifests/). The
candidate uses `freeze_status="draft_unexecutable"`, retains nonempty blockers,
has no authorized ceiling, and is not a preregistration tag or empirical result.

The provider-free implementation now includes:

- deterministic schedule-to-`RunSpec` binding and a read-only
  `run-stage4-confirmatory --preflight-only` command;
- strict schedule/manifest parsing, reconstruction, hash, Stage 3, provider,
  prompt, budget-boundary, repository, and unresolved-authority checks;
- exact conversion from bound traces or attempted provider/schema failures to
  one intention-to-treat outcome per scheduled run;
- workflow-weighted analysis in which repetitions are nested within
  workflow-by-model cells and crossed model snapshots are averaged within each
  workflow, plus frozen `GO`/`NO_GO` gates including the carried-forward
  refusal/escalation gate and the new workflow/domain breadth requirements;
- a dormant one-shot executor that creates authority before clients, retains
  every attempted failure without retries, independently revalidates the
  hash-chained trace/ledger/raw-record linkage, and archives private evidence
  before marking completion;
- an offline release builder that validates a complete private archive, its
  manifest, and matching frozen operator-supplied attestation identifiers, then
  atomically publishes only the four-file sanitized release; and
- an independent public-release verifier that returns `NOT_RUN` while no final
  frozen release exists.

The provider-free finalizer accepts only an explicitly authorized ceiling,
non-secret credential/provenance IDs and SHA-256 fingerprints, and bounded
storage-attestation IDs. It can alter only the enumerated finalization fields,
leaves `freeze_commit_sha=null` to avoid self-reference, and prints the exact
annotated-tag commitments. It never reads a key, creates authority, or executes
the study. Run it only from the clean implementation checkout with a trusted
interpreter in isolated mode: `python -I scripts/finalize_stage4_freeze.py ...`.
It rejects preloaded project modules and byte-checks its own script and every
loaded project module against the clean `HEAD` before applying the overlay.

Preflight performs no network activity. It does not read Stage 4 secret values,
construct a provider client, create a private output directory or spending
ledger, or consume one-shot authority. The CLI has an explicit, mutually
exclusive `--execute` latch for the eventual frozen run, but the checked-in
draft fails closed before it can read secrets, create state, construct a client,
or make a call.

The production latch requires a fresh dedicated virtual environment outside the
repository containing a non-editable wheel installation of the exact frozen
source. The checked-in `.venv` is editable and is deliberately rejected. From
the clean frozen repository root, the canonical finalized invocation is:

```bash
/absolute/path/outside/repository/stage4-clean/bin/python -I -B -m mas_safety run-stage4-confirmatory --execute
```

Execution requires Python isolated mode with bytecode-cache writes disabled
(`-I -B`), rejects startup/import override environment variables and any project
`__pycache__`/`.pyc`/`.pyo`, confines effective import paths to
interpreter-owned stdlib/purelib/platlib roots, and byte-matches loaded project
source files to the frozen repository before reading Stage 4 secrets. This
post-import check does not independently prove which bytecode Python executed
while entering `-m`; the cache-free wheel environment must be inspected and
provisioned before secrets are injected, then kept within the operator-trusted
boundary. The trusted dependency path remains constrained while constructing
the SDK client and making every provider call. `-I` still permits
interpreter-site `.pth` and `sitecustomize` processing before the executor can
run its checks. These requirements do not apply to the provider-free
`--preflight-only` command.

The release builder is also dormant: it rejects a draft freeze, an incomplete
execution, mismatched ledger/trace/raw commitments, a mutable or differently
attested archive, and an existing or partially occupied public destination. It
does not contact the provider and cannot publish over an existing release.
Its hash and replay checks can establish internal consistency of the archived
evidence. Private raw bytes are hash-committed and internally linked, but their
preimages are not public and those commitments do not establish provider
origin. Provider origin remains an operator/process trust boundary. The frozen
encryption-at-rest and archive-immutability identifiers are operator-supplied
attestations; the public verifier does not independently prove those properties.

The eight workflows and the outcome-blind construction record remain bound to
the immutable Stage 3 annotated tag. The constructor was an isolated Codex
process, not an external human. The sealed scenarios must not be edited; a fatal
validity defect requires disclosure and a separately versioned restart.

A focused, outcome-blind pre-freeze audit traced the eight execution and release
invariants listed in the
[`Stage 4 trusted computing base`](stage4_trusted_computing_base.md). It found
and repaired two fail-closed evidence-integrity defects before freeze: invalid
provider usage now preserves and archives the exact durable forfeiture event,
and release construction now recomputes and exactly compares the complete
private decision artifact rather than checking only its headline decision.
Regression tests cover both paths. The audit also records the deliberate limit
of internal commitments: an actor who coherently replaces an entire public
bundle and recomputes all of its checksums remains inside the publication trust
boundary until the released commit, tag, signature, or another post-result
anchor is independently recorded. The complete provider-free evidence record is
in the
[`pre-freeze audit`](../verification/stage4-confirmatory/pre_freeze_audit.md).

## Budget and authority blocker

Applying the exact Stage 1 conservative sizing rule offline to all 3,072 exact
potential schedule/role requests yields 11,804,904 canonical request bytes and an
all-execute bound of **USD 79.657830000** at the frozen standard-tier prices.
That is not enough gross authority under the frozen ledger: a transport failure
without trustworthy usage forfeits its full 65,536-input/512-output reservation,
the failed workflow is retained, and later rows continue. Summing each run's
most expensive successful prefix plus one forfeited reservation gives the exact
completion-safe ceiling of **USD 257.023620000** (GPT-5.4: USD 85.674540000;
GPT-5.5: USD 171.349080000). This is a worst-case ceiling, not predicted spend.
It is a local completion-safe call-admission and ledger-accounting authority
conditional on the frozen provider model, service tier, list-price, and
usage-reporting contract; it neither proves nor caps provider-side billing. A
returned model/tier contract mismatch aborts and locally forfeits the
requested-model reservation, but does not establish how the provider billed
that call.
The ledger makes the proof executable: a successful call may settle only when
provider-reported input tokens are no greater than that call's exact canonical
request UTF-8 bytes. Missing, malformed, or larger usage forfeits the reservation
and aborts `INCOMPLETE`.

The previous USD 20 authority is insufficient and is not reusable. No Stage 4
ceiling or call is currently authorized.

The proposed Stage 4-specific byte-sized pre-call reservation was not adopted.
Official OpenAI documentation states that input-token counts include structural
formatting tokens that may not appear in locally tokenized fields and provides
the `POST /responses/input_tokens` endpoint for an exact model-side count. It
does not state that billed input tokens are bounded by locally serialized
request bytes. Without that provider guarantee, the post-response byte check
cannot justify a smaller reservation for a transport failure that returns no
usage. The current USD 257.023620000 completion-safe authority requirement is
therefore unchanged; this is a reservation ceiling, not a spending forecast.

Final execution additionally requires a fresh Stage 4 credential and provenance
key, encrypted-at-rest private storage and immutable archive attestations, a new
Stage 4-only ledger, an atomic one-shot authority, a clean final freeze commit,
and an annotated tag committing the manifest, schedule, and Stage 3 seal hashes.
Account-specific access to both exact snapshots cannot be verified without a
provider call; no smoke calls are planned, so the first scheduled call for each
snapshot will be its access check and any attempted failure will be retained.

Nothing from Stage 1 or Stage 2—credential, budget, receipt, key, output path, or
row—can satisfy these boundaries. Any credential previously exposed in a
conversation or log is forbidden even if it still works.

## Outcome and abort boundary

Attempted provider/schema failures receive no retry or replacement, remain
invalid in the attempted structured-decision denominator, retain their typed
reason, and map to `LGH=0` and `safe_completion=0`. Usage-unavailable transport
failures forfeit the full reservation and later scheduled rows continue; a
response with missing, malformed, or out-of-bounds usage aborts as unverifiable.
Unattempted rows after an
authentication, budget, contract, storage, or process abort are not imputed.
Such a batch is `INCOMPLETE` and cannot produce a confirmatory GO/NO-GO; a
restart requires a new disclosed version and authority.

The historical Stage 2 policy-intersection evaluator is not used by Stage 4.
Before any later defense replay, a new pure evaluator must be prospectively
frozen over the typed Stage 4 observation objects. The finite-action experiment
also remains deferred.
