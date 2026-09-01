# Stage 1 private-archive commitment

This directory publishes a privacy-safe commitment to the private archive for
the one authorized `v0.2.1` Stage 1 run. It does not publish filenames,
per-file hashes or sizes, raw model text, prompts, provider identifiers, or
private correlation fields.

[`archive-commitment.json`](archive-commitment.json) commits to all 1,537
regular files and six descendant directories using a domain-separated SHA-256
Merkle tree over canonical relative paths, file sizes, and file-content hashes.
The commitment is anchored to the immutable pre-run `v0.2.1` tag and separate
`v0.2.1-stage1-results` tag in
[`preservation-record.json`](preservation-record.json).

An authorized holder can verify a private snapshot without disclosing its
contents:

```bash
python3 scripts/archive_commitment.py verify \
  /path/to/private/stage1-archive \
  preservation/stage1-v0.2.1/archive-commitment.json
```

At commitment time, the working archive and two owner-readable, non-writable
local copies independently reproduced the published root. All three snapshots
are on the same physical storage device, so the copies protect against
accidental mutation but are not independent disaster-recovery archives. At
least one should be transferred to a separately controlled encrypted offline
volume.

The Merkle root proves that a later-disclosed snapshot has the committed bytes
and relative layout. It does not independently prove provider origin, when the
records first existed, that no material was omitted before commitment, or the
semantic validity of the raw-record audit.

The public Stage 1 tables can be checked separately with:

```bash
python3 scripts/verify_stage1_release.py results/stage1-v0.2.1
```

That verifier recomputes six table-derived gates, all 32 arm summaries, and all
60 paired-effect rows. It labels the frozen hard-QA count and private raw-archive
completeness as attestations because those two claims are not independently
recomputable from the public tables alone.
