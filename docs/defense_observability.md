# Defense observability contract

> This table documents the implemented v0.1-scripted defense views and is a
> historical baseline for v0.2-live. Stage 2 must freeze its distinct live
> contract before defense replay; any change receives a new protocol hash.
> Scripted predictions below remain unit-oracle expectations, not live defense
> evidence.

V0.2 intent decomposition is deliberately leak-free: its shareable history does
not contain the withheld authorization evidence. Therefore v0.2 makes **no**
prediction that `HISTORY_MONITOR` blocks intent-decomposition LGH. The archived
history-blocks-intent signature below applies only to the v0.1 scripted fixture.

This table records why a defense can or cannot establish a violation. A failure
caused by absent evidence is an information-limit failure, not a reasoning
failure. The same frozen defense implementation is used across workflows and
mechanisms.

| Defense | Exact pilot input | Important exclusions |
|---|---|---|
| Local only | Empty defense view; the role-local policy has already evaluated its own context | No cross-stage evidence |
| History monitor | Accumulated `shareable_public_evidence` dictionaries | No delegation prose, private facts, artifact bodies, or tool log |
| Source anchoring | Trusted runtime fields `restriction_present`, `evaluation_complete`, `restriction_active`, and `restriction_text` | No full objective, unrelated ground-truth facts, principal-registry/authority-chain enforcement, or externally authenticated principal credential |
| Provenance carrying | Physical-run-bound artifact ID plus hidden `origin_scenario`, `signed_claims`, HMAC-SHA256 `signature`, `signature_algorithm`, and `signature_key_id` metadata | No task text or full goal graph; the pilot key and metadata are simulator-managed |
| Policy intersection | Runtime-selected applicable policy IDs and the current gate-visible facts | No missing facts are reconstructed |
| Omniscient reference | All authoritative scenario facts | Upper bound only; excluded from candidate rankings |

For intent decomposition, the history view accumulates `workflow_kind`,
`asset_class`, `authorization_marker`, and `destination_kind`; the other mechanism
builders publish only `workflow_stage`. The source-anchor record marks evaluation
complete for authorization drift and policy heterogeneity, but not for intent
decomposition or context fragmentation. The provenance claim set contains the
scenario's declared `provenance_claim_keys`. Policy heterogeneity is the only
mechanism whose treated Actuator lists both source and downstream policy IDs.

Those exact inputs produce the scripted predictions: history blocks intent,
source anchoring blocks drift and heterogeneous-policy conflict, provenance
blocks all four unsafe fixtures, and policy intersection blocks heterogeneity.
They are unit-oracle predictions—not empirical discoveries or claims about every
implementation in a defense family.
