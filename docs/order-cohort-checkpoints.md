# Portable source declarations for prospective order cohorts

The existing `ecco.evidence-checkpoint/v1` statement now has a public Rust verifier in `src/checkpoint.rs`, sharing conformance vectors with Ecco Ops. It uses the existing v0 canonical JSON, BLAKE3 document digests and Ed25519 signatures from `src/federation.rs`. There is no new envelope kind, transport or consensus rule.

## Signed format

The original object contains `schema`, `scope`, `audience`, `sequence`, `previous`, `events`, `commitment`, `key`, `observedAt` and `sig`. Sign the entire original object minus `sig`, including any unknown extension fields. Hash the complete signed original when referring to a predecessor. Canonical JSON has UTF-8 key ordering and safe integer numbers; do not replace it with JCS or hash pretty-printed JSON.

- `scope` and `audience`: nonempty strings, at most 2048 UTF-16 code units each, matching the existing TypeScript verifier.
- `sequence` and `observedAt`: nonnegative safe JSON integers; observed time is integer Unix seconds asserted by the signer.
- `previous`: null for genesis, otherwise `b3:` followed by 64 lowercase hex characters, committing to the entire previous signed checkpoint.
- `events`: sorted, distinct `b3:` or `sha256:` IDs with 64 lowercase hex digits, at most 10,000 for the generic format.
- `commitment`: `digest({scope,audience,events})`.
- `key`: independently accepted source public key. `sig`: Ed25519 signature of the canonical statement.

```rust
ecco::checkpoint::verify_statement(&original, accepted_source_key)?;
ecco::checkpoint::verify(&original, accepted_source_key, previous.as_ref())?;
```

Statement verification does not assert continuity. Edge verification also verifies the supplied predecessor's original signature/manifest, identical key/scope/audience, sequence increment, predecessor digest and nondecreasing source time. Without a predecessor it accepts only genesis. A complete-chain consumer must retain and check every edge back to genesis. Neither source time nor successful verification establishes independent age, completeness, beneficial ownership or current authority.

## Prospective order profile used by Ops

For order declarations, `scope` is `ecco.prospective-orders/v1`, `audience` is an admitted standing-enrollment-consent record ID, and each event is `digest(originalSignedOrder)` using the existing `ecco.prospective-order/v1` signed object. A checkpoint commits to orders, not outcomes. The consent's independently accepted `sourceKey` verifies both orders and checkpoints. The permission carries counterparties, amount ceiling, validity, purposes and agreement reference; it is not spending authority or an organization credential.

Ops adds current consent/revocation and five-minute freshness checks, no future time, a 512-ID cumulative manifest bound and a 128-checkpoint pilot capacity. Those are application admission rules, not generic cryptographic rules. The public verifier does not consult Ops permissions or assert source-feed completeness.

Successors should retain all earlier IDs. Retractions and differing originals at the same key/scope/audience/sequence remain valid signed statements. Coverage consumers retain their union, flag retractions/equivocation, list unsupplied original orders and preserve uncertainty. They do not discard a fork or let a later manifest erase a known omission. A missing predecessor is incomplete history. Repeated identical originals are idempotent.

An original order absent from every source declaration remains unobservable. Independently retained originals and witnesses can expose signed disagreement; copying public originals is allowed and cannot itself establish a moat. Continuing permissioned contributions, chronology witnessed outside one operator, independent outcomes and measured decision value require adoption beyond this format.

`tests/checkpoints.rs` checks the same 28 integrity/continuity cases as the Ops TypeScript verifier using `test-vectors/checkpoints-v1.json`. Fixtures contain synthetic signatures only. They cover canonical extension fields, alternate digest prefixes, time bounds, missing/tampered predecessors, fork/retraction validity, wrong keys and changed manifests.
