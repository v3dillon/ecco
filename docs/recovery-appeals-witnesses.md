# Recovery, contractual appeals and checkpoint witnesses

These optional profiles extend existing `ecco.economic-event/v1` envelopes and scoped checkpoints. Original bytes, signatures and admitted source/custody policy remain authoritative. Cryptographic verification does not establish legal truth, user presence, independent organizations or accurate clocks.

## Recovery

An inception recovery policy `{threshold,keys}` may include integer `delaySeconds` and `contestSeconds` (each 0–2,592,000). Their sum is the notice waiting/contest window. Windowless legacy recovery is unchanged.

The proposed new controller signs an `external_attestation` payload `{claim:"ecco.recovery-notice/v1",entity,previous,controller,owner}`. `identity_recovered` links this notice and includes `payload.notice`. The existing `ecco.controller-transition/v1` endorsement statement also includes `notice`; both new-controller and guardian signatures bind that exact ID. Recovery cannot advance before the admitted notice receipt plus the window.

A precommitted guardian or the old controller can sign `{claim:"ecco.recovery-contest/v1",entity,notice}` and link the notice within that period. That attempt cannot advance the controller; an entirely new notice and endorsements are required for a new attempt. The verifier does not deliver notifications or arbitrate contests. Custodian receipt times are not independent trusted timestamps.

Ops also interprets attributable `ecco.identity-compromise/v1` reports with entity/head, reported interval and reason digest as review evidence. They never remove original identity history or conclusively classify all signatures in the interval as forged. This report-to-risk projection is product policy, not a public-core verdict.

## One contractual appeal round

Opening terms optionally include `arbiter` and `disputePolicy:{procedureDigest,appealArbiter,appealWindowSeconds}` (1–2,592,000 seconds). Counterparty `offer_accepted` must explicitly bind `disputePolicyDigest`, computed with the existing canonical digest, in addition to `termsDigest`.

Procedural events bind the same interaction, dispute ID, terms digest and procedure digest. Initial resolutions are signed by the initial arbiter and link a retained party opening. A party's appeal uses `dispute_opened`, `payload.appeals` and a link to the original ruling within the window. The named appeal arbiter resolves using `previousResolution`, `appeal` and links to the original ruling and every retained timely appeal opening. A ruling leaving another timely appeal unaddressed cannot drive an effective outcome.

Public semantic output preserves `resolutionHistory`, `appeals`, `finalAfter` and `contested` alongside effective `outcomes`. A pending appeal or competing valid final heads has no effective outcome. The product waits through the appeal window before outcome maturity. Legacy non-procedural conflicting rulings retain their original semantics. No workflow annotation silently supersedes an economic ruling.

## Checkpoint witness receipts

`checkpoint::verify_witness(checkpoint,receipt,policy,now)` verifies `ecco.checkpoint-witness/v1`. Its signature covers every field except `sig`: `source,witness,scope,audience,checkpoint,receivedAt,schema`. `checkpoint` is the canonical digest of the complete original signed checkpoint. Policy independently pins `source,witness,scope,audience`; source and witness keys must differ. The receipt time cannot precede the source declaration or exceed the supplied verification cutoff.

The signature key is the pinned witness. Unknown original fields remain covered by the signature/digest. Verification authenticates a witness's clock/custody claim; it does not establish global ordering, inclusion in a transparency service, accurate identity age or completeness. Operators must retain independently signed originals and conflicting checkpoints. Ops supplies a bounded witness journal and export/recovery tools; admission and availability/retention agreements remain external.

## Conformance

`test-vectors/economic-semantics-v1.json` includes notice delay/contest and contractual appeal scenarios. `test-vectors/witnesses-v1.json` is the shared seven-case receipt corpus. The Rust implementation and Ops TypeScript implementation verify originals independently. These synthetic keys and examples establish no actual issuer or witness authority.
