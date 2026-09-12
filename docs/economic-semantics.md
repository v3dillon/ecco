# Portable economic semantics

The public `economic_history::project` verifier and `ecco verify-history BUNDLES --pins PINS` implement `ecco.semantic-evidence/v1`. The verifier operates offline on original `ecco.evidence/v1` bundles. It requires a separately supplied origin policy:

```json
[{"address":"seller@relay.example","root":"ed25519:…","relay":"ed25519:…","claims":["payment_settled"],"suppressed":false}]
```

The example keys are placeholders. Obtain actual root and relay bindings independently. A policy file packaged by an unknown source is not an independent trust anchor. Claim admission and issuer suspension are relying-party decisions. Signatures authenticate statements; they do not establish truth, independence, legal ownership or capacity.

The output contains controller histories and owner epochs, historically attributable actors, suppressed assertions, operating histories, agreement signers, linked deliveries and buyer acknowledgments/rejections, admitted namespaced payment keys, and separately preserved dispute openings and arbitral outcomes. It deliberately contains no risk score, maturity calculation, spending permission, verified identity age or universal resolution of disagreement. Delivery dates remain contract claims in this public attribution projection; an outcome evaluator must additionally validate dates and its maturity horizon.

Controller rotation requires the old controller and the new controller's endorsement of the same `ecco.controller-transition/v1` statement. Recovery requires the quorum committed at inception and the new controller signature. Ownership transfer advances an owner epoch so acquired history cannot silently establish a new owner's performance. Two eligible successors leave continuity contested. Historical action attribution requires its explicit controller head and an accepted relay observation within that controller epoch. A receipt is the named relay's clock assertion, not an independent timestamp authority.

Assertion-grant revocations apply to matching root/grant assertions observed at or after the revocation. Missing evidence is not proof that no revocation or contradiction exists. Disclose the required continuity and authority context with selected proofs. A custodian assessing retained evidence must check its full known authority context even when a recipient receives a subset. Unknown, expired, removed or disputed issuer admission must be handled by the relying party's current policy.

## Operating versions

`operating_version_changed` is additive inside the existing signed `body.economic` object, with the existing envelope kind (normally `finding`). It is controller-only. It never authorizes spending.

```json
{"schema":"ecco.economic-event/v1","type":"operating_version_changed","links":[],"payload":{"previous":null,"versionDigest":"sha256:…"}}
```

Commit to the configuration whose performance is being claimed. Optional `modelDigest`, `toolsDigest` and `policyDigest` disclose component commitments without requiring private prompts or reasoning. A subsequent record references the prior envelope ID in `payload.previous` and advances observed time. Incomplete histories and forks remain explicitly incomplete/contested. Configuration claims do not prove remote attestation of the running software.

An interaction can include `sellerOperatingHead` in its signed opening terms. Current-version comparability requires that head and evidence it existed by the interaction's observation. A version change preserves history while limiting which historical interactions support the current configuration. Controller/owner continuity and operating continuity are distinct.

## Conformance

[`test-vectors/economic-semantics-v1.json`](../test-vectors/economic-semantics-v1.json) contains synthetic signed cases for rotation, recovery, ownership transfer, stale controllers, controller forks, operating successors/forks/missing predecessors, payment admission/suspension, fulfillment disagreement, contradictory arbitration, and historical grant revocation. The Rust test and the independently implemented TypeScript verifier in ecco-ops consume identical vectors. Both reject mutated evidence and missing independent pins. This is a versioned attribution contract, not a claim that every business projection or private risk model is identical.

Run `cargo test --test economic_semantics`. For interoperability, implement the contract and run the public vectors; do not infer semantics from dashboard scores.


## Cross-rail additions

The [cross-rail evidence profiles](cross-rail-evidence.md) define independently admitted Stripe dispute status, exact native-asset terms and selectively disclosed coordination dossiers. `providerDisputeOpen` is additive in the semantic interaction projection. Shared vectors cover delayed and contradictory status observations; this field is an evidence projection, not a globally final dispute ruling.
