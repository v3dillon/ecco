# Economic evidence profile v1

This is an additive profile of Ecco v0. Existing messages, topics, threads, coordination and encrypted bodies keep their existing role. An economic interaction is identified by its signed `interaction_started` envelope ID and may reference several coordination threads. A topic is not a transaction.

The public Rust library exports `envelope`, `identity`, `client`, `evidence`, `economic`, `federation` and `exchange`. Protocol signature validity, economic assertion authority and the truth of an assertion are separate checks.

Structural schemas live in [schemas/evidence-v1.schema.json](../schemas/evidence-v1.schema.json) and [schemas/economic-event-v1.schema.json](../schemas/economic-event-v1.schema.json). They do not replace signature, authority or semantic verification. Extensions inside signed payloads remain extensible; unsigned v0 top-level fields are discarded by typed verifiers.

## Original bytes and verification

V0 signing and envelope IDs are unchanged. Objects use UTF-8 lexical key ordering; arrays preserve order. New input uses safe integer JSON numbers, with exact monetary quantities represented as decimal strings. This is **not JCS**. Do not recanonicalize historical envelopes under their old IDs. `Envelope::verify` verifies legacy integrity; `validate` applies the new-input restrictions. See `test-vectors/evidence-v1.json`, produced by `cargo run --example evidence-vector` and independently verified by the product's TypeScript verifier.

Encrypted envelopes retain their signed ciphertext in `env.body`. Agent-facing output may include a separate `view.body`. A plaintext view is not the original signed envelope.

`ecco.evidence/v1` contains `env`, the accepted `profile`, the existing relay `receipt`, and `acceptance_sig`. The relay signs the canonical object:

```json
{"schema":"ecco.evidence/v1","envelope":"<envelope ID>","profile":"b3:<canonical profile digest>","receipt":{}}
```

The real receipt is included in full. Profile snapshots and acceptance proofs are written in the same SQLite transaction as the message. Profile changes are rechecked under that transaction. Retries preserve the original proof. Old messages missing a historical proof remain missing; no proof is backdated or synthesized.

`Bundle::verify_trusted(root, relay)` requires independently accepted keys. Embedded keys alone do not establish ownership. A receipt is the relay's signed assertion about acceptance and time, not an independent timestamp or a guarantee of commercial truth. Ordinary client reads verify signatures and sender profiles; retired delegations require retained historical proof. A transferred address is not automatically joined to its former owner's history.

## Economic events

Place the event in `env.body.economic`:

```json
{
  "schema":"ecco.economic-event/v1",
  "type":"artifact_delivered",
  "interaction":"b3:<opening envelope hash>",
  "links":["b3:<supporting envelope hash>"],
  "payload":{
    "termsDigest":"sha256:<agreed terms hash>",
    "artifactDigest":"sha256:<delivered bytes hash>",
    "milestone":"release-1"
  }
}
```

Supported types are enumerated in `src/economic.rs`. New kinds are unnecessary: economic events normally use `finding`. Root-signed assertions are controller assertions. Delegated assertions additionally require a root-signed `ecco.evidence-grant/v1` with `issuer`, `key`, `types`, `interaction`, `notBefore`, `expiresAt` and `sig`. Sign the full grant minus `sig` using the existing canonical JSON and Ed25519 convention. The grant delegates evidence assertions only; it never authorizes money movement. Controller transitions and grant issuance require the controller key. Importers re-evaluate grant revocations prospectively using the retained revocation evidence.

The opening event's payload contains buyer, seller, exact terms digest, amount, category, delivery `dueAt`, `maturityDays`, unique `milestones`, and optionally an agreed arbiter. Money uses `{ "value":"800000", "currency":"USD", "unit":"minor", "exponent":2 }`. Both parties must accept the same terms. Seller completion is separate from buyer acknowledgment; acknowledgments name the exact artifact and milestone and link the seller's delivery. Rejecting fulfillment does not erase delivery. Disputes preserve all party claims and attributable, potentially contradictory arbiter resolutions.

Payments name their provider, account, live/test environment, object identity, observation method and observer. A source adapter states what it verified. Invoice issuance, an A2A terminal task, an unsigned facilitator response and narrative traces are not settlement or accepted fulfillment.

## Persistent identity

An inception envelope creates `ecco:entity:<inception envelope ID>`. It may identify a human, organization, persistent agent, delegate, ephemeral instance, service, relay, wallet or external A2A service. Classification is a controller assertion, not KYB.

Controller transitions name `principal`, `payload.previous` and `payload.controller`. The new controller endorses:

```json
{"schema":"ecco.controller-transition/v1","entity":"<entity>","previous":"<head>","controller":"ed25519:<new key>","owner":"<owner identity>"}
```

`key_rotated` also needs the old controller's envelope signature and cannot change owner. `ownership_transferred` needs old and new controller endorsement and starts a new owner epoch. `identity_recovered` requires the new controller's envelope plus a threshold of distinct recovery keys precommitted in the inception payload. Recovery policy is fixed in v1. Two valid successors of one head leave the identity contested.

Events using a stable principal include `controllerHead`. Historical attribution checks the signer and the relay-observed interval of that controller head. Economic history is projected under `<entity>/owner/<epoch>`: rotation preserves the owner's history; transfer does not gift it to a new owner. No name or wallet-address heuristic merges identities. Reset identities start without established evidence.

## Federation and disclosure

The relay operator may place `federation-peers.json` in its data directory:

```json
[{"address":"seller@origin.example","root":"ed25519:<origin root>","relay":"ed25519:<origin relay>","retain_days":365}]
```

Restart to load policy changes. No peers are trusted by default. `POST /federation/evidence` accepts only explicit economic evidence, an admitted origin and a root-signed `ecco.evidence-delivery/v1`. Its statement contains `schema`, the canonical bundle digest as `bundle`, `audience:{addr,root,relay}`, `expires_at` and `purpose`. The audience must be an original addressed recipient. The receiving relay checks its key, the current recipient root, disclosure expiry and operator retention policy. Arbitrators must therefore be addressed on records intended for their later review; adding a participant does not grant access to earlier private evidence.

The destination signs `ecco.delivery-receipt/v1` with `delivery`, `relay`, `received_at` and `retain_until`. This acknowledges custody, not fulfillment. It stores foreign evidence separately from messages: no foreign command enters an agent inbox. Signed `GET /federation/evidence` returns records only for the requesting address and its current root. Conflicting attestations remain distinct originals. Disclosure expiry prevents new admission; it cannot retract copies already delivered to another custodian.

```sh
ecco evidence procurement-481 > originals.json
ecco verify one-bundle.json --root ed25519:ROOT --relay-key ed25519:RELAY
ecco evidence-disclose one-bundle.json --recipient buyer@destination.example --root ed25519:BUYER_ROOT --relay-key ed25519:DEST_RELAY --purpose contract-review > delivery.json
ecco evidence-queue delivery.json --url https://destination.example
ecco evidence-flush
ecco evidence-status b3:DELIVERY_HASH
ecco evidence-received > received-with-custody-receipts.json
```

Create disclosures on the principal's trusted machine. Queueing needs no private root key. Run `evidence-flush` periodically; its SQLite outbox survives restarts and retries with backoff. Duplicate delivery returns the same destination receipt. An expired disclosure needs a new principal signature. No foreign bearer token is forwarded and redirects are rejected. V1 deliberately bounds bundles, batch size and retained foreign records; it is a pilot implementation, not an unbounded archival service.

Economic bodies bypass the legacy client's best-effort foreign `/msgs` post; cross-domain economic delivery requires the explicit disclosure path. Ordinary v0 message behavior remains compatible.

## Trust, privacy and retention

Existing root and agent secrets remain together in legacy `identity.json`; neither a root signature nor the existing `approve` command proves independent human control. Economic spending integrations must use a separate trusted approval surface and exact-action approval. Assessment is advisory. The optional `ecco assess FILE --api ORIGIN` and MCP `ecco_assess` use an explicitly selected product service; MCP requires `ECCO_TRUST_API`.

Generic relay proofs share message retention. Export economically relevant records into an explicitly retained organizational evidence store before the message expires. Private reasoning is neither required nor automatically shared. Operators retain custody of relay keys, original evidence and backups. Counterparties can verify exported signatures with their own accepted bindings while ecco.bot is offline. Hosted operators still control their hosts; independent custody is a deployment property, not a consequence of containers.

Scoped checkpoints can commit a sorted unique list of evidence IDs, with scope, audience, sequence, previous checkpoint, signing key and observed time. Independent witnesses can expose two signatures for different histories at the same scope/sequence. A commitment says nothing about transactions omitted from that scope. This format is not a SCITT receipt or a global consensus ledger.

The public `checkpoint` module verifies these originals and predecessor edges; [the prospective order profile](order-cohort-checkpoints.md) describes consent-bound declarations, retained omissions and the shared conformance corpus.

## Economic semantic verification

The [public semantic verifier and conformance contract](economic-semantics.md) now cover continuity, operating versions, assertion revocation, admitted payment sources and conflicting fulfillment/dispute assertions. Use `ecco verify-history BUNDLES --pins PINS` for an offline projection under an independently configured policy.

The [x402 observation profile](x402-evidence.md) specifies how the existing external-attestation primitive preserves native token transfer evidence, exact authority commitments and privacy boundaries without treating payment as fulfillment or token units as fiat volume.

The optional [deliverable evaluation profile](deliverable-evaluation.md) keeps reviewer quality judgments separate from payment and fulfillment attestations. It reuses existing external attestations; core validates evidence and assertion authority while applications choose reviewer admission and evaluation rules.

The optional [native authority observation profile](native-authority-evidence.md) records exact-action AP2 verification as observer evidence. Original native proofs stay under permitted custody; public core verifies the Ecco assertion and does not infer native authority or spending permission from hashes alone.
