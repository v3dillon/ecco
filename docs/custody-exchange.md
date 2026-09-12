# Organization custody exchange

This optional application profile coordinates selected evidence between independent organization installations. It does not replace core relay disclosure (`federated-evidence-v1`), confer spending authority or change the original `ecco.evidence/v1` bundles. Custodian statements about permission and admission policy remain distinct from the agent's assertion and the relay's acceptance signature.

Two operators independently establish a channel reference, their respective Ed25519 custody public keys and HTTPS origins. Each installation maps that channel to exactly one local organization; local account IDs are never interpreted as remote tenant IDs. The private application provides the initial implementation. A custody key is an online service key authorized to speak for this channel, not an economic identity's controller or recovery key.

`POST /api/economic/federation/exchange` accepts this signed JSON object:

```json
{
  "schema": "ecco.custody-exchange/v1",
  "channel": "bilateral-channel-reference",
  "sender": "ed25519:PUBLIC_HEX",
  "audience": "ed25519:PEER_PUBLIC_HEX",
  "nonce": "RANDOM_UUID",
  "issuedAt": 1789150000,
  "replyTo": null,
  "body": {"action": "grants", "requestId": "LOCAL_REQUEST_REFERENCE"},
  "sig": "ed25519:SIGNATURE_HEX"
}
```

Sign the entire object except `sig` using existing v0 canonical JSON and Ed25519. Reject unsafe JSON numbers. Replies reverse sender/audience, preserve channel and nonce and set `replyTo` to the BLAKE3 digest of the complete signed request. Both messages allow at most 60 seconds of clock skew. Request mutations are idempotent journal appends; repeating a signed request cannot create a new grant. HTTPS destinations are operator configuration, never input URLs. Redirects are rejected. The implementation bounds request input to 256 KiB, reply input to 8 MiB and each grant to 64 selected original envelope IDs.

Actions:

- `request`: `{requestId,document:{subject,reason,consentRef,purposes}}`. Purposes are explicit members of `assessment`, `evaluation`, `export`. Receiver records an immutable incoming request and replies with its local request reference. This action grants nothing.
- `grants`: `{requestId}`. Returns this channel's unexpired, unrevoked administrator-issued grants for the request as `{grants:[{id,document}]}`. Grant document binds the channel/request, original `evidenceIds`, allowed `purposes`, `expiresAt` and consent reference. An administrator cannot grant more purposes than requested.
- `read`: `{grantId,purpose}`. Returns `{grantId,document,rows,policyDigest}` only while that channel's grant remains valid for the purpose. Each row contains the unmodified original `bundle`, custodian-reported `uploadedAt` and `retainUntil`, `suppressed` and admitted `issuerClaims`. The policy digest commits the selected original rows and their status under the provider's complete retained authority context, including known revocations. These are custodian statements, not global completeness or independent timestamps.

Consumers independently verify every original signature and their own origin/issuer policy. They intersect issuer claim scopes with the provider's scopes. Selected proofs must not conceal a known assertion revocation. Assessments retain source fingerprints and grant references; subsequent reads recheck current permission and both policies. An unavailable provider withdraws derived details until current access can be established. Revocation cannot erase copies already disclosed. Portable exports and training require their separate explicit purposes and organizational agreements.

## Selecting one original from a core relay

Core `GET /evidence?about=THREAD&id=ENVELOPE_ID` adds an optional original ID filter using the existing proof primary key. Both query values are URL-encoded and the exact request target is signed using core auth-v0. Thread participation and signed-read requirements apply before lookup. A missing original or one from a different thread produces `[]`. Omitting `id` retains the existing complete-thread export. This avoids repeatedly downloading a growing thread when a worker needs only its newly accepted proof.
