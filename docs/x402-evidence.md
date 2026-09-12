# x402 economic evidence profile

x402 is an external payment protocol. Ecco's existing v0 envelopes and `ecco.economic-event/v1` bodies can preserve attributable observations without introducing a payment rail or a new envelope kind. The core relay does not execute payments, hold wallet credentials, decide fulfillment, or interpret a facilitator response as a fact.

The current application profile supports v2 `exact` EVM EIP-3009 GET purchases. A separate organization-operated executor uses exact principal approvals and budget reservations, records the native authorization before signing, and preserves uncertain submission state. Wallet and provider policy are application trust boundaries. Neither relay transport delegation nor an economic assertion grant authorizes spending.

## Attributable observation

Use an `external_attestation` event with the original interaction envelope ID, normally in a signed `finding` envelope. Existing assertion authorization, archival profile, relay receipt, acceptance signature and disclosure controls apply unchanged. The event's payload identifies:

- `issuer`, `subject`, `interaction`, `provider` (CAIP-2 network) and `objectId` (transaction hash plus transfer log index).
- `claim: configured_rpc_operators_report_exact_eip3009_transfer` and `verification: configured_rpc_operator_agreement`.
- `transaction` and `transfer`, containing network, token contract, payer, payee, atomic amount, EIP-3009 nonce and log index.
- `nativeDigest`, committing the retained RPC observations; `nativeAuthorizationDigest`, committing the unsigned native EIP-712 authorization. The bearer payment signature remains private by default.
- `actionDigest`, `termsDigest`, `resourceDigest`, principal `approval`, `allocationDigest`, signed `executionPermit`, and reservation reference.
- Optional response status/byte count/content digest. These identify observed HTTP delivery, not contractual acceptance.
- Explicit `budgetCharge`, `budgetValuation` and limitations. A fiat budget accounting charge is not verified fiat settlement or a stablecoin redemption assertion.

The application observer requires distinct configured RPC operators to agree on successful finalized inclusion and the exact token/from/to/amount/nonce. For its admitted Circle-compatible EIP-3009 contracts, `AuthorizationUsed` must be immediately followed by its corresponding `Transfer`. Arbitrary tokens cannot be admitted on the strength of similarly named logs. Operators must independently establish contract semantics and RPC independence. This remains an observer statement, not a consensus proof.

## Verification and privacy

A counterparty can independently verify the original Ecco bundle and admitted assertion authority. Where disclosed, it can verify principal approval and execution-permit signatures against independent authority bindings, and recompute commitments from original action/authorization data. Independent on-chain reconciliation requires the underlying transaction and admitted contract semantics. Selected digests alone do not disclose those private inputs or establish their truth.

Raw RPC observations, native payment authorizations, full allocations and purchased bytes remain in organizational custody. Exporting or federating the selected event does not disclose that journal. Existing evidence grants determine permitted further use; a payment observation creates no new sharing permission.

Do not emit or infer fiat `payment_settled`, buyer `fulfillment_acknowledged`, verified corporate ownership, complete economic history or objective reputation from this profile. The current [economic semantic projection](economic-semantics.md) consequently does not count these external token observations as verified fiat volume. Artifact delivery, acceptance/rejection and disputes remain separately attributable evidence. Native-asset comparisons require an explicit future semantic profile; they cannot be created by relabeling a token as an ISO currency.

Native payment retries, expiration, cancellation and custody recovery are the executor's responsibility. EIP-3009 authorization may remain spendable until its native expiration after an Ecco approval revocation. Signatures and relay receipts do not remove that distinction.

The reviewed [Foundation v2 specification](https://github.com/x402-foundation/x402/blob/04c750e32e2c4dce658289a901710fd721e5d1a9/specs/x402-specification-v2.md) and [exact EVM profile](https://github.com/x402-foundation/x402/blob/04c750e32e2c4dce658289a901710fd721e5d1a9/specs/schemes/exact/scheme_exact_evm.md) are external specifications, not Ecco-specific payment formats. Existing messages, topics, threads and evidence exports remain compatible.

## Native offer and receipt assertions

The optional [Foundation offer/receipt extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/extension-offer-and-receipt.md) is preserved as an external native artifact, using its own EIP-712 or JWS verification rules. Never re-sign an interpreted native artifact under an original signature. An Ecco observer event may carry `nativeOffer` and `nativeReceipt` originals on explicit disclosure, or commitments and verification status only.

An independently admitted server signer, admission interval and exact resource/payment terms are necessary beyond signature validity. The application profile pins EIP-712 addresses or public Ed25519/P-256 JWS keys; it does not fetch keys from a supplied DID or header. One signed offer must match resource URL, scheme, network, asset, payee and atomic amount. Its unsigned selection index cannot establish those terms. Original execution policy must accompany historical reconciliation.

Native receipts bind resource, network, payer and issuer time, with an optional transaction reference. They omit amount, asset, payee and artifact identity. Preserve `fullTermsBound: false`, distinguish a transaction-linked receipt from a privacy-minimal receipt, and label it a server assertion. Neither receipt verifies buyer acceptance or deliverable quality. Missing or invalid native receipt evidence does not cancel a separately established token transfer.

A disclosed original lets a counterparty verify native signatures with its own issuer admission policy. A selected digest alone does not. Keep native spend authorizations, private RPC responses and purchased bytes in organizational custody. This application profile adds no relay endpoint, envelope kind or mutable reputation state.
