# Native authority observation profile

This profile extends the existing `ecco.economic-event/v1` `external_attestation` body. It adds no envelope kind, identity standard, mandate format or payment rail. The public Rust verifier verifies the Ecco envelope, custody and admitted assertion provenance; original native authority is separately verified by a native adapter.

## Observer statement

An event with `payload.claim = "ecco.native-authority-observation/v1"` records that its Ecco signer checked a native proof for an exact action at an observation time. The body contains:

| Field | Meaning |
| --- | --- |
| `interaction`, `payload.termsDigest` | Existing economic interaction and exact terms digest |
| `payload.subject` | Observer-supplied subject; association with the native key requires separate evidence |
| `payload.profile`, `payload.verification` | Explicit supported native format and verifier result |
| `payload.observedBy`, `payload.asOf` | `event_signer` and integer Unix observation time |
| `payload.amount`, `payload.checkoutDigest` | Exact currency/minor units and original checkout commitment |
| `payload.nativeDigests` | SHA-256/base64url of the original payment presentation, checkout mandate presentation and merchant checkout JWT |
| `payload.policyDigest`, `payload.policyEncoding` | SHA-256/base64url of the verifier policy's exact UTF-8 `JSON.stringify` bytes; encoding `sha256-base64url-utf8-json/v1` |
| `payload.remainingBudget`, `payload.executionPermit` | `unknown` and `null`; observation is not spending enforcement |
| `payload.assurance` | `observer_verified_native_proof_at_as_of_subject_association_requires_separate_evidence` |

The full event is signed through existing envelopes. Native original signatures are retained by the permitted custodian; they are not replaced with Ecco signatures. A hash alone cannot establish native authority, identity ownership, current revocation state, nonce consumption, settlement or fulfillment. Assessment does not upgrade this observation to an execution grant.

Use existing disclosure/custody grants to request original tokens and exact policy bytes. A verifier checks their digests and native signatures against its own admitted issuer, agent and merchant keys and current action/status policy. A disclosed issuer key is not automatically trusted because a proof mentions it. Exporting a statement does not extend permission to the underlying private evidence or policy.

## Implemented native profiles

Private Ops supplies `AP2-0.2/direct-es256` and `AP2-0.2/delegated-es256-plus` adapters through the existing economic SDK/CLI. The latter supports a trusted-provider root and up to four ES256 delegation steps. It verifies each confirmation key and predecessor hash, inherited validity, fixed claims, all supported ancestor constraints, exact checkout/action binding and fresh final-agent audience/nonce. Hidden or unknown constraints fail explicitly.

Supported stateless AP2 constraints cover allowed payees, payment instruments and PISPs, integer amount ranges, open-checkout references, execution dates, allowed merchants and flat UCP whole-item quantities. Stateful budgets and recurring consumption are rejected because they require an authoritative consumption provider. Original native action receipts bind the final SD-JWT component including its trailing `~`; receipt success remains distinct from mandate validity and settlement.

The plus-type profile intentionally follows the Formats section of the [Delegate SD-JWT draft](https://github.com/GarethCOliver/gco-delegate-sd-jwt/blob/main/draft-gco-oauth-delegate-sd-jwt.md), checked 2026-09-12. That draft's Verification section inconsistently uses hyphenated types. Separate final KB-JWT, JSON serialization, alternative type dialects and Verifiable Intent are outside this profile. The [AP2 open-payment schema](https://github.com/google-agentic-commerce/AP2/blob/main/code/sdk/schemas/ap2/open_payment_mandate.json) supplies integer minor units despite fractional examples elsewhere; [UCP line items](https://github.com/Universal-Commerce-Protocol/ucp/blob/main/source/schemas/shopping/types/line_item.json) supply `item.id` and whole quantities for the selected checkout profile. The broader [AP2 authorization contract](https://github.com/google-agentic-commerce/AP2/blob/main/docs/ap2/agent_authorization.md) must still be matched with the selected provider.

Rust does not contain a duplicate JOSE verifier in this increment. Its existing extensible event payload retains this observer claim, and its envelope/evidence verifier provides the same portability guarantees as other external observations. Native cryptographic verification requires the original evidence and the separately supported adapter.
