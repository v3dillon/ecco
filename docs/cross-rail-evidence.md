# Cross-rail evidence profiles

These profiles extend the existing `body.economic` records inside signed v0 envelopes. Topics/threads remain coordination contexts. An economic interaction references one opening and may span contexts; neither a payment rail nor a raw execution trace replaces it. Transport delegation, assertion grants, economic authority and custody permission remain separate checks.

## Provider status and disputed outcomes

A Stripe observer can issue `external_attestation` with `payload.claim: stripe_dispute_status`, a string `status`, integer `observedAt` and `source: {provider:"stripe",account,environment,objectId,observer,method}`. `observer` identifies the envelope profile root using `ecco:root:ed25519:…`. A status is the observer's claim about provider API state, not a Stripe public-key signature. It requires explicit relying-party claim admission and, for delegated signing, an appropriate existing assertion grant. `test` observations never become admitted live economic history.

The semantic projection exposes `providerDisputeOpen` for each interaction. For an admitted live observer/account/dispute, the latest observation time determines its current observed states; legacy observations without `observedAt` use the relay receipt time. Future/invalid observation timestamps do not close a dispute. Same-time conflicting statuses are retained, and differing issuers do not overwrite each other. Only `won` or `warning_closed` close a source's observed dispute. Newest publication time cannot erase a newer observation by publishing older data later. A relying-party outcome policy must not classify a known open dispute as unconditional successful fulfillment.

A successful refund and a lost dispute remain the existing `refund` and `chargeback` records. Pending/failed/canceled refunds can be external claims named `stripe_refund_status`. Each observation keeps its original provenance (`webhook_hmac_plus_api_reconciliation` or `authenticated_api_reconciliation`) and private-provider-evidence digest. Multiple observations of one provider payment do not create multiple economic interactions. Missing evidence never proves no refund or dispute exists.

The public Rust and private Ops TypeScript semantic verifiers consume shared cases covering admitted open/closed states, delayed older observations, contradictory same-time states and unadmitted status. Economic conclusions still depend on retained context, independent source admission and explicit outcome policy.

## Exact native-asset terms

An `interaction_started` payload can add:

```json
{"nativePayment":{"network":"eip155:8453","asset":"0x1111111111111111111111111111111111111111","payer":"0x2222222222222222222222222222222222222222","payee":"0x3333333333333333333333333333333333333333","value":"1000000"}}
```

These are illustrative addresses, not a recommended or admitted contract. The profile requires an EVM chain ID, exact token/payer/payee addresses and a positive decimal atomic-unit amount bounded to uint256. Native amounts and the existing ISO accounting `amount` are distinct. An accounting budget or valuation does not attest fiat settlement or asset redemption value.

The existing x402 external observation claim `configured_rpc_operators_report_exact_eip3009_transfer` can support a native outcome only with independently admitted observer authority, exact interaction/terms/seller attribution, agreed native units and unique chain/token/transaction/log identity. Duplicates do not add volume; contradictory attribution must not qualify. Delivery, buyer acknowledgment/rejection, maturity, disputes and operating/controller continuity are independently evaluated. No payment receipt automatically proves fulfillment, no global reputation score is canonical, and a paid cycle is a review signal rather than a fraud verdict. Native refunds/reversals need their own evidence; missing coverage remains explicit.

A finalized native cancellation may be recorded as `configured_rpc_operators_report_exact_eip3009_cancellation`, with original action/authority references and `cancellation: {network,asset,authorizer,nonce,logIndex}`. It asserts configured-RPC agreement about the exact pinned contract's native cancellation event. It is not a token transfer or fulfillment event. Only the organization's enforcing wallet/budget process decides whether its exact reserved exposure can be released. A timeout or expired Ecco approval is not a cancellation proof.

## Private execution and economic dossiers

Safe operational facts, human decisions, A2A task receipts, authority references, delivery records and disputes may link to an interaction through the existing event/links fields. A dossier indexes original IDs, topics, attributable actors, chronology, assertion-grant references and external claim admission from evidence the recipient is permitted to see. It must preserve missing references and conflicting assertions; it must not fetch private traces to fill gaps automatically.

Raw execution traces, private reasoning, provider response bytes and native spending signatures need not be disclosed. Only explicitly selected evidence enters the economic record. The organization's relay can retain private context, the counterparty can retain independently signed selected evidence, and an index can derive context-specific dimensions. The index need not become an omniscient source of truth.
