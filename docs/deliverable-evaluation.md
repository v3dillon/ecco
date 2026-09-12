# Attributable deliverable evaluation

This optional application profile uses existing `ecco.economic-event/v1` external attestations, v0 envelopes, assertion grants and archival evidence bundles. Core verifies the envelope and assertion authority; it does not decide quality or prescribe a universal reviewer. Applications independently admit reviewer origins and the `deliverable_evaluation` claim.

Example event body (replace placeholders with real digests and identities):

```json
{
  "schema":"ecco.economic-event/v1",
  "type":"external_attestation",
  "interaction":"b3:OPENING_ENVELOPE_DIGEST",
  "links":["b3:DELIVERY_ENVELOPE_DIGEST"],
  "payload":{
    "claim":"deliverable_evaluation",
    "subject":"ecco:root:SELLER_ROOT_KEY",
    "termsDigest":"sha256:AGREED_TERMS_DIGEST",
    "criteriaDigest":"sha256:PREDECLARED_ACCEPTANCE_CRITERIA_DIGEST",
    "evaluatorRole":"external_reviewer",
    "artifactDigests":["sha256:DELIVERED_ARTIFACT_DIGEST"],
    "outcome":"pass"
  }
}
```

`evaluatorRole` is `buyer` or `external_reviewer`. `outcome` is `pass`, `fail` or `unresolved`. Artifact digests identify the exact distinct delivered artifacts, not a private execution trace. Criteria describe the evaluation; the signed verdict remains the reviewer's judgment unless separately supported by attributable acceptance-test observations. A successful payment or HTTP response is not that observation.

The product's predeclared research projection requires matching interaction, seller, terms, criteria and artifacts, admitted assertion authority, a review received no earlier than delivery, and an elapsed maturity window. A buyer review must match the verified buyer economic actor; an external reviewer must differ from buyer and seller. Different controller/owner epochs remain governed by existing economic identity history. Distinct keys alone do not establish independent beneficial ownership.

Conflicting valid reviews remain separate and project to disagreement. An issuer can retract its own review with an external attestation whose payload includes `revokesEventId`; historical originals remain verifiable. Corrections never mutate another issuer's verdict. A relay receipt provides attributable custodian chronology, not independent objective time.

The optional projection is application policy, not a new Rust core quality score. Counterparties can verify original bundles offline, choose different admitted reviewers and maturity rules, and reach different conclusions while preserving the same evidence. Enrollment, evaluation and export permissions remain separate. Private reasoning and confidential artifact bytes are not required or automatically disclosed.
