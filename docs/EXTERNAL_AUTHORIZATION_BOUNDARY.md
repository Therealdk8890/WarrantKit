# External Authorization Trust Boundary

`import_authorization(document, ...)` performs structural and local-policy checks. It does not authenticate the external issuer or verify a signature on the external document. The `issuer` field is supplied by the document and must not be treated as a verified identity.

## Integration requirement

Before calling `import_authorization`, the integration must authenticate the original decision using its provider's signature or authenticated response mechanism, validate the issuer and relevant audience/subject/replay controls, and import the exact payload that was authenticated. Continue through WarrantKit's normal Warrant signing and adapter verification path afterward.

A policy ID and digest match proves compatibility with the local policy; it does not prove who issued the external decision. Do not promote unauthenticated external JSON into trusted local authority.

The converter currently rejects non-empty external constraints because their semantics are unsupported. Do not treat arbitrary constraint fields as enforced restrictions.

This is an integration contract, not a claim that WarrantKit currently provides a generic external-issuer signature verifier. The current `ExternalAuthorizationDecision` dataclass is a data model, not proof that a verifier ran. For requirements a future provider adapter must satisfy—including trust anchors, audience and subject binding, replay protection, exact-payload binding, and negative tests—see [External Authorization Provider Contract](EXTERNAL_AUTHORIZATION_PROVIDER_CONTRACT.md).

See [issue #207](https://github.com/Therealdk8890/WarrantKit/issues/207) for implementation tracking.