# External Authorization Provider Contract

## Status

This document defines the trust requirements for a future provider integration. It does not claim that WarrantKit currently authenticates external authorization documents, and it does not define a generic token format.

Until a provider adapter satisfies this contract, `import_authorization(document, ...)` is a structural and local-policy converter only. It must not be used as proof that an identity provider authenticated or approved a decision.

## Trust stages

Keep these stages distinct:

1. **Acquire** the provider response using the provider's documented authenticated channel, or obtain a signed decision token/document.
2. **Authenticate** the response according to a configured provider profile. TLS alone authenticates the remote endpoint for that connection; it does not necessarily authenticate a detached document that is later copied, stored, or replayed.
3. **Validate claims** required by that profile: trusted issuer, intended audience/recipient, subject, decision semantics, issue/expiry times, and any provider-specific tenant or client binding.
4. **Prevent replay** using provider-defined unique identifiers or nonces and a durable replay policy where the threat model requires it. A decision ID supplied by an untrusted payload is not replay protection by itself.
5. **Bind the exact payload**: the claims validated by the provider verifier must be the same claims passed to WarrantKit. Do not authenticate one byte sequence or object and then import a separately parsed or caller-mutated object.
6. **Apply WarrantKit admission checks**: local policy ID and digest, execution identity, runtime epoch, capability subset, and validity window remain authoritative and fail closed.
7. **Issue local authority** only after all prior stages succeed. Local Warrant signing authenticates the local Warrant issuer; it does not retroactively authenticate an untrusted upstream decision.

## Provider profile requirements

A provider adapter must document and test all of the following before it can be described as authenticated:

- The trust-anchor source and administration process (including key rotation and revocation).
- The accepted issuer identifiers and the exact audience/recipient expected by this deployment.
- The signature algorithm or authenticated transport mechanism, with an explicit allowlist rather than algorithm negotiation from untrusted input.
- Subject and tenant/client binding to the requested agent and execution.
- The meaning of an allow decision and the mapping of provider claims to WarrantKit capabilities.
- Clock-skew policy, required issuance/expiry claims, and maximum accepted decision lifetime.
- Replay handling and its persistence/availability assumptions.
- Canonicalization or exact-byte rules used to bind the verified payload to the imported decision.
- Failure behavior: unknown issuer/key, invalid signature, wrong audience/subject, missing claims, expired/not-yet-valid decision, replay, malformed payload, or unavailable trust configuration must deny admission.

OIDC identity tokens, OAuth access tokens, policy-engine responses, and custom signed authorization decisions are not interchangeable. A provider profile must state which artifact is being verified and why its claims authorize this particular action. Merely validating an identity token does not prove that a separate authorization decision was approved.

## API design constraints

- Do not add a caller-controlled boolean such as `authenticated=True` or accept a caller-supplied issuer string as proof.
- A verifier callback is not sufficient by itself unless its contract defines the authenticated artifact, trust configuration, claim checks, replay behavior, and exact-payload binding.
- Do not silently infer a provider protocol from the shape of the existing v1 document.
- Do not weaken local policy, runtime identity, epoch fencing, expiry, signed-Warrant verification, or runtime enforcement to accommodate an upstream provider.
- Preserve the distinction between external source authentication and local Warrant attestation. They establish different trust statements.

## Required negative tests

Every provider adapter must show that it rejects:

- Unknown issuer and unknown/untrusted key.
- Modified decision claims or payload after authentication.
- Missing or incorrect audience, subject, tenant/client binding, or decision claim.
- Expired, not-yet-valid, and overlong-lived decisions.
- Replayed decision identifiers/nonces according to the documented replay policy.
- Missing signature/authentication material and malformed encodings.
- A decision whose capabilities exceed the locally accepted policy.
- A decision bound to the wrong execution identity, policy digest, or runtime epoch.

At least one end-to-end test must demonstrate that an unauthenticated or altered external document cannot reach the supported local Warrant-signing flow. Unit tests that only check JSON shape are not sufficient evidence of source authentication.

## Current implementation

The current `ExternalAuthorizationDecision` dataclass is a data model, not a proof that a provider verifier ran. `import_authorization` parses and checks an external document but does not verify its source. The existing external authorization boundary document describes this limitation. See [issue #207](https://github.com/Therealdk8890/WarrantKit/issues/207) before implementing a provider-specific adapter.
