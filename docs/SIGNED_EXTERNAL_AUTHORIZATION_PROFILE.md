# Ed25519 Raw-JSON External Decision Profile (experimental)

This is an **opt-in, local reference profile** for [issue #207](https://github.com/Therealdk8890/WarrantKit/issues/207). It authenticates one exact external-decision payload *before* the existing local-policy converter issues an unsigned epoch-bound Warrant. **It is not an OIDC, OAuth, JWT, JWS, SAML, or hosted identity integration.**

## Required trust setup

- The controller operator obtains and pins a 32-byte Ed25519 verification key, exact issuer name, exact audience string, expected agent/execution identity, and durable replay-database path **from trusted configuration, not from the decision**.
- A provider signs the **exact UTF-8 JSON bytes** of a v1 external authorization document with one additional `audience` string field, using Ed25519 over the domain-separated bytes `b"WARRANTKIT-SIGNED-EXTERNAL-AUTHORIZATION-V1\x00" + signed_document`. The signature is supplied separately as the raw 64 bytes. There is no signature key-discovery or algorithm negotiation.
- The consumer calls `import_signed_authorization(signed_document, signature=..., trusted_public_key=..., expected_issuer=..., expected_audience=..., expected_agent_id=..., expected_execution_id=..., replay_store=..., policy=..., runtime_id=..., epoch=...)`.
- `SQLiteDecisionReplayStore` must reside in a trusted persistent controller-owned directory. The database must not be deleted, restored from a stale backup, or replaced with an attacker-writable file; no independently protected anti-rollback anchor is implemented. Its decision identities are never reused, so capacity/retention must be managed operationally.
- Install `warrantkit[attestation]` for the `cryptography` Ed25519 verifier.

The importer verifies the raw signature **before** JSON decoding, rejects duplicate keys and non-JSON constants, requires a bounded JSON object, checks issuer/audience/agent/execution equality, and then invokes the existing strict policy/expiry/epoch checks. It rejects decisions longer than 15 minutes and uses one SQLite `BEGIN IMMEDIATE` transaction to claim the (issuer, audience, decision ID). Failures deny admission; failed authentication never consumes a decision.

### Important nonclaims

- `import_authorization(document, ...)` remains a **structural-only** compatibility API. **It does not authenticate** any upstream issuer. `ExternalAuthorizationDecision.to_warrant` likewise does not prove upstream origin. Never sign a local Warrant based solely on either without a separate authenticated provider integration.
- The new signed profile does not validate arbitrary provider tokens, discover/rotate/revoke keys, or implement identity-provider transport. Operators must authenticate the trust-key distribution and manage rotation/revocation.
- A single local replay database is not a distributed, cross-replica replay barrier and cannot withstand privileged DB rollback. The controller and DB directory are trusted, and there is no proof of arbitrary hostile-code isolation.
- The importer **returns an unsigned Warrant**. Local Warrant signing, action-gateway checks, current runtime state, final side-effect authorization, and external enforcement remain separate required boundaries.
- This opt-in profile is a testable starting point for one explicitly documented provider protocol; it is **not production-certified external IAM support**.

See [External Authorization Provider Contract](EXTERNAL_AUTHORIZATION_PROVIDER_CONTRACT.md) for the complete requirements for a supported provider integration.
