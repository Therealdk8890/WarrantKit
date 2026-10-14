# Incident bundle API and trust model

WarrantKit exposes the incident-bundle builder and verifier from the installed Python package in version 0.1.3 and later:

```python
from pathlib import Path
from agentcontain import verify_incident_bundle

result = verify_incident_bundle(
    Path("incident-bundle"),
    trusted_public_key_b64=trusted_public_key_b64,
)
```

The directory must contain the bundle's manifest, receipt, public-key record, and all records listed by the manifest. The verifier validates required files and digests, cross-record identity/epoch invariants, manifest claims, the Ed25519 receipt, and the signed manifest digest.

## Trust states

- **`INTEGRITY_ONLY`** — the signature and internal bundle consistency validate using the public key embedded in the bundle. This does not authenticate the producer.
- **`AUTHENTICATED`** — the signature validates using an independently provisioned public-key trust anchor supplied as `trusted_public_key_b64`, and that anchor matches the bundle key.

Do not promote `INTEGRITY_ONLY` to `AUTHENTICATED`. Do not treat either status as proof that arbitrary natural-language claims are objectively true. The verifier establishes the stated bundle contract and the provenance of the signed artifact relative to the trust anchor.

## CLI compatibility

Existing source-checkout usage remains available:

```bash
python tools/verify_incident_bundle.py incident-bundle \
  --trusted-public-key "$WARRANTKIT_TRUSTED_PUBLIC_KEY_B64"
```

Install the optional cryptographic dependency with:

```bash
pip install 'warrantkit[attestation]'
```

The API is local and offline. It does not fetch trust anchors, access artifact URLs, or contact a hosted service. The caller is responsible for securely provisioning and rotating the trusted public key.
