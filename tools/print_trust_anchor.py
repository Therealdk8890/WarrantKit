#!/usr/bin/env python3
"""Print the independently distributable identity of an Ed25519 public key."""
from __future__ import annotations

import argparse
import base64
import hashlib
from pathlib import Path


def describe_public_key(path: Path) -> dict[str, str]:
    """Load a PEM Ed25519 public key and return portable anchor metadata."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise RuntimeError(
            "trust-anchor fingerprinting requires: pip install 'warrantkit[attestation]'"
        ) from exc

    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key file must contain an Ed25519 public key")
    raw = key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return {
        "algorithm": "Ed25519",
        "fingerprint_sha256": "SHA256:" + hashlib.sha256(raw).hexdigest(),
        "trusted_public_key_b64": base64.b64encode(raw).decode("ascii"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Print an Ed25519 public-key fingerprint and verifier input."
    )
    parser.add_argument("public_key_pem", type=Path)
    args = parser.parse_args()
    try:
        metadata = describe_public_key(args.public_key_pem)
    except Exception as exc:
        parser.exit(1, f"REJECTED: {type(exc).__name__}: {exc}\n")
    for name, value in metadata.items():
        print(f"{name}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
