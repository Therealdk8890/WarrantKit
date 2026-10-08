#!/usr/bin/env python3
"""Independently verify a WarrantKit incident bundle."""
from __future__ import annotations

import argparse
from pathlib import Path

from incident_bundle import verify_incident_bundle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument(
        "--trusted-public-key",
        help="base64 Ed25519 public key supplied by an external trust anchor",
    )
    args = parser.parse_args()

    try:
        result = verify_incident_bundle(
            args.bundle,
            trusted_public_key_b64=args.trusted_public_key,
        )
    except Exception as exc:
        print(f"REJECTED: {type(exc).__name__}: {exc}")
        return 1

    print(
        f"{result['status']}: incident={result['incident_id']} "
        f"authenticity={result['authenticity']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
