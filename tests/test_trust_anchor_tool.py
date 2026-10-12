import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.print_trust_anchor import describe_public_key


def test_describe_public_key_prints_verifier_input_and_fingerprint(tmp_path):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    path = tmp_path / "trusted-public-key.pem"
    path.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    assert describe_public_key(path) == {
        "algorithm": "Ed25519",
        "fingerprint_sha256": "SHA256:" + hashlib.sha256(raw).hexdigest(),
        "trusted_public_key_b64": base64.b64encode(raw).decode("ascii"),
    }


def test_describe_public_key_rejects_non_ed25519_key(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import rsa

    path = tmp_path / "rsa-public-key.pem"
    path.write_bytes(
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    with pytest.raises(ValueError, match="must contain an Ed25519"):
        describe_public_key(path)
