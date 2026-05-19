"""ECDSA P-256 key helpers."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


@dataclass
class P256KeyPair:
    """An ECDSA P-256 keypair with cached DER/PEM encodings."""

    private: ec.EllipticCurvePrivateKey
    public: ec.EllipticCurvePublicKey

    @classmethod
    def generate(cls) -> "P256KeyPair":
        priv = ec.generate_private_key(ec.SECP256R1())
        return cls(private=priv, public=priv.public_key())

    @property
    def public_der(self) -> bytes:
        """SubjectPublicKeyInfo DER (used for log id derivation)."""
        return self.public.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def public_pem(self) -> str:
        return self.public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    @property
    def log_id(self) -> bytes:
        """The 32-byte SHA-256 of the SPKI DER. Used as CT log id and Rekor log id."""
        return hashlib.sha256(self.public_der).digest()

    def sign_prehashed_sha256(self, message: bytes) -> bytes:
        """ECDSA P-256 signature over SHA-256(message). DER-encoded."""
        return self.private.sign(message, ec.ECDSA(hashes.SHA256()))

    def sign_digest_sha256(self, digest: bytes) -> bytes:
        """ECDSA P-256 signature over an already-computed SHA-256 digest."""
        return self.private.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
