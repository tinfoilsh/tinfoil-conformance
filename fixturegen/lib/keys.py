"""ECDSA P-256 key helpers."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils


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


@dataclass
class Ed25519KeyPair:
    """Rekor v2 (rekor-tiles) logs sign checkpoints with Ed25519."""

    private: ed25519.Ed25519PrivateKey
    public: ed25519.Ed25519PublicKey

    @classmethod
    def generate(cls) -> "Ed25519KeyPair":
        priv = ed25519.Ed25519PrivateKey.generate()
        return cls(private=priv, public=priv.public_key())

    @property
    def public_der(self) -> bytes:
        return self.public.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def public_raw(self) -> bytes:
        return self.public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

    def log_id(self, origin: str) -> bytes:
        """rekor-tiles key id: sha256(origin || "\n" || 0x01 || raw key). Its first
        4 bytes are the checkpoint key hint; the trust root's logId.keyId is the
        full hash (not sha256(SPKI) as for Rekor v1)."""
        return hashlib.sha256(origin.encode() + b"\n\x01" + self.public_raw).digest()

    def sign(self, message: bytes) -> bytes:
        return self.private.sign(message)
