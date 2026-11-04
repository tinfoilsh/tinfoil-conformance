"""ECDSA P-256 / P-384 and Ed25519 key helpers."""

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
    # Keys derived from a fixed secret sign with RFC 6979 deterministic nonces
    # so a generator built on them is byte-stable across runs.
    deterministic: bool = False

    CURVE = ec.SECP256R1

    @classmethod
    def generate(cls) -> "P256KeyPair":
        priv = ec.generate_private_key(cls.CURVE())
        return cls(private=priv, public=priv.public_key())

    @classmethod
    def from_secret(cls, secret: int) -> "P256KeyPair":
        """Derive a reproducible keypair from a fixed private scalar."""
        priv = ec.derive_private_key(secret, cls.CURVE())
        return cls(private=priv, public=priv.public_key(), deterministic=True)

    def _ecdsa_sha256(self):
        if self.deterministic:
            return ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
        return ec.ECDSA(hashes.SHA256())

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
        """ECDSA signature over SHA-256(message). DER-encoded."""
        return self.private.sign(message, self._ecdsa_sha256())

    def sign_digest_sha256(self, digest: bytes) -> bytes:
        """ECDSA P-256 signature over an already-computed SHA-256 digest."""
        return self.private.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))


class P384KeyPair(P256KeyPair):
    """An ECDSA P-384 keypair. The production Sigstore timestamp authority
    signs with a P-384 key over SHA-256 digests, so the rfc3161 fixtures need one."""

    CURVE = ec.SECP384R1


@dataclass
class Ed25519KeyPair:
    """An Ed25519 keypair (Rekor v2 logs sign checkpoints with Ed25519)."""

    private: ed25519.Ed25519PrivateKey
    public: ed25519.Ed25519PublicKey

    @classmethod
    def from_seed(cls, seed: bytes) -> "Ed25519KeyPair":
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        return cls(private=priv, public=priv.public_key())

    @property
    def public_der(self) -> bytes:
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
    def public_raw(self) -> bytes:
        """The 32-byte raw public key (the subjectPublicKey of the SPKI)."""
        return self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def log_id(self) -> bytes:
        """The 32-byte SHA-256 of the SPKI DER, used as the trusted root's log id."""
        return hashlib.sha256(self.public_der).digest()

    def sign(self, message: bytes) -> bytes:
        """Pure Ed25519 signature (64 bytes) over the message."""
        return self.private.sign(message)
