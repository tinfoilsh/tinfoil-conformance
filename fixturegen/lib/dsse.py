"""DSSE envelope signing.

DSSE PAE (Pre-Authentication Encoding) per https://github.com/secure-systems-lab/dsse:

    PAE("DSSEv1", payload_type, payload) =
        "DSSEv1" + SP + str(len(payload_type)) + SP + payload_type
        + SP + str(len(payload)) + SP + payload
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from .keys import P256KeyPair


@dataclass
class SignedEnvelope:
    """A DSSE envelope ready to embed in a Sigstore bundle."""

    payload_type: str
    payload_bytes: bytes
    signature_der: bytes

    @property
    def payload_b64(self) -> str:
        return base64.standard_b64encode(self.payload_bytes).decode()

    @property
    def signature_b64(self) -> str:
        return base64.standard_b64encode(self.signature_der).decode()


def compute_pae(payload_type: str, payload: bytes) -> bytes:
    return (
        b"DSSEv1 "
        + str(len(payload_type)).encode()
        + b" "
        + payload_type.encode()
        + b" "
        + str(len(payload)).encode()
        + b" "
        + payload
    )


def sign_envelope(
    *, signing_key: P256KeyPair, payload_type: str, payload: bytes
) -> SignedEnvelope:
    pae = compute_pae(payload_type, payload)
    sig = signing_key.sign_prehashed_sha256(pae)
    return SignedEnvelope(
        payload_type=payload_type, payload_bytes=payload, signature_der=sig
    )
