"""RFC 6962 Signed Certificate Timestamp generation.

We hand-roll the TLS-encoded SCT structure because PyCA `cryptography` only
parses SCTs; it doesn't generate them. The format is fixed and small.

References:
  - RFC 6962 §3.2 (DigitallySigned)
  - RFC 6962 §3.4 (SignedCertificateTimestamp + CertificateTimestamp signing input)
  - RFC 6962 §3.3 (Precertificate Submission to Log)
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from .keys import P256KeyPair


# RFC 6962 enums
_SCT_VERSION_V1 = 0
_SIGNATURE_TYPE_CERT_TIMESTAMP = 0
_ENTRY_TYPE_PRECERT = 1
# DigitallySigned: HashAlgorithm=sha256(4), SignatureAlgorithm=ecdsa(3)
_HASH_SHA256 = 4
_SIG_ECDSA = 3


@dataclass
class SCT:
    """One Signed Certificate Timestamp ready to embed in a cert extension."""

    serialized: bytes  # SerializedSCT bytes (the TLS-encoded structure)


def make_sct(
    *,
    ct_log_key: P256KeyPair,
    issuer_spki_der: bytes,
    tbs_pre_sct_bytes: bytes,
    timestamp: datetime,
) -> SCT:
    """Build an RFC 6962 SCT for a precert.

    `tbs_pre_sct_bytes` MUST be the cert's TBSCertificate DER bytes WITHOUT
    the SCT extension included (the verifier reconstructs this exact byte
    sequence at check time).
    """
    timestamp_ms = int(timestamp.timestamp() * 1000)
    log_id = hashlib.sha256(issuer_spki_der_for_log_id(ct_log_key)).digest()
    issuer_key_hash = hashlib.sha256(issuer_spki_der).digest()

    # CertificateTimestamp signing input (RFC 6962 §3.2 + §3.4):
    #   sct_version(1) || signature_type(1) || timestamp(8) || entry_type(2)
    #   || precert_entry(34 + 3 + len(tbs)) || extensions(2-byte length + bytes)
    extensions = b""
    signed_data = (
        struct.pack("!B", _SCT_VERSION_V1)
        + struct.pack("!B", _SIGNATURE_TYPE_CERT_TIMESTAMP)
        + struct.pack("!Q", timestamp_ms)
        + struct.pack("!H", _ENTRY_TYPE_PRECERT)
        + issuer_key_hash
        + _opaque24(tbs_pre_sct_bytes)
        + _opaque16(extensions)
    )

    sig_der = ct_log_key.sign_prehashed_sha256(signed_data)
    digitally_signed = (
        struct.pack("!B", _HASH_SHA256)
        + struct.pack("!B", _SIG_ECDSA)
        + _opaque16(sig_der)
    )

    # SerializedSCT (what gets embedded, RFC 6962 §3.3):
    #   sct_version(1) || log_id(32) || timestamp(8) || extensions(2+len)
    #   || digitally_signed
    serialized = (
        struct.pack("!B", _SCT_VERSION_V1)
        + log_id
        + struct.pack("!Q", timestamp_ms)
        + _opaque16(extensions)
        + digitally_signed
    )
    return SCT(serialized=serialized)


def issuer_spki_der_for_log_id(ct_log_key: P256KeyPair) -> bytes:
    """The bytes used to compute the CT log id are the SPKI DER of the log key."""
    return ct_log_key.public_der


def serialized_sct_list(scts: Iterable[SCT]) -> bytes:
    """Build the SerializedSCTList (length-prefixed list of length-prefixed SCTs)."""
    inner = b"".join(_opaque16(sct.serialized) for sct in scts)
    return _opaque16(inner)


def sct_extension_value(scts: Iterable[SCT]) -> bytes:
    """Wrap SerializedSCTList in the outer OCTET STRING that the SCT extension
    value carries. PyCA `cryptography` will wrap THIS in another OCTET STRING
    when we add it as an UnrecognizedExtension — that's the double-wrapping
    RFC 6962 §3.3 requires."""
    inner = serialized_sct_list(scts)
    return _der_octet_string(inner)


def _opaque16(b: bytes) -> bytes:
    """RFC 5246 opaque<0..2^16-1>: 2-byte big-endian length + bytes."""
    if len(b) >= 1 << 16:
        raise ValueError("opaque too long for 16-bit length")
    return struct.pack("!H", len(b)) + b


def _opaque24(b: bytes) -> bytes:
    """RFC 5246 opaque<0..2^24-1>: 3-byte big-endian length + bytes."""
    if len(b) >= 1 << 24:
        raise ValueError("opaque too long for 24-bit length")
    return len(b).to_bytes(3, "big") + b


def _der_octet_string(b: bytes) -> bytes:
    """Encode bytes as a DER OCTET STRING (tag 0x04)."""
    return b"\x04" + _der_length(len(b)) + b


def _der_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def timestamp_to_ms(ts: datetime) -> int:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return int(ts.timestamp() * 1000)
