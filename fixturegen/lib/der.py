"""A minimal DER encoder (ITU-T X.690) for the structures the generators emit
by hand: the RFC 3161 TimeStampResp / CMS SignedData and the small
AlgorithmIdentifier / Attribute / Name pieces inside it.

Only encoding is provided. Every function returns the complete TLV bytes.
"""

from __future__ import annotations

from datetime import datetime, timezone

TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_UTF8_STRING = 0x0C
TAG_SEQUENCE = 0x30
TAG_SET = 0x31
TAG_GENERALIZED_TIME = 0x18


def length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + length(len(content)) + content


def sequence(*parts: bytes) -> bytes:
    return tlv(TAG_SEQUENCE, b"".join(parts))


def set_of(*parts: bytes) -> bytes:
    """SET OF: DER requires the encodings sorted as octet strings."""
    return tlv(TAG_SET, b"".join(sorted(parts)))


def explicit(number: int, content: bytes) -> bytes:
    """[number] EXPLICIT — a constructed context-specific tag wrapping `content`."""
    return tlv(0xA0 | number, content)


def implicit_constructed(number: int, content: bytes) -> bytes:
    """[number] IMPLICIT over a constructed type: the same bytes as EXPLICIT, since
    the inner constructed header is replaced rather than wrapped."""
    return tlv(0xA0 | number, content)


def integer(n: int) -> bytes:
    if n == 0:
        return tlv(TAG_INTEGER, b"\x00")
    size = (n.bit_length() + 8) // 8  # one extra bit for the sign
    return tlv(TAG_INTEGER, n.to_bytes(size, "big", signed=True))


def boolean(v: bool) -> bytes:
    return tlv(TAG_BOOLEAN, b"\xff" if v else b"\x00")


def null() -> bytes:
    return tlv(TAG_NULL, b"")


def octet_string(data: bytes) -> bytes:
    return tlv(TAG_OCTET_STRING, data)


def bit_string(data: bytes, unused_bits: int = 0) -> bytes:
    return tlv(TAG_BIT_STRING, bytes([unused_bits]) + data)


def utf8_string(s: str) -> bytes:
    return tlv(TAG_UTF8_STRING, s.encode("utf-8"))


def oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    if len(arcs) < 2:
        raise ValueError(f"OID {dotted!r} needs at least two arcs")
    body = bytearray(_base128(arcs[0] * 40 + arcs[1]))
    for arc in arcs[2:]:
        body += _base128(arc)
    return tlv(TAG_OID, bytes(body))


def _base128(n: int) -> bytes:
    out = bytearray([n & 0x7F])
    n >>= 7
    while n:
        out.insert(0, 0x80 | (n & 0x7F))
        n >>= 7
    return bytes(out)


def generalized_time(dt: datetime) -> bytes:
    """GeneralizedTime in the DER-mandated YYYYMMDDHHMMSSZ form (no fraction)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    text = dt.astimezone(timezone.utc).strftime("%Y%m%d%H%M%SZ")
    return tlv(TAG_GENERALIZED_TIME, text.encode("ascii"))


def algorithm_identifier(dotted: str, *, null_params: bool = False) -> bytes:
    """AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }."""
    return sequence(oid(dotted), null() if null_params else b"")
