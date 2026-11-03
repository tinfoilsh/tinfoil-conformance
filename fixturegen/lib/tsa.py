"""Synthetic RFC 3161 timestamp authority: certificate chain + TimeStampResp.

Builds what a Sigstore-style TSA returns for a request over some bytes:

    TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo }
    ContentInfo   ::= SEQUENCE { signedData OID, [0] EXPLICIT SignedData }
    SignedData    ::= SEQUENCE { version 3, digestAlgorithms, encapContentInfo
                                 (id-ct-TSTInfo, [0] EXPLICIT OCTET STRING TSTInfo),
                                 [0] IMPLICIT certificates OPTIONAL, signerInfos }
    SignerInfo    ::= SEQUENCE { version 1, issuerAndSerialNumber, digestAlgorithm,
                                 [0] IMPLICIT signedAttrs, signatureAlgorithm, signature }

The signature covers the signed attributes re-tagged as a SET (RFC 5652
§5.4); the attributes are content-type (id-ct-TSTInfo), message-digest
(SHA-256 of the TSTInfo DER) and signing-certificate-v2 (ESSCertIDv2 of the
signer, RFC 5816), as the production Sigstore TSA emits.

References used while implementing:
  * RFC 3161 §2.4.2 (TimeStampResp / TSTInfo), RFC 5652 (CMS), RFC 5816
  * sigstore/timestamp-authority pkg/verification (the Go verify side)
  * digitorus/timestamp (CreateResponseWithOpts, the Go emit side)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import der
from .keys import P256KeyPair

# Object identifiers.
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2"
# The Sigstore timestamp policy a tinfoil verifier requires.
SIGSTORE_TIMESTAMP_POLICY = "1.3.6.1.4.1.57264.2"

# PKIStatus (RFC 3161 §2.4.2).
STATUS_GRANTED = 0
STATUS_GRANTED_WITH_MODS = 1
STATUS_REJECTION = 2
# PKIFailureInfo bit positions.
FAIL_BAD_ALG = 0
FAIL_BAD_REQUEST = 2


@dataclass
class TimestampAuthority:
    """A root and the timestamping leaf it issued. `chain_der` is in trusted
    root wire order (leaf first, root last)."""

    root_cert: x509.Certificate
    root_key: P256KeyPair
    leaf_cert: x509.Certificate
    leaf_key: P256KeyPair

    @property
    def root_der(self) -> bytes:
        return self.root_cert.public_bytes(serialization.Encoding.DER)

    @property
    def leaf_der(self) -> bytes:
        return self.leaf_cert.public_bytes(serialization.Encoding.DER)

    @property
    def chain_der(self) -> list[bytes]:
        return [self.leaf_der, self.root_der]


def build_timestamp_authority(
    *,
    root_key: P256KeyPair,
    leaf_key: P256KeyPair,
    root_not_before: datetime,
    root_not_after: datetime,
    leaf_not_before: datetime,
    leaf_not_after: datetime,
    root_serial: int,
    leaf_serial: int,
    root_common_name: str = "tinfoil-conformance test TSA root",
    leaf_common_name: str = "tinfoil-conformance test TSA signer",
    eku: bool = True,
    eku_critical: bool = True,
) -> TimestampAuthority:
    """A self-signed ECDSA root and an end-entity timestamping leaf. The leaf
    carries a critical extended key usage of timestamping only, as RFC 3161
    §2.3 requires; the `eku` / `eku_critical` knobs produce the certificates a
    verifier must reject."""
    org = x509.NameAttribute(NameOID.ORGANIZATION_NAME, "tinfoil-conformance")
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, root_common_name), org])
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, leaf_common_name), org])
    # Certificates are signed with the hash that matches the issuing key's
    # curve (ecdsa-with-SHA384 for P-384), as CAs issue them; only the
    # timestamp token itself signs SHA-256 digests regardless of curve.
    cert_hash = hashes.SHA384() if root_key.public.curve.key_size == 384 else hashes.SHA256()

    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public)
        .serial_number(root_serial)
        .not_valid_before(_naive_utc(root_not_before))
        .not_valid_after(_naive_utc(root_not_after))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(_key_usage(key_cert_sign=True), critical=True)
        .sign(root_key.private, cert_hash, ecdsa_deterministic=True)
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(root_name)
        .public_key(leaf_key.public)
        .serial_number(leaf_serial)
        .not_valid_before(_naive_utc(leaf_not_before))
        .not_valid_after(_naive_utc(leaf_not_after))
        .add_extension(_key_usage(digital_signature=True), critical=True)
    )
    if eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=eku_critical
        )
    leaf_cert = builder.sign(root_key.private, cert_hash, ecdsa_deterministic=True)
    return TimestampAuthority(root_cert=root_cert, root_key=root_key, leaf_cert=leaf_cert, leaf_key=leaf_key)


def build_tst_info(
    *,
    imprint: bytes,
    gen_time: datetime,
    serial: int,
    policy: str = SIGSTORE_TIMESTAMP_POLICY,
) -> bytes:
    """TSTInfo ::= SEQUENCE { version 1, policy, messageImprint, serialNumber, genTime }."""
    message_imprint = der.sequence(
        der.algorithm_identifier(OID_SHA256, null_params=True),
        der.octet_string(imprint),
    )
    return der.sequence(
        der.integer(1),
        der.oid(policy),
        message_imprint,
        der.integer(serial),
        der.generalized_time(gen_time),
    )


def build_timestamp_response(
    *,
    tsa: TimestampAuthority,
    tst_info: bytes,
    status: int = STATUS_GRANTED,
    embed_certificate: bool = True,
) -> bytes:
    """A granted (or granted-with-mods) TimeStampResp whose token is signed by
    the authority's leaf over SHA-256 with ecdsa-with-SHA256, whatever the
    leaf's curve (the production TSA key is P-384 and signs SHA-256 digests)."""
    leaf = tsa.leaf_cert
    signed_attrs = [
        der.sequence(der.oid(OID_CONTENT_TYPE), der.set_of(der.oid(OID_TST_INFO))),
        der.sequence(
            der.oid(OID_MESSAGE_DIGEST),
            der.set_of(der.octet_string(hashlib.sha256(tst_info).digest())),
        ),
        der.sequence(
            der.oid(OID_SIGNING_CERTIFICATE_V2),
            der.set_of(_signing_certificate_v2(leaf)),
        ),
    ]
    # The signature is computed over the attributes encoded as a SET OF, while
    # the SignerInfo carries them under the [0] IMPLICIT tag.
    attrs_set = der.set_of(*signed_attrs)
    signature = tsa.leaf_key.sign_prehashed_sha256(attrs_set)
    signed_attrs_tagged = b"\xa0" + attrs_set[1:]

    signer_info = der.sequence(
        der.integer(1),
        der.sequence(leaf.issuer.public_bytes(), der.integer(leaf.serial_number)),
        der.algorithm_identifier(OID_SHA256, null_params=True),
        signed_attrs_tagged,
        der.algorithm_identifier(OID_ECDSA_WITH_SHA256),
        der.octet_string(signature),
    )
    signed_data = der.sequence(
        der.integer(3),
        der.set_of(der.algorithm_identifier(OID_SHA256, null_params=True)),
        der.sequence(der.oid(OID_TST_INFO), der.explicit(0, der.octet_string(tst_info))),
        der.implicit_constructed(0, tsa.leaf_der) if embed_certificate else b"",
        der.set_of(signer_info),
    )
    token = der.sequence(der.oid(OID_SIGNED_DATA), der.explicit(0, signed_data))
    return der.sequence(der.sequence(der.integer(status)), token)


def build_rejected_response(*, status: int = STATUS_REJECTION, fail_info_bit: int = FAIL_BAD_REQUEST,
                            status_text: str = "request rejected") -> bytes:
    """A TimeStampResp whose status carries no token."""
    bits = bytearray(1 + fail_info_bit // 8)
    bits[fail_info_bit // 8] |= 0x80 >> (fail_info_bit % 8)
    status_info = der.sequence(
        der.integer(status),
        der.sequence(der.utf8_string(status_text)),  # PKIFreeText ::= SEQUENCE OF UTF8String
        der.bit_string(bytes(bits), unused_bits=7 - (fail_info_bit % 8)),
    )
    return der.sequence(status_info)


def _signing_certificate_v2(cert: x509.Certificate) -> bytes:
    """SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 };
    ESSCertIDv2 with the default SHA-256 hash algorithm omitted and the
    issuerSerial present (RFC 5035 §4)."""
    cert_hash = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).digest()
    issuer_serial = der.sequence(
        der.sequence(der.implicit_constructed(4, cert.issuer.public_bytes())),  # GeneralNames { directoryName }
        der.integer(cert.serial_number),
    )
    ess_cert_id = der.sequence(der.octet_string(cert_hash), issuer_serial)
    return der.sequence(der.sequence(ess_cert_id))


def _key_usage(*, digital_signature: bool = False, key_cert_sign: bool = False) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=digital_signature,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=key_cert_sign,
        crl_sign=key_cert_sign,
        encipher_only=False,
        decipher_only=False,
    )


def _naive_utc(d: datetime) -> datetime:
    if d.tzinfo is None:
        return d
    return d.astimezone(timezone.utc).replace(tzinfo=None)
