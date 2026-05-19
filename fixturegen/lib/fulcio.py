"""Test Fulcio root + leaf certificate builder.

Generates an ECDSA P-256 self-signed root and a leaf signing cert with the
Fulcio OID extensions a SDK looks up (OIDC issuer, GitHub workflow repo,
workflow ref, build signer URI). Embeds RFC 6962 SCTs.

OID arc reference: https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .keys import P256KeyPair
from .sct import SCT, sct_extension_value


# Fulcio extension OIDs (https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md).
# V1 extensions carry raw UTF-8 byte values; V2 extensions carry DER UTF8String.
OID_FULCIO_OIDC_ISSUER_V1 = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
OID_FULCIO_GITHUB_WORKFLOW_REPOSITORY = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.5")
OID_FULCIO_GITHUB_WORKFLOW_REF = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.6")
OID_FULCIO_OIDC_ISSUER_V2 = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.8")
OID_FULCIO_BUILD_SIGNER_URI = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.9")
OID_FULCIO_SOURCE_REPOSITORY_URI = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.12")

# RFC 6962 SCT extension OID.
OID_SCT = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")


@dataclass
class RootCA:
    cert: x509.Certificate
    key: P256KeyPair

    @property
    def cert_pem(self) -> str:
        return self.cert.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def cert_der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)


@dataclass
class LeafCert:
    cert: x509.Certificate
    key: P256KeyPair

    @property
    def cert_pem(self) -> str:
        return self.cert.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def cert_der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)


def build_root_ca(
    *,
    key: P256KeyPair,
    common_name: str = "tinfoil-conformance test Fulcio root",
    not_before: datetime,
    not_after: datetime,
) -> RootCA:
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "tinfoil-conformance"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public)
        .serial_number(x509.random_serial_number())
        .not_valid_before(_naive_utc(not_before))
        .not_valid_after(_naive_utc(not_after))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public), critical=False
        )
        .sign(key.private, hashes.SHA256())
    )
    return RootCA(cert=cert, key=key)


@dataclass
class LeafCertSpec:
    oidc_issuer: str
    workflow_repository: str
    workflow_ref: str
    build_signer_uri: str
    source_repository_uri: str | None = None
    common_name: str = "tinfoil-conformance test signer"
    # Per-extension omission knobs. Defaults emit a full Fulcio-style cert.
    omit_oidc_v1: bool = False
    omit_oidc_v2: bool = False
    omit_workflow_ref_ext: bool = False
    omit_build_signer_uri: bool = False
    # When non-None the V1 OIDC issuer (.1.1) carries this value while V2
    # (.1.8) carries `oidc_issuer`. Lets fixtures probe V1-vs-V2 precedence.
    oidc_issuer_v1_override: str | None = None


def build_leaf_pre_sct(
    *,
    leaf_key: P256KeyPair,
    root: RootCA,
    spec: LeafCertSpec,
    not_before: datetime,
    not_after: datetime,
    serial: int,
) -> x509.Certificate:
    """Build a leaf cert WITHOUT the SCT extension. Used only to extract its
    TBS bytes for the SCT signing input — the resulting cert is discarded.

    `serial` MUST be the same value passed to `build_leaf_final` so the
    SCT signing input matches what the verifier reconstructs (it strips the
    SCT extension from the final cert and re-encodes the TBS)."""
    return _build_leaf(
        leaf_key=leaf_key,
        root=root,
        spec=spec,
        not_before=not_before,
        not_after=not_after,
        serial=serial,
        extra_extensions=[],
    )


def build_leaf_final(
    *,
    leaf_key: P256KeyPair,
    root: RootCA,
    spec: LeafCertSpec,
    not_before: datetime,
    not_after: datetime,
    serial: int,
    scts: Iterable[SCT],
) -> LeafCert:
    """Build the final leaf cert with the SCT extension included.

    `serial` MUST match what was passed to `build_leaf_pre_sct`."""
    sct_ext = x509.UnrecognizedExtension(
        OID_SCT, sct_extension_value(list(scts))
    )
    cert = _build_leaf(
        leaf_key=leaf_key,
        root=root,
        spec=spec,
        not_before=not_before,
        not_after=not_after,
        serial=serial,
        extra_extensions=[(sct_ext, False)],
    )
    return LeafCert(cert=cert, key=leaf_key)


def _build_leaf(
    *,
    leaf_key: P256KeyPair,
    root: RootCA,
    spec: LeafCertSpec,
    not_before: datetime,
    not_after: datetime,
    serial: int,
    extra_extensions: list[tuple[x509.ExtensionType, bool]],
) -> x509.Certificate:
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, spec.common_name)]
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root.cert.subject)
        .public_key(leaf_key.public)
        .serial_number(serial)
        .not_valid_before(_naive_utc(not_before))
        .not_valid_after(_naive_utc(not_after))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root.key.public),
            critical=False,
        )
    )
    # Fulcio extensions — emitted conditionally per LeafCertSpec flags. The
    # default path (everything True) reproduces a normal Fulcio leaf cert;
    # individual omissions + the V1 override let fixtures exercise SDK
    # quirks around which fields are required and how V1-vs-V2 precedence
    # is resolved.
    if not spec.omit_oidc_v1:
        v1_value = (
            spec.oidc_issuer_v1_override
            if spec.oidc_issuer_v1_override is not None
            else spec.oidc_issuer
        )
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                OID_FULCIO_OIDC_ISSUER_V1, v1_value.encode("utf-8")
            ),
            critical=False,
        )
    builder = builder.add_extension(
        x509.UnrecognizedExtension(
            OID_FULCIO_GITHUB_WORKFLOW_REPOSITORY,
            spec.workflow_repository.encode("utf-8"),
        ),
        critical=False,
    )
    if not spec.omit_workflow_ref_ext:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                OID_FULCIO_GITHUB_WORKFLOW_REF, spec.workflow_ref.encode("utf-8")
            ),
            critical=False,
        )
    if not spec.omit_oidc_v2:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                OID_FULCIO_OIDC_ISSUER_V2,
                _der_utf8_string(spec.oidc_issuer),
            ),
            critical=False,
        )
    if not spec.omit_build_signer_uri:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                OID_FULCIO_BUILD_SIGNER_URI,
                _der_utf8_string(spec.build_signer_uri),
            ),
            critical=False,
        )
    if spec.source_repository_uri:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                OID_FULCIO_SOURCE_REPOSITORY_URI,
                _der_utf8_string(spec.source_repository_uri),
            ),
            critical=False,
        )

    for ext, critical in extra_extensions:
        builder = builder.add_extension(ext, critical=critical)

    return builder.sign(root.key.private, hashes.SHA256())


def issuer_spki_der(root: RootCA) -> bytes:
    """The DER-encoded SubjectPublicKeyInfo of the Fulcio root — used as
    the issuer_key_hash precursor in SCT signing input."""
    return root.cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# Helpers ------------------------------------------------------------------


def _der_utf8_string(s: str) -> bytes:
    """Encode `s` as a DER-encoded UTF8String (tag 0x0C)."""
    body = s.encode("utf-8")
    return b"\x0c" + _der_length(len(body)) + body


def _der_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _naive_utc(d: datetime) -> datetime:
    """PyCA cryptography wants naive datetimes interpreted as UTC."""
    if d.tzinfo is None:
        return d
    return d.astimezone(timezone.utc).replace(tzinfo=None)
