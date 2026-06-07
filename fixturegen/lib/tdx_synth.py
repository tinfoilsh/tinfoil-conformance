"""Synthetic Intel-mimicking chain + TDX quote builder.

Produces a self-consistent set of certificates, a TDX v4 quote, and the
collateral (TCB Info JSON, QE Identity JSON, CRLs) needed to drive Phase 3
fixtures through Intel's §4.7 collateral evaluation path with controllable
TCB statuses.

Cryptographic notes:
  * All keys are ECDSA P-256 (matches Intel's AKT=2 and SGX cert format).
  * Intel SGX OID extensions are encoded raw — cryptography library lacks a
    high-level builder for the Intel-specific extension layout.
  * QE Report has MRSIGNER set to a controllable 32-byte value so the QE
    Identity JSON's `mrsigner` field can match.
  * AK hash binding: SHA-256(AK pubkey raw 64 bytes) is placed in
    QE.ReportData (first 32 bytes); the remaining 32 are zero.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from .keys import P256KeyPair


INTEL_QE_VENDOR_ID = bytes.fromhex("939a7233f79c4ca9940a0db3957f0607")
# Tinfoil-conformance synthetic FMSPC and PCEID — not real Intel values.
SYNTH_FMSPC = bytes.fromhex("50806f000000")
SYNTH_PCEID = bytes.fromhex("0000")
# Intel SGX Extension OID parent and children (SPEC §4.6.1).
OID_SGX_EXT = "1.2.840.113741.1.13.1"
OID_PPID = "1.2.840.113741.1.13.1.1"
OID_TCB = "1.2.840.113741.1.13.1.2"
OID_PCEID = "1.2.840.113741.1.13.1.3"
OID_FMSPC = "1.2.840.113741.1.13.1.4"


# ---- DER encoding helpers (raw — cryptography doesn't expose Intel ext) -----


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _der_seq(content: bytes) -> bytes:
    return bytes([0x30]) + _der_len(len(content)) + content


def _der_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".")]
    first = parts[0] * 40 + parts[1]
    body = bytes([first])
    for p in parts[2:]:
        chunks = []
        chunks.append(p & 0x7F)
        p >>= 7
        while p:
            chunks.append(0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(reversed(chunks))
    return bytes([0x06]) + _der_len(len(body)) + body


def _der_int(n: int) -> bytes:
    if n == 0:
        return bytes([0x02, 0x01, 0x00])
    body = b""
    x = n
    while x:
        body = bytes([x & 0xFF]) + body
        x >>= 8
    # ASN.1 INTEGER is signed; prepend 0x00 if top bit set.
    if body[0] & 0x80:
        body = b"\x00" + body
    return bytes([0x02]) + _der_len(len(body)) + body


def _der_octet(b: bytes) -> bytes:
    return bytes([0x04]) + _der_len(len(b)) + b


# ---- Synth chain types -----------------------------------------------------


@dataclass
class SynthCert:
    cert: x509.Certificate
    key: P256KeyPair

    @property
    def pem(self) -> str:
        return self.cert.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)


@dataclass
class SynthChain:
    """The whole synthetic Intel-mimicking ecosystem for one fixture run."""
    root_ca: SynthCert            # "Intel SGX Root CA" (self-signed)
    platform_ca: SynthCert        # "Intel SGX PCK Platform CA"
    tcb_signer: SynthCert         # "Intel SGX TCB Signing"
    pck_leaf: SynthCert           # PCK leaf w/ Intel SGX OID extensions
    ak_key: P256KeyPair           # Attestation key (used to sign the quote)


def _build_self_signed_root(
    common_name: str,
    not_before: datetime,
    not_after: datetime,
) -> SynthCert:
    key = P256KeyPair.generate()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intel Corporation"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Santa Clara"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])
    spki_der = key.public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    ski = hashlib.sha1(spki_der).digest()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public)
        .serial_number(1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        # Real Intel SGX Root CA has these 5 extensions in this order.
        .add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=ski,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        )
        .add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(
                        "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"
                    )],
                    relative_name=None, reasons=None, crl_issuer=None,
                ),
            ]),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier(ski), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key.private, hashes.SHA256())
    )
    return SynthCert(cert=cert, key=key)


def _build_intermediate(
    issuer: SynthCert,
    common_name: str,
    not_before: datetime,
    not_after: datetime,
    *,
    is_ca: bool = True,
    extra_extensions: list[tuple[x509.ObjectIdentifier, bytes, bool]] | None = None,
) -> SynthCert:
    key = P256KeyPair.generate()
    # Compute Subject Key Identifier per RFC 5280 (SHA-1 of SPKI).
    spki_der = key.public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    ski = hashlib.sha1(spki_der).digest()
    issuer_spki_der = issuer.cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    aki = hashlib.sha1(issuer_spki_der).digest()

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intel Corporation"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Santa Clara"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]))
        .issuer_name(issuer.cert.subject)
        .public_key(key.public)
        .serial_number(int.from_bytes(hashlib.sha256(common_name.encode()).digest()[:8], "big"))
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        # Order matters — real Intel PCK leaf has AKI, CDP, SKI, KU, BC, SGX.
        .add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=aki,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        )
        .add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(
                        "https://certificates.trustedservices.intel.com/IntelSGXPCKPlatform.crl"
                    )],
                    relative_name=None, reasons=None, crl_issuer=None,
                ),
            ]),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier(ski), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=not is_ca, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=is_ca, crl_sign=is_ca, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    for oid, value, critical in (extra_extensions or []):
        builder = builder.add_extension(
            x509.UnrecognizedExtension(oid, value), critical=critical
        )
    cert = builder.sign(issuer.key.private, hashes.SHA256())
    return SynthCert(cert=cert, key=key)


def _build_pck_sgx_extension_value(
    *,
    ppid: bytes,
    cpu_svn: bytes,
    pce_svn: int,
    tcb_components: list[int],
    pceid: bytes,
    fmspc: bytes,
) -> bytes:
    """Build the raw DER bytes of the Intel SGX extension (OID 1.2.840.113741.1.13.1).

    Structure (per SPEC §4.6):
      SEQUENCE {
        SEQUENCE { OID PPID,  OCTET STRING ppid (16 bytes) }
        SEQUENCE { OID TCB,
          SEQUENCE {
            SEQUENCE { OID .2.1, INTEGER comp1 }
            ... 16 components
            SEQUENCE { OID .2.17, INTEGER pcesvn }
            SEQUENCE { OID .2.18, OCTET STRING cpu_svn (16 bytes) }
          }
        }
        SEQUENCE { OID PCEID, OCTET STRING pceid (2 bytes) }
        SEQUENCE { OID FMSPC, OCTET STRING fmspc (6 bytes) }
      }
    """
    assert len(ppid) == 16
    assert len(cpu_svn) == 16
    assert len(tcb_components) == 16
    assert len(pceid) == 2
    assert len(fmspc) == 6

    # PPID entry
    ppid_entry = _der_seq(_der_oid(OID_PPID) + _der_octet(ppid))

    # TCB sub-sequence
    tcb_inner = b""
    for i, comp in enumerate(tcb_components, start=1):
        tcb_inner += _der_seq(_der_oid(f"{OID_TCB}.{i}") + _der_int(comp))
    tcb_inner += _der_seq(_der_oid(f"{OID_TCB}.17") + _der_int(pce_svn))
    tcb_inner += _der_seq(_der_oid(f"{OID_TCB}.18") + _der_octet(cpu_svn))
    tcb_entry = _der_seq(_der_oid(OID_TCB) + _der_seq(tcb_inner))

    pceid_entry = _der_seq(_der_oid(OID_PCEID) + _der_octet(pceid))
    fmspc_entry = _der_seq(_der_oid(OID_FMSPC) + _der_octet(fmspc))

    return _der_seq(ppid_entry + tcb_entry + pceid_entry + fmspc_entry)


def build_synth_chain(
    *,
    cpu_svn: bytes = b"\x05\x05\x02\x02\x03\x01\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00",
    pce_svn: int = 11,
    tcb_components: list[int] | None = None,
    fmspc: bytes = SYNTH_FMSPC,
    pceid: bytes = SYNTH_PCEID,
    ppid: bytes = b"\x55" * 16,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> SynthChain:
    """Build a complete synthetic Intel-mimicking chain in one call."""
    if tcb_components is None:
        tcb_components = list(cpu_svn)
    if not_before is None:
        not_before = datetime(2023, 1, 1, tzinfo=timezone.utc)
    if not_after is None:
        not_after = datetime(2030, 1, 1, tzinfo=timezone.utc)

    nb = not_before.replace(tzinfo=None)
    na = not_after.replace(tzinfo=None)

    root = _build_self_signed_root("Intel SGX Root CA", nb, na)
    platform_ca = _build_intermediate(
        root, "Intel SGX PCK Platform CA", nb, na, is_ca=True
    )
    tcb_signer = _build_intermediate(
        root, "Intel SGX TCB Signing", nb, na, is_ca=False
    )
    pck_ext = _build_pck_sgx_extension_value(
        ppid=ppid, cpu_svn=cpu_svn, pce_svn=pce_svn,
        tcb_components=tcb_components, pceid=pceid, fmspc=fmspc,
    )
    pck_leaf = _build_intermediate(
        platform_ca, "Intel SGX PCK Certificate", nb, na, is_ca=False,
        extra_extensions=[
            (x509.ObjectIdentifier(OID_SGX_EXT), pck_ext, False),
        ],
    )
    ak = P256KeyPair.generate()
    return SynthChain(
        root_ca=root, platform_ca=platform_ca,
        tcb_signer=tcb_signer, pck_leaf=pck_leaf, ak_key=ak,
    )


# ---- TDX v4 quote builder --------------------------------------------------


def _raw_pubkey_xy(key: P256KeyPair) -> bytes:
    """Extract raw X||Y bytes (64 bytes total) from a P-256 pubkey."""
    raw = key.public.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    # Strip 0x04 prefix
    assert raw[0] == 0x04 and len(raw) == 65
    return raw[1:]


def _ecdsa_sign_raw(key: P256KeyPair, message: bytes) -> bytes:
    """Sign message with ECDSA-SHA256 and return raw R||S (64 bytes)."""
    der = key.private.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


@dataclass
class TdBodyFields:
    """Controllable TD Quote Body fields. Defaults give a 'clean' TD that
    passes Phase 4 policy checks too (DEBUG=0, RTMR3=0, no reserved bits)."""
    # SPEC §4.7.8 step 1: module id derived from byte[1]. Set to 3 →
    # synth TCB Info's tdxModuleIdentities entry is TDX_03 — matches.
    # SPEC §4.7.6 step 3: when byte[1]>0 (versioned module), bytes 0-1
    # are skipped in the TCB level comparison; byte[2]=5 then matches
    # the synth tcbLevel's tdxtcbcomponents[2].svn=5.
    tee_tcb_svn: bytes = b"\x00\x03\x05\x00" + b"\x00" * 12
    mr_seam: bytes = b"\xAA" * 48
    mr_signer_seam: bytes = b"\x00" * 48
    seam_attributes: bytes = b"\x00" * 8
    # Default to PKS=1 (matches the real testdata so existing fixtures pass).
    td_attributes: bytes = b"\x00\x00\x00\x40\x00\x00\x00\x00"
    xfam: bytes = b"\xE7\x1A\x06\x00\x00\x00\x00\x00"
    mr_td: bytes = b"\x11" * 48
    mr_config_id: bytes = b"\x00" * 48
    mr_owner: bytes = b"\x00" * 48
    mr_owner_config: bytes = b"\x00" * 48
    rtmr0: bytes = b"\x22" * 48
    rtmr1: bytes = b"\x33" * 48
    rtmr2: bytes = b"\x44" * 48
    rtmr3: bytes = b"\x00" * 48
    report_data: bytes = b"\x66" * 64

    def to_bytes(self) -> bytes:
        out = (
            self.tee_tcb_svn + self.mr_seam + self.mr_signer_seam
            + self.seam_attributes + self.td_attributes + self.xfam
            + self.mr_td + self.mr_config_id + self.mr_owner + self.mr_owner_config
            + self.rtmr0 + self.rtmr1 + self.rtmr2 + self.rtmr3
            + self.report_data
        )
        assert len(out) == 584, f"TD body must be 584 bytes, got {len(out)}"
        return out


def _build_qe_report(
    *,
    mrsigner: bytes,
    isv_prod_id: int,
    isv_svn: int,
    misc_select: int,
    attributes: bytes,
    ak_pubkey_raw: bytes,
    report_data: bytes | None = None,
) -> bytes:
    """Build a 384-byte SGX EnclaveReport (per §A.3.10). MRSIGNER is the
    field the QE Identity JSON validates against."""
    assert len(mrsigner) == 32
    assert len(attributes) == 16
    # ReportData = SHA-256(AK pubkey raw) ‖ 32 zero bytes — binds AK to QE.
    # Negative fixtures may override this while keeping the QE report
    # signature valid, isolating the AK-binding check from signature checks.
    if report_data is None:
        report_data = hashlib.sha256(ak_pubkey_raw).digest() + b"\x00" * 32
    assert len(report_data) == 64

    cpu_svn = b"\x00" * 16
    misc = struct.pack("<I", misc_select)
    reserved1 = b"\x00" * 28
    mr_enclave = b"\x77" * 32
    reserved2 = b"\x00" * 32
    reserved3 = b"\x00" * 96
    isv_prod_id_b = struct.pack("<H", isv_prod_id)
    isv_svn_b = struct.pack("<H", isv_svn)
    reserved4 = b"\x00" * 60

    body = (
        cpu_svn + misc + reserved1 + attributes + mr_enclave + reserved2
        + mrsigner + reserved3 + isv_prod_id_b + isv_svn_b + reserved4 + report_data
    )
    assert len(body) == 384, f"QE Report must be 384 bytes, got {len(body)}"
    return body


def build_tdx_quote_v4(
    chain: SynthChain,
    *,
    body: TdBodyFields | None = None,
    quote_signing_key: P256KeyPair | None = None,
    attestation_key: P256KeyPair | None = None,
    qe_mrsigner: bytes = b"\xDC" * 32,
    qe_isv_prod_id: int = 2,
    qe_isv_svn: int = 8,
    qe_misc_select: int = 0,
    qe_attributes: bytes = b"\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    qe_report_data: bytes | None = None,
) -> tuple[bytes, TdBodyFields]:
    """Pack a complete synthetic v4 TDX quote signed by chain.ak_key with
    PCK chain extracted from chain.pck_leaf → platform_ca → root_ca.

    Returns (raw_quote_bytes, body_fields_used)."""
    if body is None:
        body = TdBodyFields()

    # --- Header (48 bytes) per §A.3.1 ---
    header = (
        struct.pack("<H", 4)              # version
        + struct.pack("<H", 2)            # AKT = ECDSA-P-256
        + struct.pack("<I", 0x81)         # TEE Type = TDX
        + b"\x00\x00"                     # RESERVED1
        + b"\x00\x00"                     # RESERVED2
        + INTEL_QE_VENDOR_ID              # 16 bytes
        + b"\x00" * 20                    # User Data
    )
    assert len(header) == 48

    body_bytes = body.to_bytes()
    signed_region = header + body_bytes

    # --- Quote signature: AK signs SHA-256(header || body) ---
    signing_key = quote_signing_key or chain.ak_key
    embedded_key = attestation_key or chain.ak_key
    quote_sig_raw = _ecdsa_sign_raw(signing_key, signed_region)
    ak_pubkey_raw = _raw_pubkey_xy(embedded_key)

    # --- QE Report (384 bytes) ---
    qe_report = _build_qe_report(
        mrsigner=qe_mrsigner,
        isv_prod_id=qe_isv_prod_id,
        isv_svn=qe_isv_svn,
        misc_select=qe_misc_select,
        attributes=qe_attributes,
        ak_pubkey_raw=ak_pubkey_raw,
        report_data=qe_report_data,
    )

    # --- QE Report signature: PCK leaf signs the QE Report ---
    qe_report_sig_raw = _ecdsa_sign_raw(chain.pck_leaf.key, qe_report)

    # --- QE Auth Data (variable, can be 0 bytes) ---
    qe_auth_data = b""
    qe_auth_data_section = struct.pack("<H", len(qe_auth_data)) + qe_auth_data

    # --- QE Certification Data type 5: Concatenated PCK Cert Chain (PEM) ---
    pck_chain_pem = (
        chain.pck_leaf.pem.encode()
        + chain.platform_ca.pem.encode()
        + chain.root_ca.pem.encode()
    )
    qe_inner_cert_section = (
        struct.pack("<H", 5)                            # Cert Data Type 5
        + struct.pack("<I", len(pck_chain_pem))         # Cert Data Size
        + pck_chain_pem                                 # Concatenated PEM
    )

    # --- QE Report Certification Data (Type 6 wrapper, §A.3.11) ---
    qe_report_cert_data = (
        qe_report + qe_report_sig_raw
        + qe_auth_data_section
        + qe_inner_cert_section
    )

    qe_cert_data_section = (
        struct.pack("<H", 6)                            # Cert Data Type 6
        + struct.pack("<I", len(qe_report_cert_data))
        + qe_report_cert_data
    )

    # --- Quote Signature Data Structure v4 (§A.3.8) ---
    quote_sig_data = (
        quote_sig_raw + ak_pubkey_raw + qe_cert_data_section
    )

    # --- Full quote ---
    full = (
        header + body_bytes
        + struct.pack("<I", len(quote_sig_data))
        + quote_sig_data
    )
    return full, body


# ---- TCB Info / QE Identity / CRL builders ---------------------------------


def _sign_intel_pcs_response(
    inner_dict: dict[str, Any], outer_key: str, signer: SynthCert,
) -> str:
    """Build an Intel-PCS-shaped {outer_key: {...}, signature: hex} response.

    Intel's verification reads the EXACT bytes of the inner JSON (per SPEC
    §4.7.3 step 1). The inner dict gets canonical-encoded once, and that
    byte string is what gets signed; the outer string embeds those exact
    bytes via raw assembly."""
    # Use compact JSON for the inner so the signed bytes are deterministic.
    inner_bytes = json.dumps(inner_dict, separators=(",", ":")).encode()
    digest = hashlib.sha256(inner_bytes).digest()
    sig_raw = _ecdsa_sign_raw(signer.key, inner_bytes)  # uses prehashed-style
    # Note: we passed the already-built byte string into _ecdsa_sign_raw,
    # which itself does SHA-256 internally. That matches go-tdx-guest's
    # verification path: it computes SHA-256 over the raw inner bytes and
    # verifies the signature against that digest.
    _ = digest  # documentation only
    return (
        '{"' + outer_key + '":'
        + inner_bytes.decode()
        + ',"signature":"' + sig_raw.hex() + '"}'
    )


def build_tcb_info_response(
    chain: SynthChain,
    *,
    tcb_levels: list[dict[str, Any]],
    fmspc: str = "50806f000000",
    issue_date: str = "2023-06-18T08:42:58Z",
    next_update: str = "2030-07-18T08:42:58Z",
    tcb_evaluation_data_number: int = 18,
    mr_seam: bytes = b"\xAA" * 48,
) -> str:
    """Return the raw JSON body of a synthetic TCB Info response."""
    tcb_info = {
        "id": "TDX",
        "version": 3,
        "issueDate": issue_date,
        "nextUpdate": next_update,
        "fmspc": fmspc,
        "pceId": "0000",
        "tcbType": 0,
        "tcbEvaluationDataNumber": tcb_evaluation_data_number,
        "tdxModule": {
            "mrsigner": "00" * 48,
            "attributes": "0000000000000000",
            "attributesMask": "FFFFFFFFFFFFFFFF",
        },
        "tdxModuleIdentities": [
            {
                "id": "TDX_03",
                "mrsigner": "00" * 48,
                "attributes": "0000000000000000",
                "attributesMask": "FFFFFFFFFFFFFFFF",
                "tcbLevels": [{"tcb": {"isvsvn": 0}, "tcbDate": issue_date,
                               "tcbStatus": "UpToDate"}],
            },
        ],
        "tcbLevels": tcb_levels,
    }
    return _sign_intel_pcs_response(tcb_info, "tcbInfo", chain.tcb_signer)


def build_qe_identity_response(
    chain: SynthChain,
    *,
    mrsigner_hex: str,
    isv_prod_id: int,
    isv_svn: int,
    identity_id: str = "TD_QE",
    version: int = 2,
    issue_date: str = "2023-06-08T07:24:59Z",
    next_update: str = "2030-07-08T07:24:59Z",
    tcb_evaluation_data_number: int = 18,
    tcb_status: str = "UpToDate",
) -> str:
    qe_identity = {
        "id": identity_id,
        "version": version,
        "issueDate": issue_date,
        "nextUpdate": next_update,
        "tcbEvaluationDataNumber": tcb_evaluation_data_number,
        "miscselect": "00000000",
        "miscselectMask": "FFFFFFFF",
        "attributes": "11000000000000000000000000000000",
        "attributesMask": "FBFFFFFFFFFFFFFF0000000000000000",
        "mrsigner": mrsigner_hex.upper(),
        "isvprodid": isv_prod_id,
        "tcbLevels": [{
            "tcb": {"isvsvn": isv_svn},
            "tcbDate": issue_date,
            "tcbStatus": tcb_status,
        }],
    }
    return _sign_intel_pcs_response(qe_identity, "enclaveIdentity", chain.tcb_signer)


def build_empty_crl(issuer: SynthCert,
                    *,
                    not_before: datetime | None = None,
                    not_after: datetime | None = None,
                    revoked_certs: list[SynthCert] | None = None) -> bytes:
    """An empty X.509 CRL signed by `issuer`. DER bytes."""
    if not_before is None:
        not_before = datetime(2023, 1, 1, tzinfo=timezone.utc)
    if not_after is None:
        not_after = datetime(2030, 1, 1, tzinfo=timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.cert.subject)
        .last_update(not_before.replace(tzinfo=None))
        .next_update(not_after.replace(tzinfo=None))
    )
    for revoked_cert in revoked_certs or []:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(revoked_cert.cert.serial_number)
            .revocation_date(not_before.replace(tzinfo=None))
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)
    crl = builder.sign(issuer.key.private, hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.DER)


# ---- Issuer chain header builders ------------------------------------------

def url_encoded_pem_chain(*certs: SynthCert) -> str:
    """Build the URL-encoded concatenated PEM that go-tdx-guest's getter
    headers carry (per SPEC §4.7.1)."""
    import urllib.parse
    pem = "".join(c.pem for c in certs)
    return urllib.parse.quote(pem)


__all__ = [
    "SynthChain", "SynthCert", "TdBodyFields",
    "build_synth_chain", "build_tdx_quote_v4",
    "build_tcb_info_response", "build_qe_identity_response",
    "build_empty_crl", "url_encoded_pem_chain",
]
