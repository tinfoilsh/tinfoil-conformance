"""SEV-SNP synthetic chain library.

Builds a complete ARK → ASK → VCEK certificate chain plus a 1184-byte SEV-SNP
v3 attestation report signed under that chain. Used by Phase 4B-SEV fixtures
where signature verification must succeed but a normative policy check
(§3.7 DEBUG bit, reserved bits, MIGRATE_MA, etc.) must reject.

Approach mirrors fixturegen/lib/tdx_synth.py:
  - All three keys are ECDSA P-384 with SHA-384 signatures.
  - VCEK carries the AMD-spec'd X.509v3 extensions (OIDs under
    1.3.6.1.4.1.3704.1) so go-sev-guest's TCB-vs-extension cross-check
    passes when the report's reported_tcb matches the cert's SPL extensions.
  - HWID extension encodes the report's chip_id raw (no inner DER tag).
  - Report body is built by overriding fields on a real-bundle template
    so the spec-mandated MBZ ranges and v3 layout stay correct.
  - Report signature: ECDSA(SHA-384) over bytes [0..0x2A0); written into
    bytes [0x2A0..0x4A0) in AMD's little-endian-padded format (72-byte R,
    72-byte S, 368-byte reserved).

The conformance binaries accept the synthetic ARK + ASK via
input.amd_root_ca_pem / input.ask_pem (Go: TrustedRoots; Python:
monkey-patches ARK_CERT/ASK_CERT constants; JS doesn't support injection
and Phase 4B-SEV fixtures skip cleanly there).
"""

from __future__ import annotations

import base64
import gzip
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID, ObjectIdentifier

# ---- AMD KDS extension OIDs (from go-sev-guest/kds/kds.go) -----------------

OID_STRUCT_VERSION = ObjectIdentifier("1.3.6.1.4.1.3704.1.1")
OID_PRODUCT_NAME = ObjectIdentifier("1.3.6.1.4.1.3704.1.2")
OID_BL_SPL = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.1")
OID_TEE_SPL = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.2")
OID_SNP_SPL = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.3")
OID_SPL4 = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.4")
OID_SPL5 = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.5")
OID_SPL6 = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.6")
OID_SPL7 = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.7")
OID_UCODE_SPL = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.8")
OID_HWID = ObjectIdentifier("1.3.6.1.4.1.3704.1.4")


# ---- DER encoding helpers --------------------------------------------------

def _enc_int(n: int) -> bytes:
    """DER-encode an INTEGER. Returns the full TLV (tag+len+value)."""
    if n == 0:
        return bytes([0x02, 0x01, 0x00])
    body = n.to_bytes((n.bit_length() + 8) // 8, "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return bytes([0x02, len(body)]) + body


def _enc_ia5(s: str) -> bytes:
    """DER-encode an IA5String TLV."""
    raw = s.encode("ascii")
    return bytes([0x16, len(raw)]) + raw


# ---- Chain + report types --------------------------------------------------

@dataclass
class TcbParts:
    bl_spl: int = 7
    tee_spl: int = 0
    snp_spl: int = 14
    ucode_spl: int = 72
    spl4: int = 0
    spl5: int = 0
    spl6: int = 0
    spl7: int = 0

    def to_u64(self) -> int:
        return (
            (self.ucode_spl << 56)
            | (self.snp_spl << 48)
            | (self.spl7 << 40)
            | (self.spl6 << 32)
            | (self.spl5 << 24)
            | (self.spl4 << 16)
            | (self.tee_spl << 8)
            | self.bl_spl
        )


@dataclass
class SynthChain:
    # Real AMD chain: ARK + ASK are RSA-4096 with PSS+SHA384; VCEK key is
    # ECDSA P-384 (used to sign the report). Mirror that here so
    # go-sev-guest's signature-algorithm check on the cert chain accepts.
    ark_priv: rsa.RSAPrivateKey
    ark_cert: x509.Certificate
    ask_priv: rsa.RSAPrivateKey
    ask_cert: x509.Certificate
    vcek_priv: ec.EllipticCurvePrivateKey
    vcek_cert: x509.Certificate

    @property
    def ark_pem(self) -> str:
        return self.ark_cert.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def ask_pem(self) -> str:
        return self.ask_cert.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def vcek_der(self) -> bytes:
        return self.vcek_cert.public_bytes(serialization.Encoding.DER)

    @property
    def vcek_der_b64(self) -> str:
        return base64.standard_b64encode(self.vcek_der).decode()


# ---- Chain generation ------------------------------------------------------

# Validity window long enough to cover any realistic fixture verification time.
_NOT_BEFORE = datetime(2020, 1, 1, tzinfo=timezone.utc)
_NOT_AFTER = datetime(2099, 1, 1, tzinfo=timezone.utc)

# Common AMD-style name attributes used in all three cert subjects.
_AMD_BASE_NAME_ATTRS = [
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Engineering"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Santa Clara"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Advanced Micro Devices"),
]


def _amd_name(cn: str) -> x509.Name:
    return x509.Name(_AMD_BASE_NAME_ATTRS + [x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def gen_synth_chain(
    *,
    chip_id: bytes,
    tcb: TcbParts,
    not_before: Optional[datetime] = None,
    not_after: Optional[datetime] = None,
    vcek_extension_omit: Optional[set[ObjectIdentifier]] = None,
    vcek_extension_overrides: Optional[dict[ObjectIdentifier, bytes]] = None,
) -> SynthChain:
    """Generate a complete ARK → ASK → VCEK chain.

    vcek_extension_omit / vcek_extension_overrides let Phase 4B-SEV fixtures
    test VCEK_TCB_MISMATCH, VCEK_HWID_MISMATCH, or missing-extension paths
    by skipping specific OIDs or pinning intentionally-wrong values.
    """
    nb = not_before or _NOT_BEFORE
    na = not_after or _NOT_AFTER
    assert len(chip_id) == 64, "chip_id must be 64 bytes for Genoa"
    omit = vcek_extension_omit or set()
    overrides = vcek_extension_overrides or {}

    ark_priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    ask_priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    vcek_priv = ec.generate_private_key(ec.SECP384R1())

    # ARK + ASK are signed with RSA-PSS + SHA-384 (matches real AMD chain).
    pss_sha384 = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)

    ark_name = _amd_name("ARK-Genoa")
    ask_name = _amd_name("SEV-Genoa")
    vcek_name = _amd_name("SEV-VCEK")

    ark_cert = (
        x509.CertificateBuilder()
        .subject_name(ark_name)
        .issuer_name(ark_name)
        .public_key(ark_priv.public_key())
        .serial_number(1)
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ark_priv, hashes.SHA384(), rsa_padding=pss_sha384)
    )

    ask_cert = (
        x509.CertificateBuilder()
        .subject_name(ask_name)
        .issuer_name(ark_name)
        .public_key(ask_priv.public_key())
        .serial_number(2)
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ark_priv, hashes.SHA384(), rsa_padding=pss_sha384)
    )

    # AMD-spec'd VCEK extensions. Values are wrapped TLVs except HWID which
    # is the raw 64-byte chip_id with no inner DER tag.
    default_ext_values: dict[ObjectIdentifier, bytes] = {
        OID_STRUCT_VERSION: _enc_int(0),
        OID_PRODUCT_NAME: _enc_ia5("Genoa"),
        OID_BL_SPL: _enc_int(tcb.bl_spl),
        OID_TEE_SPL: _enc_int(tcb.tee_spl),
        OID_SNP_SPL: _enc_int(tcb.snp_spl),
        OID_SPL4: _enc_int(tcb.spl4),
        OID_SPL5: _enc_int(tcb.spl5),
        OID_SPL6: _enc_int(tcb.spl6),
        OID_SPL7: _enc_int(tcb.spl7),
        OID_UCODE_SPL: _enc_int(tcb.ucode_spl),
        OID_HWID: chip_id,
    }
    builder = (
        x509.CertificateBuilder()
        .subject_name(vcek_name)
        .issuer_name(ask_name)
        .public_key(vcek_priv.public_key())
        .serial_number(3)
        .not_valid_before(nb)
        .not_valid_after(na)
    )
    for oid, value in default_ext_values.items():
        if oid in omit:
            continue
        v = overrides.get(oid, value)
        builder = builder.add_extension(x509.UnrecognizedExtension(oid, v), critical=False)
    vcek_cert = builder.sign(ask_priv, hashes.SHA384(), rsa_padding=pss_sha384)

    return SynthChain(
        ark_priv=ark_priv,
        ark_cert=ark_cert,
        ask_priv=ask_priv,
        ask_cert=ask_cert,
        vcek_priv=vcek_priv,
        vcek_cert=vcek_cert,
    )


# ---- Report builder + signer -----------------------------------------------

# Real-bundle template — gives us correct v3 layout including all MBZ bytes.
_BASE_BUNDLE_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "vectors" / "attestation-sev" / "_assets" / "real_genoa_bundle.json"
)


def _load_base_report() -> bytes:
    import json
    bundle = json.loads(_BASE_BUNDLE_PATH.read_text())
    return gzip.decompress(base64.standard_b64decode(bundle["enclaveAttestationReport"]["body"]))


@dataclass
class ReportFields:
    """Subset of SEV-SNP v3 report fields commonly tampered for tests.
    Any field left at None inherits the real-bundle template's value, so
    spec-mandated MBZ ranges stay intact."""
    version: Optional[int] = None
    guest_svn: Optional[int] = None
    policy: Optional[int] = None
    family_id: Optional[bytes] = None
    image_id: Optional[bytes] = None
    vmpl: Optional[int] = None
    signature_algo: Optional[int] = None
    current_tcb: Optional[int] = None
    platform_info: Optional[int] = None
    signer_info: Optional[int] = None
    report_data: Optional[bytes] = None
    measurement: Optional[bytes] = None
    host_data: Optional[bytes] = None
    id_key_digest: Optional[bytes] = None
    author_key_digest: Optional[bytes] = None
    report_id: Optional[bytes] = None
    reported_tcb: Optional[int] = None
    chip_id: Optional[bytes] = None


def _put_u32_le(b: bytearray, off: int, val: int) -> None:
    b[off:off + 4] = val.to_bytes(4, "little")


def _put_u64_le(b: bytearray, off: int, val: int) -> None:
    b[off:off + 8] = val.to_bytes(8, "little")


def _put_bytes(b: bytearray, off: int, val: bytes, expected_len: int) -> None:
    assert len(val) == expected_len, f"expected {expected_len} bytes, got {len(val)}"
    b[off:off + expected_len] = val


def build_report_body(fields: ReportFields, *, base: Optional[bytes] = None) -> bytes:
    """Build a 0x2A0-byte (672) signed-region body. The trailing 512-byte
    signature region is appended by sign_report()."""
    template = base if base is not None else _load_base_report()
    assert len(template) >= 0x2A0
    body = bytearray(template[:0x2A0])

    if fields.version is not None:
        _put_u32_le(body, 0x00, fields.version)
    if fields.guest_svn is not None:
        _put_u32_le(body, 0x04, fields.guest_svn)
    if fields.policy is not None:
        _put_u64_le(body, 0x08, fields.policy)
    if fields.family_id is not None:
        _put_bytes(body, 0x10, fields.family_id, 16)
    if fields.image_id is not None:
        _put_bytes(body, 0x20, fields.image_id, 16)
    if fields.vmpl is not None:
        _put_u32_le(body, 0x30, fields.vmpl)
    if fields.signature_algo is not None:
        _put_u32_le(body, 0x34, fields.signature_algo)
    if fields.current_tcb is not None:
        _put_u64_le(body, 0x38, fields.current_tcb)
    if fields.platform_info is not None:
        _put_u64_le(body, 0x40, fields.platform_info)
    if fields.signer_info is not None:
        _put_u32_le(body, 0x48, fields.signer_info)
    if fields.report_data is not None:
        _put_bytes(body, 0x50, fields.report_data, 64)
    if fields.measurement is not None:
        _put_bytes(body, 0x90, fields.measurement, 48)
    if fields.host_data is not None:
        _put_bytes(body, 0xC0, fields.host_data, 32)
    if fields.id_key_digest is not None:
        _put_bytes(body, 0xE0, fields.id_key_digest, 48)
    if fields.author_key_digest is not None:
        _put_bytes(body, 0x110, fields.author_key_digest, 48)
    if fields.report_id is not None:
        _put_bytes(body, 0x140, fields.report_id, 32)
    if fields.reported_tcb is not None:
        _put_u64_le(body, 0x180, fields.reported_tcb)
    if fields.chip_id is not None:
        _put_bytes(body, 0x1A0, fields.chip_id, 64)
    return bytes(body)


def _amd_signature_field(sig_der: bytes) -> bytes:
    """Translate cryptography's DER ECDSA signature to AMD's 512-byte
    little-endian-padded layout: R(72) || S(72) || reserved(368)."""
    r, s = decode_dss_signature(sig_der)
    r_be = r.to_bytes(48, "big")
    s_be = s.to_bytes(48, "big")
    r_le_padded = r_be[::-1] + b"\x00" * 24
    s_le_padded = s_be[::-1] + b"\x00" * 24
    sig_field = r_le_padded + s_le_padded + b"\x00" * 368
    assert len(sig_field) == 512
    return sig_field


def sign_report(body: bytes, vcek_priv: ec.EllipticCurvePrivateKey) -> bytes:
    """Sign the 0x2A0-byte body with vcek_priv; return the full 1184-byte report."""
    assert len(body) == 0x2A0
    sig_der = vcek_priv.sign(body, ec.ECDSA(hashes.SHA384()))
    sig_field = _amd_signature_field(sig_der)
    full = body + sig_field
    assert len(full) == 1184
    return full


def gzip_b64(report_bytes: bytes) -> str:
    return base64.standard_b64encode(gzip.compress(report_bytes)).decode()


# ---- Chain persistence ------------------------------------------------------
# The chain is heavy (4096-bit RSA keys) and must stay constant across
# fixturegen runs so fixtures are reproducible. Persist to _assets/.

_DEFAULT_SYNTH_DIR = (
    Path(__file__).resolve().parent.parent.parent
    / "vectors" / "attestation-sev" / "_assets" / "synth_chain"
)

# Deterministic synth chip_id — flagged in fixtures as the "Phase 4B synth
# machine" so it never collides with a real chip in cross-table lookups.
SYNTH_CHIP_ID = bytes.fromhex(
    "5e7053796e7468436861696e" + "aa" * 52
)
assert len(SYNTH_CHIP_ID) == 64

# Match the real bundle's TCB so cert-vs-report TCB check passes and the
# committed_tcb / launch_tcb template bytes don't need synthesizing.
SYNTH_TCB = TcbParts(bl_spl=10, tee_spl=0, snp_spl=23, ucode_spl=84)


def load_or_create_synth_chain(persist_dir: Path = _DEFAULT_SYNTH_DIR) -> SynthChain:
    """Load a persisted synth chain from disk; generate + persist if missing.

    Persisting the chain keeps Phase 4B-SEV fixture inputs stable across
    fixturegen runs. (Report ECDSA signatures still vary run-to-run because
    cryptography doesn't ship deterministic ECDSA out of the box, but the
    cert chain bytes — which dominate fixture size — stay byte-for-byte
    identical.)"""
    ark_pem_path = persist_dir / "ark.pem"
    ask_pem_path = persist_dir / "ask.pem"
    vcek_cert_der_path = persist_dir / "vcek_cert.der"
    vcek_priv_pem_path = persist_dir / "vcek_priv.pem"

    if all(p.exists() for p in (ark_pem_path, ask_pem_path, vcek_cert_der_path, vcek_priv_pem_path)):
        ark_cert = x509.load_pem_x509_certificate(ark_pem_path.read_bytes())
        ask_cert = x509.load_pem_x509_certificate(ask_pem_path.read_bytes())
        vcek_cert = x509.load_der_x509_certificate(vcek_cert_der_path.read_bytes())
        vcek_priv = serialization.load_pem_private_key(vcek_priv_pem_path.read_bytes(), password=None)
        # ARK + ASK private keys aren't needed once the chain is signed; we
        # only need to re-sign the VCEK->report signature each fixture run.
        # Synthesize placeholder keys so the dataclass stays well-formed.
        ark_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ask_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return SynthChain(
            ark_priv=ark_priv,
            ark_cert=ark_cert,
            ask_priv=ask_priv,
            ask_cert=ask_cert,
            vcek_priv=vcek_priv,
            vcek_cert=vcek_cert,
        )

    persist_dir.mkdir(parents=True, exist_ok=True)
    chain = gen_synth_chain(chip_id=SYNTH_CHIP_ID, tcb=SYNTH_TCB)
    ark_pem_path.write_text(chain.ark_pem)
    ask_pem_path.write_text(chain.ask_pem)
    vcek_cert_der_path.write_bytes(chain.vcek_der)
    vcek_priv_pem_path.write_bytes(chain.vcek_priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return chain
