#!/usr/bin/env python3
"""Synthetic AMD SEV-SNP stack for v3 QUOTE-SEV conformance fixtures.

Mints an ARK -> ASK -> VCEK chain and a signed SEV-SNP attestation report + CRL
that pass tinfoil-go's quote/sev.AuthenticateWithRoot -> google go-sev-guest
verify.SnpAttestation. Everything is deterministic enough to regenerate on demand
(EC keys from fixed scalars; RSA keys generated once per process).

Gotchas baked in (see the synthetic-sev-generator memory):
  * go-sev-guest ENFORCES SHA384-with-RSASSA-PSS on ARK/ASK/VCEK certs, so every
    RSA signature uses rsa_padding=PSS. cryptography's default is PKCS#1 v1.5.
  * The report signature is ECDSA P-384 over SHA-384 of report[:0x2A0], stored as
    r then s, each the 48-byte component LITTLE-ENDIAN zero-padded into 72 bytes.
  * VCEK carries AMD custom extensions (OIDs 1.3.6.1.4.1.3704.1.x) whose TCB SPLs
    and HWID must agree with the report's reported_tcb and chip_id.
  * Report version must be >= 3 and carry a Genoa CPUID (family 0x19, model 0x11)
    or productFromReport / the trusted-root lookup fails.
"""

import datetime
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID, ObjectIdentifier

REPORT_SIZE = 0x4A0          # 1184 bytes
SIGNATURE_OFFSET = 0x2A0
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=padding.PSS.DIGEST_LENGTH)

# AMD KDS VCEK extension OIDs (go-sev-guest kds package).
OID_STRUCT_VERSION = ObjectIdentifier("1.3.6.1.4.1.3704.1.1")
OID_PRODUCT_NAME = ObjectIdentifier("1.3.6.1.4.1.3704.1.2")
OID_HWID = ObjectIdentifier("1.3.6.1.4.1.3704.1.4")
OID_SPL = {  # minor -> OID under 1.3.6.1.4.1.3704.1.3.x
    "bl": ObjectIdentifier("1.3.6.1.4.1.3704.1.3.1"),
    "tee": ObjectIdentifier("1.3.6.1.4.1.3704.1.3.2"),
    "snp": ObjectIdentifier("1.3.6.1.4.1.3704.1.3.3"),
    "spl4": ObjectIdentifier("1.3.6.1.4.1.3704.1.3.4"),
    "spl5": ObjectIdentifier("1.3.6.1.4.1.3704.1.3.5"),
    "spl6": ObjectIdentifier("1.3.6.1.4.1.3704.1.3.6"),
    "spl7": ObjectIdentifier("1.3.6.1.4.1.3704.1.3.7"),
    "ucode": ObjectIdentifier("1.3.6.1.4.1.3704.1.3.8"),
}

PRODUCT_NAME = "Genoa-B0"
GENOA_FMS = (0x19, 0x11, 0x00)  # family, model, stepping

BASE_TIME = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
NOT_BEFORE = BASE_TIME - datetime.timedelta(days=1)
NOT_AFTER = BASE_TIME + datetime.timedelta(days=3650)

# A representative Genoa TCB; the same parts go into the VCEK extensions and the
# report's TCB fields so they agree.
TCB = {"bl": 7, "tee": 0, "snp": 20, "spl4": 0, "spl5": 0, "spl6": 0, "spl7": 0, "ucode": 72}

_LEAF_SCALAR = 0x6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A
_ark_key = None
_ask_key = None


# --- DER helpers for the raw extension values ------------------------------
def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_tlv(tag, val):
    return bytes([tag]) + _der_len(len(val)) + val


def _der_integer(n):
    content = b"\x00" if n == 0 else n.to_bytes(n.bit_length() // 8 + 1, "big")
    return _der_tlv(0x02, content)


def _der_ia5(s):
    return _der_tlv(0x16, s.encode())


def _der_octet_string(b):
    return _der_tlv(0x04, b)


def compose_tcb(parts):
    return (
        (parts["ucode"] << 56) | (parts["snp"] << 48) | (parts["spl7"] << 40)
        | (parts["spl6"] << 32) | (parts["spl5"] << 24) | (parts["spl4"] << 16)
        | (parts["tee"] << 8) | parts["bl"]
    )


def _rsa4096():
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def _keys():
    global _ark_key, _ask_key
    if _ark_key is None:
        _ark_key = _rsa4096()
        _ask_key = _rsa4096()
    return _ark_key, _ask_key


# AMD KDS mandates these exact subject/issuer location fields on every cert.
_AMD_LOCATION = [
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Santa Clara"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Advanced Micro Devices"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Engineering"),
]
CRL_URL = "https://kdsintf.amd.com/vcek/v1/Genoa/crl"


def _name(cn):
    return x509.Name(_AMD_LOCATION + [x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _crl_dp():
    return x509.CRLDistributionPoints([x509.DistributionPoint(
        full_name=[x509.UniformResourceIdentifier(CRL_URL)],
        relative_name=None, reasons=None, crl_issuer=None)])


# --- AMD certificate chain (all RSA-PSS) -----------------------------------
def _ca_certs(ark_key, ask_key):
    ark_name, ask_name = _name("ARK-Genoa"), _name("SEV-Genoa")
    ark = (
        x509.CertificateBuilder()
        .subject_name(ark_name).issuer_name(ark_name)
        .public_key(ark_key.public_key()).serial_number(1)
        .not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(_crl_dp(), critical=False)
        .sign(ark_key, hashes.SHA384(), rsa_padding=PSS)
    )
    ask = (
        x509.CertificateBuilder()
        .subject_name(ask_name).issuer_name(ark_name)
        .public_key(ask_key.public_key()).serial_number(2)
        .not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_crl_dp(), critical=False)
        .sign(ark_key, hashes.SHA384(), rsa_padding=PSS)
    )
    return ark, ask


def rogue_anchor():
    """An unrelated ARK+ASK chain, for the wrong-root case (S26): pinning it as
    the anchor while the report chains to the real ARK breaks chain building."""
    ark, ask = _ca_certs(_rsa4096(), _rsa4096())
    return _pem(ark), _pem(ask)


def _build_chain(vcek_key, tcb_parts, hwid):
    ark_key, ask_key = _keys()
    ask_name = _name("SEV-Genoa")
    ark, ask = _ca_certs(ark_key, ask_key)

    exts = [
        x509.UnrecognizedExtension(OID_STRUCT_VERSION, _der_integer(0)),
        x509.UnrecognizedExtension(OID_PRODUCT_NAME, _der_ia5(PRODUCT_NAME)),
        x509.UnrecognizedExtension(OID_HWID, _der_octet_string(hwid)),
    ]
    for key, oid in OID_SPL.items():
        exts.append(x509.UnrecognizedExtension(oid, _der_integer(tcb_parts[key])))

    vcek_builder = (
        x509.CertificateBuilder()
        .subject_name(_name("SEV-VCEK")).issuer_name(ask_name)
        .public_key(vcek_key.public_key()).serial_number(3)
        .not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER)
    )
    for e in exts:
        vcek_builder = vcek_builder.add_extension(e, critical=False)
    vcek = vcek_builder.sign(ask_key, hashes.SHA384(), rsa_padding=PSS)
    return ark, ask, vcek


def _build_crl(revoke_serial=None, expired=False):
    ark_key, _ = _keys()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(_name("ARK-Genoa"))
        .last_update(NOT_BEFORE)
        .next_update(NOT_BEFORE + datetime.timedelta(days=1) if expired else NOT_AFTER)
    )
    if revoke_serial is not None:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(revoke_serial).revocation_date(NOT_BEFORE).build())
    return builder.sign(ark_key, hashes.SHA384(), rsa_padding=PSS)


# --- SEV-SNP report --------------------------------------------------------
def _build_report(report_data, measurement, chip_id, tcb_parts, policy, host_data,
                  version, signer_info, fms, guest_svn, vmpl, family_id, image_id,
                  id_key_digest, report_id, report_id_ma):
    r = bytearray(REPORT_SIZE)
    struct.pack_into("<I", r, 0x00, version)                 # version
    struct.pack_into("<I", r, 0x04, guest_svn)               # guest_svn
    struct.pack_into("<Q", r, 0x08, policy)                  # guest policy
    r[0x10:0x20] = family_id
    r[0x20:0x30] = image_id
    struct.pack_into("<I", r, 0x30, vmpl)                    # vmpl
    struct.pack_into("<I", r, 0x34, 1)                       # signature algo = ECDSA P-384
    tcb = compose_tcb(tcb_parts)
    struct.pack_into("<Q", r, 0x38, tcb)                     # current_tcb
    struct.pack_into("<Q", r, 0x40, 0)                       # platform_info
    struct.pack_into("<I", r, 0x48, signer_info)             # signer_info
    r[0x50:0x90] = report_data
    r[0x90:0xC0] = measurement
    r[0xC0:0xE0] = host_data
    r[0xE0:0x110] = id_key_digest
    r[0x140:0x160] = report_id
    r[0x160:0x180] = report_id_ma
    struct.pack_into("<Q", r, 0x180, tcb)                   # reported_tcb
    r[0x188], r[0x189], r[0x18A] = fms
    r[0x1A0:0x1E0] = chip_id
    struct.pack_into("<Q", r, 0x1E0, tcb)                   # committed_tcb
    r[0x1E8], r[0x1E9], r[0x1EA] = 21, 55, 1                 # current build/minor/major (1.55.21)
    r[0x1EC], r[0x1ED], r[0x1EE] = 21, 55, 1                 # committed build/minor/major
    struct.pack_into("<Q", r, 0x1F0, tcb)                   # launch_tcb
    return r


def _sign_report(r, vcek_key):
    sig = vcek_key.sign(bytes(r[:SIGNATURE_OFFSET]), ec.ECDSA(hashes.SHA384()))
    r_int, s_int = decode_dss_signature(sig)
    r[SIGNATURE_OFFSET:SIGNATURE_OFFSET + 48] = r_int.to_bytes(48, "little")
    r[SIGNATURE_OFFSET + 0x48:SIGNATURE_OFFSET + 0x48 + 48] = s_int.to_bytes(48, "little")
    return bytes(r)


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def build_sev(report_data=b"\x00" * 64, measurement=b"\xaa" * 48, chip_id=b"\x11" * 64,
              tcb_parts=None, vcek_tcb_parts=None, policy=0x30000, host_data=b"\x00" * 32,
              tamper_report_sig=False, version=3, signer_info=0, fms=GENOA_FMS,
              vcek_hwid=None, revoke_ask=False, crl_expired=False,
              guest_svn=0, vmpl=0, family_id=b"\x00" * 16, image_id=b"\x00" * 16,
              id_key_digest=b"\x00" * 48, report_id=b"\x00" * 32, report_id_ma=b"\x00" * 32):
    """Return the pieces for a v3 SEV cpu_evidence + collateral + anchor.

    tcb_parts sets the report's TCB; vcek_tcb_parts (defaults to tcb_parts) sets
    the VCEK extension TCB; vcek_hwid (defaults to chip_id) sets the VCEK HWID
    extension — split so mutations can make the VCEK disagree with the report.
    """
    tcb_parts = tcb_parts or dict(TCB)
    vcek_tcb_parts = vcek_tcb_parts or tcb_parts
    vcek_key = ec.derive_private_key(_LEAF_SCALAR, ec.SECP384R1())
    ark, ask, vcek = _build_chain(vcek_key, vcek_tcb_parts, vcek_hwid or chip_id)

    r = _build_report(report_data, measurement, chip_id, tcb_parts, policy, host_data,
                      version, signer_info, fms, guest_svn, vmpl, family_id, image_id,
                      id_key_digest, report_id, report_id_ma)
    _sign_report(r, vcek_key)
    if tamper_report_sig:
        r = bytearray(r)
        r[SIGNATURE_OFFSET] ^= 0xFF
        r = bytes(r)

    # go-sev-guest checks ASK (serial 2) revocation against the CRL, not the VCEK.
    crl = _build_crl(revoke_serial=2 if revoke_ask else None, expired=crl_expired)
    return {
        "report": bytes(r),
        "vcek_der": vcek.public_bytes(serialization.Encoding.DER),
        "cert_chain_pem": _pem(ask) + _pem(ark),   # KDS order: ASK then ARK
        "crl_der": crl.public_bytes(serialization.Encoding.DER),
        "ark_pem": _pem(ark),
        "ask_pem": _pem(ask),
        "chip_id": chip_id,
        "measurement": measurement,
    }
