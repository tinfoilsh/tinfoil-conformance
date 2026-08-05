#!/usr/bin/env python3
"""Synthetic Sigstore stack for v3 provenance conformance fixtures.

Builds a complete, self-consistent Sigstore signing chain from fixed keys so a
DSSE-signed in-toto statement verifies under sigstore-go's SignedEntityVerifier
with SCT + transparency-log + observer-timestamp requirements — exactly what the
tinfoil verifier configures. Everything is deterministic (fixed EC keys, fixed
base time) so regenerated fixtures are byte-stable.

The one delicate piece is the embedded SCT. sigstore-go verifies it through
google/certificate-transparency-go, which reconstructs the pre-certificate TBS
by DER round-tripping the leaf's TBSCertificate minus the SCT extension
(x509.RemoveSCTList). So the CT log must sign over Go's re-marshaling of the
leaf-without-SCT TBS. We rely on the fixed-point that a `cryptography`-produced
DER TBS survives that round-trip unchanged (holds for the standard fields we
emit); build_leaf signs the SCT over the pre-SCT TBS accordingly.

Produced by build_bundle(): (bundle_json_bytes, trusted_root_json_bytes) plus
the artifact digest, ready to drop into a v3 sigstore-code / sigstore-platform
collateral entry.
"""

import base64
import datetime
import hashlib
import json
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.x509.oid import NameOID, ObjectIdentifier

# Fulcio certificate-extension OIDs (github.com/sigstore/fulcio spec), matched by
# sigstore-go's certificate identity checks.
OID_ISSUER_V1 = ObjectIdentifier("1.3.6.1.4.1.57264.1.1")  # raw string value
OID_RUNNER_ENVIRONMENT = ObjectIdentifier("1.3.6.1.4.1.57264.1.11")  # DER string
OID_SCT_LIST = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")  # RFC 6962 §3.3

GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"

# Fixed instant all validity windows and timestamps hang off of. Verification is
# anchored to the log's integrated time (observer timestamp), never wall-clock,
# so a fixed past instant verifies forever.
BASE_TIME = datetime.datetime(2025, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
INTEGRATED_TIME = int(BASE_TIME.timestamp()) + 1
SCT_TIMESTAMP_MS = int(BASE_TIME.timestamp() * 1000)

# Fixed EC private scalars → reproducible keys. Distinct, nonzero, < P-256 order.
_SECRETS = {
    "fulcio_root": 0x1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A,
    "fulcio_int": 0x2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B,
    "leaf": 0x3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C,
    "ctlog": 0x4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D,
    "rekor": 0x5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E,
}


def _key(name):
    return ec.derive_private_key(_SECRETS[name], ec.SECP256R1())


def b64(data):
    return base64.b64encode(data).decode()


def sha256(data):
    return hashlib.sha256(data).digest()


def spki_der(pub):
    return pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# --- TLS wire encoders (RFC 8446 §3) for the SCT signature ------------------
def _u8(n):
    return struct.pack("!B", n)


def _u16(n):
    return struct.pack("!H", n)


def _u64(n):
    return struct.pack("!Q", n)


def _opaque(data, length_bytes):
    n = len(data)
    hdr = n.to_bytes(length_bytes, "big")
    return hdr + data


def _der_octet_string(data):
    # DER OCTET STRING; SCT payloads stay short so length uses the short form
    # or a single/double long-form byte.
    if len(data) < 0x80:
        return bytes([0x04, len(data)]) + data
    length = len(data)
    nbytes = (length.bit_length() + 7) // 8
    return bytes([0x04, 0x80 | nbytes]) + length.to_bytes(nbytes, "big") + data


def _der_utf8_string(text):
    raw = text.encode()
    assert len(raw) < 0x80
    return bytes([0x0C, len(raw)]) + raw


# --- Certificate authority --------------------------------------------------
def _build_ca_with_secrets(root_secret, int_secret):
    return _build_ca(
        ec.derive_private_key(root_secret, ec.SECP256R1()),
        ec.derive_private_key(int_secret, ec.SECP256R1()),
    )


def _build_ca(root_key=None, int_key=None):
    root_key = root_key or _key("fulcio_root")
    int_key = int_key or _key("fulcio_int")

    not_before = BASE_TIME - datetime.timedelta(days=1)
    not_after = BASE_TIME + datetime.timedelta(days=3650)

    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-sigstore-root")])
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    int_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-sigstore-intermediate")])
    int_cert = (
        x509.CertificateBuilder()
        .subject_name(int_name)
        .issuer_name(root_name)
        .public_key(int_key.public_key())
        .serial_number(2)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(int_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    return root_cert, int_cert, int_key


# --- SCT (RFC 6962) ---------------------------------------------------------
def _sct_signature_input(tbs_no_sct, issuer_pub):
    """digitally-signed input for an embedded (precert) SCT over the leaf TBS
    with its SCT extension removed."""
    issuer_key_hash = sha256(spki_der(issuer_pub))
    precert = issuer_key_hash + _opaque(tbs_no_sct, 3)
    return (
        _u8(0)              # sct_version = v1
        + _u8(0)            # signature_type = certificate_timestamp
        + _u64(SCT_TIMESTAMP_MS)
        + _u16(1)           # entry_type = precert_entry
        + precert
        + _u16(0)           # extensions (empty)
    )


def _serialized_sct(log_key_id, signature_der):
    """One SerializedSCT (RFC 6962 §3.2 struct) for embedding."""
    digitally_signed = _u8(4) + _u8(3) + _opaque(signature_der, 2)  # sha256, ecdsa
    return (
        _u8(0)              # sct_version = v1
        + log_key_id        # LogID: 32-byte key hash
        + _u64(SCT_TIMESTAMP_MS)
        + _u16(0)           # extensions (empty)
        + digitally_signed
    )


def _sct_list_extension_value(serialized_scts):
    entries = b"".join(_opaque(s, 2) for s in serialized_scts)
    sct_list = _opaque(entries, 2)  # SignedCertificateTimestampList
    return _der_octet_string(sct_list)


# --- Leaf certificate with embedded SCT -------------------------------------
def _leaf_extensions(identity_uri, int_key, issuer, runner_environment):
    return [
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), True),
        (x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CODE_SIGNING]), False),
        (x509.SubjectKeyIdentifier.from_public_key(_key("leaf").public_key()), False),
        (x509.AuthorityKeyIdentifier.from_issuer_public_key(int_key.public_key()), False),
        (x509.UnrecognizedExtension(OID_ISSUER_V1, issuer.encode()), False),
        (x509.UnrecognizedExtension(OID_RUNNER_ENVIRONMENT, _der_utf8_string(runner_environment)), False),
        (x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identity_uri)]), True),
    ]


def _build_leaf(identity_uri, root_cert, int_cert, int_key, dup_sct=False,
                issuer=GITHUB_ACTIONS_ISSUER, runner_environment="github-hosted"):
    leaf_key = _key("leaf")
    int_name = int_cert.subject
    not_before = BASE_TIME - datetime.timedelta(minutes=5)
    not_after = BASE_TIME + datetime.timedelta(minutes=10)

    def base_builder():
        b = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(int_name)
            .public_key(leaf_key.public_key())
            .serial_number(0x1000)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
        )
        for ext, critical in _leaf_extensions(identity_uri, int_key, issuer, runner_environment):
            b = b.add_extension(ext, critical)
        return b

    # Pre-SCT leaf: its TBS is what the CT log signs over (after Go's
    # RemoveSCTList round-trip, which this DER is a fixed-point of).
    pre_cert = base_builder().sign(int_key, hashes.SHA256())
    tbs_no_sct = pre_cert.tbs_certificate_bytes

    ctlog_key = _key("ctlog")
    log_key_id = sha256(spki_der(ctlog_key.public_key()))
    sig_input = _sct_signature_input(tbs_no_sct, int_cert.public_key())
    sct_sig_der = ctlog_key.sign(sig_input, ec.ECDSA(hashes.SHA256()))
    sct = _serialized_sct(log_key_id, sct_sig_der)
    # dup_sct embeds the same SCT twice (same CT log id) to exercise the
    # duplicate-log-SCT rejection (P12).
    scts = [sct, sct] if dup_sct else [sct]
    sct_ext_value = _sct_list_extension_value(scts)

    # Final leaf: identical fields plus the SCT-list extension appended last.
    leaf = (
        base_builder()
        .add_extension(x509.UnrecognizedExtension(OID_SCT_LIST, sct_ext_value), False)
        .sign(int_key, hashes.SHA256())
    )
    return leaf, leaf_key


# --- DSSE + in-toto ---------------------------------------------------------
def _pae(payload_type, payload):
    return b"DSSEv1 %d %b %d %b" % (len(payload_type), payload_type.encode(), len(payload), payload)


def _dsse_sign(statement_bytes, leaf_key):
    sig = leaf_key.sign(_pae(DSSE_PAYLOAD_TYPE, statement_bytes), ec.ECDSA(hashes.SHA256()))
    return sig


# --- Rekor v1 dsse/0.0.1 entry + Signed Entry Timestamp ---------------------
def _canonical_json(obj):
    # Rekor bodies and the SET payload use JSON canonicalization; for our flat
    # objects sorted keys + compact separators match RFC 8785 output.
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _rekor_body(dsse_sig, leaf_pem, statement_bytes, envelope_json):
    # Field order must match rekor's dsse/v0.0.1 Canonicalize output
    # (apiVersion, spec, kind) — that is the byte string the log's Merkle leaf
    # commits to, so emitting any other order breaks inclusion verification.
    return json.dumps({
        "apiVersion": "0.0.1",
        "spec": {
            "envelopeHash": {"algorithm": "sha256", "value": sha256(envelope_json).hex()},
            "payloadHash": {"algorithm": "sha256", "value": sha256(statement_bytes).hex()},
            "signatures": [{"signature": b64(dsse_sig), "verifier": b64(leaf_pem)}],
        },
        "kind": "dsse",
    }, separators=(",", ":")).encode()


def _signed_entry_timestamp(body_bytes, log_key_id, integrated_time):
    payload = _canonical_json({
        "body": b64(body_bytes),
        "integratedTime": integrated_time,
        "logID": log_key_id.hex(),
        "logIndex": 0,
    })
    # ECDSA(SHA256) over the raw payload yields a signature over sha256(payload),
    # which is what VerifySET checks (ecdsa.VerifyASN1 against sha256(canonical)).
    return _key("rekor").sign(payload, ec.ECDSA(hashes.SHA256()))


# v0.3 bundles also require an inclusion proof. For a single-entry log the
# Merkle root is just the RFC 6962 leaf hash and the proof carries no siblings.
# The origin must carry a " - <treeID>" suffix or sigstore-go misclassifies the
# checkpoint as Rekor v2 (treeIDSuffixRegex) and reconstructs a different hash.
# The signature line's name, by contrast, is a single whitespace-free token.
REKOR_ORIGIN = "rekor.synthetic - 1"
REKOR_SIG_NAME = "rekor.synthetic"


def _rfc6962_leaf_hash(body_bytes):
    return sha256(b"\x00" + body_bytes)


def _checkpoint_envelope(root_hash):
    rekor_key = _key("rekor")
    note = "%s\n%d\n%s\n" % (REKOR_ORIGIN, 1, b64(root_hash))
    sig_der = rekor_key.sign(note.encode(), ec.ECDSA(hashes.SHA256()))
    key_hint = sha256(spki_der(rekor_key.public_key()))[:4]
    sig_line = "— %s %s" % (REKOR_SIG_NAME, b64(key_hint + sig_der))
    return note + "\n" + sig_line + "\n"


# --- Trusted root -----------------------------------------------------------
def _rfc3339(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _public_key_entry(pub, key_id, start):
    return {
        "rawBytes": b64(spki_der(pub)),
        "keyDetails": "PKIX_ECDSA_P256_SHA_256",
        "validFor": {"start": _rfc3339(start)},
    }


def _trusted_root(root_cert, int_cert):
    valid_start = BASE_TIME - datetime.timedelta(days=1)
    ctlog_pub = _key("ctlog").public_key()
    rekor_pub = _key("rekor").public_key()
    return {
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "certificateAuthorities": [{
            "subject": {"organization": "synthetic", "commonName": "synthetic-sigstore"},
            "uri": "https://fulcio.synthetic",
            "certChain": {"certificates": [
                {"rawBytes": b64(int_cert.public_bytes(serialization.Encoding.DER))},
                {"rawBytes": b64(root_cert.public_bytes(serialization.Encoding.DER))},
            ]},
            "validFor": {"start": _rfc3339(valid_start)},
        }],
        "ctlogs": [{
            "baseUrl": "https://ctlog.synthetic",
            "hashAlgorithm": "SHA2_256",
            "publicKey": _public_key_entry(ctlog_pub, sha256(spki_der(ctlog_pub)), valid_start),
            "logId": {"keyId": b64(sha256(spki_der(ctlog_pub)))},
        }],
        "tlogs": [{
            "baseUrl": "https://rekor.synthetic",
            "hashAlgorithm": "SHA2_256",
            "publicKey": _public_key_entry(rekor_pub, sha256(spki_der(rekor_pub)), valid_start),
            "logId": {"keyId": b64(sha256(spki_der(rekor_pub)))},
        }],
        "timestampAuthorities": [],
    }


# --- Bundle assembly --------------------------------------------------------
def build_bundle(identity_uri, statement_bytes, integrated_time=None, dup_sct=False, bad_dsse=False,
                 issuer=GITHUB_ACTIONS_ISSUER, runner_environment="github-hosted"):
    """Return (bundle_dict, trusted_root_dict) for a DSSE-signed in-toto
    statement whose signing certificate carries identity_uri as its SAN.
    integrated_time overrides the log timestamp (used to place it outside the
    certificate validity window); dup_sct embeds a duplicate-log SCT; bad_dsse
    signs the envelope with a non-leaf key (the log entry stays self-consistent,
    but the DSSE signature fails to verify under the certificate)."""
    it = INTEGRATED_TIME if integrated_time is None else integrated_time
    root_cert, int_cert, int_key = _build_ca()
    leaf, leaf_key = _build_leaf(identity_uri, root_cert, int_cert, int_key, dup_sct=dup_sct,
                                 issuer=issuer, runner_environment=runner_environment)
    leaf_pem = leaf.public_bytes(serialization.Encoding.PEM)

    dsse_sig = _dsse_sign(statement_bytes, _key("ctlog") if bad_dsse else leaf_key)
    envelope = {
        "payload": b64(statement_bytes),
        "payloadType": DSSE_PAYLOAD_TYPE,
        "signatures": [{"sig": b64(dsse_sig)}],
    }
    envelope_json = _canonical_json(envelope)

    body = _rekor_body(dsse_sig, leaf_pem, statement_bytes, envelope_json)
    rekor_key_id = sha256(spki_der(_key("rekor").public_key()))
    set_sig = _signed_entry_timestamp(body, rekor_key_id, it)
    root_hash = _rfc6962_leaf_hash(body)

    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": b64(leaf.public_bytes(serialization.Encoding.DER))},
            "tlogEntries": [{
                "logIndex": "0",
                "logId": {"keyId": b64(rekor_key_id)},
                "kindVersion": {"kind": "dsse", "version": "0.0.1"},
                "integratedTime": str(it),
                "inclusionPromise": {"signedEntryTimestamp": b64(set_sig)},
                "inclusionProof": {
                    "logIndex": "0",
                    "rootHash": b64(root_hash),
                    "treeSize": "1",
                    "hashes": [],
                    "checkpoint": {"envelope": _checkpoint_envelope(root_hash)},
                },
                "canonicalizedBody": b64(body),
            }],
        },
        "dsseEnvelope": envelope,
    }
    return bundle, _trusted_root(root_cert, int_cert)


def rogue_ca_cert_chain():
    """A certificate chain from an unrelated CA, for the untrusted-root case
    (P5): swapping it into a trusted root breaks leaf chain-building."""
    root_cert, int_cert, _ = _build_ca_with_secrets(0x71, 0x72)
    return [
        {"rawBytes": b64(int_cert.public_bytes(serialization.Encoding.DER))},
        {"rawBytes": b64(root_cert.public_bytes(serialization.Encoding.DER))},
    ]
