#!/usr/bin/env python3
"""Enclave-certificate verification fixtures (SPEC §9.1-9.4).

The bundle verification flow (§11.2) verifies the enclave's TLS certificate
offline: the cert's DNS SANs carry the HPKE key (`.hpke.`) and the attestation
document hash (`.hatt.`), dcode-encoded (§9.2), and must bind to the attested
HPKE key (§9.3) and the computed document hash (§9.4); the cert must also be
valid for the expected domain (§9.1, RFC 6125 wildcard rules).

These are deterministic (fixed keys/dates — no Date.now()/random). Generates a
real ECDSA P-256 self-signed cert per case with dcode SANs, plus tamper
variants. Stage: verify-enclave-cert.

Gated on `enclave_cert.offline_verification_supported: true` — go/py/js perform
offline cert verification (VerifyFromBundle / cert-verify.ts); tinfoil-rs does
cert binding only over a live TLS connection (no offline path), so it declares
the capability false and skips.
"""

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

VECTORS_DIR = Path(__file__).resolve().parent.parent / "vectors" / "enclave-cert"

DOMAIN = "inference.tinfoil.sh"
PREDICATE = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
BODY = base64.b64encode(b"conformance-enclave-cert-attestation-body").decode()

# Deterministic 32-byte X25519-style HPKE key (content only matters as bytes).
HPKE_KEY = bytes(range(1, 33))
HPKE_HEX = HPKE_KEY.hex()

# Fixed cert validity window (deterministic; the harness supplies no clock to
# this stage — validity-period enforcement, if any, is the SDK's own).
NOT_BEFORE = datetime(2025, 1, 1, tzinfo=timezone.utc)
NOT_AFTER = datetime(2035, 1, 1, tzinfo=timezone.utc)

# One fixed EC key reused across fixtures (the SPKI fingerprint is a live-TLS /
# §8.2 concern, not checked by the offline §9 path — so a static key is fine).
_KEY = ec.derive_private_key(
    0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF,
    ec.SECP256R1(),
)

B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def doc_hash(fmt: str, body: str) -> str:
    """SPEC §2.4: SHA-256(format_string + base64_body), lowercase hex."""
    return hashlib.sha256((fmt + body).encode("utf-8")).hexdigest()


def dcode_sans(data: bytes, prefix: str, domain: str, chunk: int = 50) -> list[str]:
    """SPEC §9.2 encode: NN<base32-chunk>.<prefix>.<domain>, standard base32
    alphabet, no padding, chunked so each DNS label stays <= 63 chars."""
    b32 = base64.b32encode(data).decode().rstrip("=")
    pieces = [b32[i : i + chunk] for i in range(0, len(b32), chunk)] or [""]
    return [f"{idx:02d}{piece}.{prefix}.{domain}" for idx, piece in enumerate(pieces)]


def make_cert_pem(sans: list[str]) -> str:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )
    cert = builder.sign(_KEY, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def enclave_sans(domain: str, hpke: bytes, hatt_hex: str) -> list[str]:
    """Full enclave SAN set: the domain + dcode hpke + dcode hatt (hex string
    bytes, per §9.4)."""
    return (
        [domain]
        + dcode_sans(hpke, "hpke", domain)
        + dcode_sans(hatt_hex.encode("utf-8"), "hatt", domain)
    )


def write_fixture(
    *,
    fixture_id: str,
    title: str,
    notes: str,
    payload: dict[str, Any],
    accepted: bool,
    outputs: dict[str, Any] | None = None,
    exit_code: int = 10,
    rejection_code: str | list[str] | None = None,
) -> None:
    dst = VECTORS_DIR / fixture_id
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "input.json").write_text(json.dumps(payload, indent=2) + "\n")

    if accepted:
        expected: dict[str, Any] = {"stage": "verify-enclave-cert", "accepted": True}
        if outputs:
            expected["outputs"] = outputs
    else:
        expected = {"stage": "verify-enclave-cert", "accepted": False}
        if rejection_code is not None:
            expected["rejection"] = {"code": rejection_code}
    (dst / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")

    manifest = (
        f"id: {fixture_id}\n"
        f"stage: verify-enclave-cert\n"
        f"title: |\n  {title}\n"
        f'spec_refs: ["9.1", "9.2", "9.3", "9.4"]\n'
        f"expects:\n"
        f"  exit_code: {0 if accepted else exit_code}\n"
    )
    if not accepted and rejection_code is not None:
        manifest += f"  rejection_code: {json.dumps(rejection_code)}\n"
    manifest += (
        "required_capabilities:\n"
        "  enclave_cert.offline_verification_supported: true\n"
        "fixture_kind: synthetic\n"
        "notes: |\n"
    )
    for line in notes.strip().splitlines():
        manifest += f"  {line}\n"
    (dst / "manifest.yaml").write_text(manifest)


def base_payload(cert_pem: str, *, domain=DOMAIN, hpke_hex=HPKE_HEX, body=BODY):
    return {
        "schema_version": "1",
        "certificate_pem": cert_pem,
        "expected_domain": domain,
        "expected_hpke_public_key_hex": hpke_hex,
        "attestation_document": {"format": PREDICATE, "body": body},
    }


def main() -> None:
    hatt = doc_hash(PREDICATE, BODY)
    good_sans = enclave_sans(DOMAIN, HPKE_KEY, hatt)

    # 700 — happy path
    write_fixture(
        fixture_id="700-enclave-cert-happy",
        title="Enclave cert with matching HPKE + attestation-hash SANs verifies (SPEC §9).",
        notes="""
Real ECDSA P-256 enclave cert: DNS SAN for the domain, dcode `.hpke.` SANs
carrying the attested HPKE key, dcode `.hatt.` SANs carrying the (hex) document
hash SHA-256(format+body). All bindings match the attested values, so
verification accepts and returns the extracted hpke key + attestation hash.
""",
        payload=base_payload(make_cert_pem(good_sans)),
        accepted=True,
        outputs={
            "hpke_public_key_hex": HPKE_HEX,
            "attestation_hash_hex": hatt,
        },
    )

    # 710 — attested HPKE key differs from the cert's .hpke. SANs
    write_fixture(
        fixture_id="710-hpke-key-mismatch",
        title="Cert HPKE SAN not equal to the attested key must reject (SPEC §9.3).",
        notes="""
The attested/expected HPKE key differs from the key dcode-encoded in the cert's
`.hpke.` SANs — a key swap. Must reject.
""",
        payload=base_payload(make_cert_pem(good_sans), hpke_hex=bytes(range(2, 34)).hex()),
        accepted=False,
        rejection_code="ENCLAVE_CERT_HPKE_MISMATCH",
    )

    # 720 — attestation document hash differs from the cert's .hatt. SANs
    write_fixture(
        fixture_id="720-attestation-hash-mismatch",
        title="Cert attestation-hash SAN not equal to the document hash must reject (SPEC §9.4).",
        notes="""
The attestation_document body is altered so its computed SHA-256(format+body)
no longer equals the hash dcode-encoded in the cert's `.hatt.` SANs. Must
reject — the cert is bound to a different document.
""",
        payload=base_payload(make_cert_pem(good_sans), body=base64.b64encode(b"tampered-body").decode()),
        accepted=False,
        rejection_code="ENCLAVE_CERT_HASH_MISMATCH",
    )

    # 730 — no .hpke. SANs at all
    sans_no_hpke = [DOMAIN] + dcode_sans(hatt.encode("utf-8"), "hatt", DOMAIN)
    write_fixture(
        fixture_id="730-missing-hpke-san",
        title="Cert with no .hpke. SAN must reject (SPEC §9.3).",
        notes="Cert carries the domain + `.hatt.` SANs but no `.hpke.` SANs. Must reject.",
        payload=base_payload(make_cert_pem(sans_no_hpke)),
        accepted=False,
        rejection_code="ENCLAVE_CERT_HPKE_MISSING",
    )

    # 740 — no .hatt. SANs at all
    sans_no_hatt = [DOMAIN] + dcode_sans(HPKE_KEY, "hpke", DOMAIN)
    write_fixture(
        fixture_id="740-missing-hatt-san",
        title="Cert with no .hatt. SAN must reject (SPEC §9.4).",
        notes="Cert carries the domain + `.hpke.` SANs but no `.hatt.` SANs. Must reject.",
        payload=base_payload(make_cert_pem(sans_no_hatt)),
        accepted=False,
        rejection_code="ENCLAVE_CERT_HASH_MISSING",
    )

    # 750 — expected domain not present in SANs
    write_fixture(
        fixture_id="750-domain-mismatch",
        title="Cert not valid for the expected domain must reject (SPEC §9.1).",
        notes="""
The cert's SANs are for inference.tinfoil.sh but the expected domain is a
different host. Must reject (no SAN matches).
""",
        payload=base_payload(make_cert_pem(good_sans), domain="evil.example.com"),
        accepted=False,
        rejection_code="ENCLAVE_CERT_DOMAIN_MISMATCH",
    )

    # 760 — no SAN extension at all
    write_fixture(
        fixture_id="760-no-san",
        title="Cert with no Subject Alternative Names must reject (SPEC §9.1).",
        notes="Cert has no SAN extension at all. Must reject.",
        payload=base_payload(make_cert_pem([])),
        accepted=False,
        rejection_code="ENCLAVE_CERT_NO_SAN",
    )

    # 770 — wildcard must not match the apex domain (RFC 6125)
    wild = "*.tinfoil.sh"
    wild_sans = [wild] + dcode_sans(HPKE_KEY, "hpke", "tinfoil.sh") + dcode_sans(
        hatt.encode("utf-8"), "hatt", "tinfoil.sh"
    )
    write_fixture(
        fixture_id="770-wildcard-apex-rejected",
        title="Wildcard SAN must not match the apex domain (SPEC §9.1, RFC 6125).",
        notes="""
Cert SAN is `*.tinfoil.sh`; the expected domain is the apex `tinfoil.sh`. Per
RFC 6125 a wildcard matches a single label but NOT the apex, so this must
reject.
""",
        payload=base_payload(make_cert_pem(wild_sans), domain="tinfoil.sh"),
        accepted=False,
        rejection_code="ENCLAVE_CERT_DOMAIN_MISMATCH",
    )

    # 780 — unparseable certificate
    write_fixture(
        fixture_id="780-malformed-cert",
        title="Unparseable certificate PEM must be malformed input (exit 30).",
        notes="certificate_pem is not a valid PEM certificate.",
        payload=base_payload("-----BEGIN CERTIFICATE-----\nnot-a-cert\n-----END CERTIFICATE-----\n"),
        accepted=False,
        exit_code=30,
        rejection_code="ENCLAVE_CERT_MALFORMED",
    )

    print(f"wrote enclave-cert fixtures to {VECTORS_DIR}")


if __name__ == "__main__":
    main()
