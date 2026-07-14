#!/usr/bin/env python3
"""Phase 4D verify-attestation-sev fixtures: AMD certificate-chain integrity.

Closes the SPEC §3.3 coverage gaps that the earlier phases left — the earlier
tamper fixtures only touch the VCEK (230/231) and its extensions (700-703),
never the ARK/ASK links or the AMD Distinguished Name, and never a structurally
malformed VCEK. Each fixture here breaks one chain-integrity property and MUST
be rejected:

  250 §3.3.1  ARK self-signature invalid (does the SDK validate the trust root,
              or blindly trust the injected root?)
  251 §3.3.2/§3.3.5  ASK not signed by the ARK (broken intermediate link)
  252 §3.3.4  non-AMD Distinguished Name on the chain (Organization != AMD)
  253 §3.4.2  structurally malformed VCEK certificate

Expected outcome is exit_code 10 with *no* pinned rejection_code: any rejection
passes, so a fixture only fails if an SDK ACCEPTS — surfacing a real
chain-integrity divergence. Like the 600/700 series these inject a synthetic
ARK/ASK, so they gate on attestation_sev.amd_root_ca_injection_supported and
skip on JS (its verifier embeds the real AMD roots with no injection point).
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "fixturegen"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

from lib.sev_synth import (  # noqa: E402
    ReportFields, SYNTH_CHIP_ID, SYNTH_TCB,
    build_report_body, gen_synth_chain, gzip_b64, load_or_create_synth_chain, sign_report,
)

VECTORS_DIR = REPO_ROOT / "vectors" / "attestation-sev"
DEFAULT_DATE = 1780272000  # 2026-06-01, inside the synth validity window


def _base_fields() -> ReportFields:
    tcb = SYNTH_TCB.to_u64()
    return ReportFields(
        current_tcb=tcb,
        reported_tcb=tcb,
        chip_id=SYNTH_CHIP_ID,
        measurement=bytes.fromhex("11" * 48),
        host_data=bytes.fromhex("22" * 32),
        report_data=bytes.fromhex("33" * 64),
        policy=0x30000,  # SMT + reserved-MBO — a clean, accept-worthy policy
    )


def _write(fixture_id: str, title: str, notes: str, inp: dict[str, Any]) -> None:
    dst = VECTORS_DIR / fixture_id
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "input.json").write_text(json.dumps(inp, indent=2) + "\n")
    # No pinned rejection_code: any rejection passes; only an ACCEPT fails.
    (dst / "expected.json").write_text(
        json.dumps({"stage": "verify-attestation-sev", "accepted": False}, indent=2) + "\n"
    )
    manifest = (
        f"id: {fixture_id}\n"
        f"stage: verify-attestation-sev\n"
        f"title: |\n  {title}\n"
        f'spec_refs: {json.dumps(SPEC_REFS[fixture_id])}\n'
        f"expects:\n"
        f"  exit_code: 10\n"
        f"required_capabilities:\n"
        f"  attestation_sev.supported: true\n"
        f"  attestation_sev.injected_collateral_supported: true\n"
        f"  attestation_sev.amd_root_ca_injection_supported: true\n"
        f"fixture_kind: synthetic-chain-integrity\n"
        f"notes: |\n"
    )
    for line in notes.strip().splitlines():
        manifest += f"  {line}\n"
    (dst / "manifest.yaml").write_text(manifest)


SPEC_REFS = {
    "250-ark-self-signature-tampered": ["3.3.1", "3.3.5"],
    "251-ask-not-signed-by-ark": ["3.3.2", "3.3.5"],
    "252-chain-non-amd-distinguished-name": ["3.3.4"],
    "253-vcek-malformed": ["3.4.2"],
}


def _report_b64(chain) -> str:
    return gzip_b64(sign_report(build_report_body(_base_fields()), chain.vcek_priv))


def main() -> None:
    # ---- 250: ARK self-signature invalid (§3.3.1) ------------------------
    # Persisted chain, but flip a byte deep inside the ARK cert's RSA
    # signatureValue. The ARK public key is unchanged (so ASK->ARK still
    # verifies by key), but the ARK's *self*-signature no longer validates.
    # A verifier that validates its trust root rejects; one that blindly
    # trusts the injected root accepts (the divergence we probe).
    chain = load_or_create_synth_chain()
    ark_der = bytearray(chain.ark_cert.public_bytes(serialization.Encoding.DER))
    ark_der[-15] ^= 0xFF  # inside the RSA signature; structure stays parseable
    tampered_ark_pem = (
        "-----BEGIN CERTIFICATE-----\n"
        + "\n".join(
            base64.standard_b64encode(bytes(ark_der)).decode()[i : i + 64]
            for i in range(0, len(base64.standard_b64encode(bytes(ark_der)).decode()), 64)
        )
        + "\n-----END CERTIFICATE-----\n"
    )
    # sanity: still parses as a cert (only the signature is wrong)
    x509.load_pem_x509_certificate(tampered_ark_pem.encode())
    _write(
        "250-ark-self-signature-tampered",
        "Injected AMD root (ARK) with an invalid self-signature must reject (SPEC §3.3.1).",
        """
The persisted synth ARK cert with one byte flipped inside its RSA
signatureValue — the public key is intact (so ASK still chains to it by key),
but the root's self-signature is invalid. A verifier that validates the trust
root rejects; one that blindly trusts the injected/pinned root accepts. Probes
whether the SDK actually checks the AMD root.
""",
        {
            "schema_version": "1",
            "attestation_doc_b64": _report_b64(chain),
            "vcek_der_b64": chain.vcek_der_b64,
            "amd_root_ca_pem": tampered_ark_pem,
            "ask_pem": chain.ask_pem,
            "expiration_check_date_unix": DEFAULT_DATE,
        },
    )

    # ---- 251: ASK not signed by the ARK (§3.3.2/§3.3.5) ------------------
    # Two independent chains. Trust root = chainA.ARK, but the ASK/VCEK (and
    # the report) come from chainB — so chainB's ASK is not signed by
    # chainA's ARK. The intermediate link is broken.
    chain_a = gen_synth_chain(chip_id=SYNTH_CHIP_ID, tcb=SYNTH_TCB)
    chain_b = gen_synth_chain(chip_id=SYNTH_CHIP_ID, tcb=SYNTH_TCB)
    _write(
        "251-ask-not-signed-by-ark",
        "ASK not signed by the trusted ARK must reject (SPEC §3.3.2 / §3.3.5).",
        """
Trust root is chain A's ARK, but the ASK, VCEK, and report all come from an
unrelated chain B. Chain B's ASK is signed by chain B's ARK, not the trusted
chain A ARK, so the intermediate link is broken. All SDKs must reject.
""",
        {
            "schema_version": "1",
            "attestation_doc_b64": _report_b64(chain_b),
            "vcek_der_b64": chain_b.vcek_der_b64,
            "amd_root_ca_pem": chain_a.ark_pem,
            "ask_pem": chain_b.ask_pem,
            "expiration_check_date_unix": DEFAULT_DATE,
        },
    )

    # ---- 252: non-AMD Distinguished Name (§3.3.4) -----------------------
    # A fully self-consistent chain (verifies cryptographically) but whose
    # certs carry Organization = "Definitely Not Advanced Micro Devices".
    # SDKs that enforce AMD DN validation reject; ones that don't accept.
    chain_dn = gen_synth_chain(
        chip_id=SYNTH_CHIP_ID, tcb=SYNTH_TCB,
        org_name="Definitely Not Advanced Micro Devices",
    )
    _write(
        "252-chain-non-amd-distinguished-name",
        "Chain with a non-AMD Distinguished Name (Organization) must reject (SPEC §3.3.4).",
        """
The ARK/ASK/VCEK chain verifies cryptographically but every cert's
Organization is "Definitely Not Advanced Micro Devices" instead of "Advanced
Micro Devices". SPEC §3.3.4 requires AMD Distinguished Name validation; an SDK
that skips it accepts a chain from the wrong issuer.
""",
        {
            "schema_version": "1",
            "attestation_doc_b64": _report_b64(chain_dn),
            "vcek_der_b64": chain_dn.vcek_der_b64,
            "amd_root_ca_pem": chain_dn.ark_pem,
            "ask_pem": chain_dn.ask_pem,
            "expiration_check_date_unix": DEFAULT_DATE,
        },
    )

    # ---- 253: structurally malformed VCEK (§3.4.2) ----------------------
    # Persisted chain but the VCEK DER is truncated — not a parseable cert.
    truncated_vcek = base64.standard_b64encode(chain.vcek_der[:-60]).decode()
    _write(
        "253-vcek-malformed",
        "Structurally malformed (truncated) VCEK certificate must reject (SPEC §3.4.2).",
        """
The injected VCEK DER is truncated (last 60 bytes removed) so it is not a
parseable X.509 certificate. SPEC §3.4.2 VCEK format validation must reject;
the failure should be a clean malformed/format error, not a crash.
""",
        {
            "schema_version": "1",
            "attestation_doc_b64": _report_b64(chain),
            "vcek_der_b64": truncated_vcek,
            "amd_root_ca_pem": chain.ark_pem,
            "ask_pem": chain.ask_pem,
            "expiration_check_date_unix": DEFAULT_DATE,
        },
    )

    print("Wrote Phase 4D attestation-sev chain-integrity fixtures: 250-253")


if __name__ == "__main__":
    main()
