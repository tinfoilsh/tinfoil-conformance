#!/usr/bin/env python3
"""Generate Phase 1 verify-attestation-sev fixtures: real AMD-signed happy path.

Phase 1 of the SPEC §3 / AMD SEV-SNP conformance buildout. This is the
foundation fixture for verify-attestation-sev — a real production-class
attestation bundle from a Genoa-class system, with the matching real
VCEK certificate. Every later phase (synth-chain tampers, policy pins,
verify-full) reuses this bundle's measurement / report_data / chip_id as
the baseline truth.

Sourced from tinfoil-js/packages/verifier/test/fixtures/attestation-bundle.json
(staged into vectors/attestation-sev/_assets/real_genoa_bundle.json for
traceability). The bundle's enclaveAttestationReport.body is gzip+base64
of a 1184-byte SEV-SNP report (SPEC §3.1); .vcek is the matching
DER-encoded VCEK cert signed by AMD's real Genoa SEV Key.

The conformance binary serves AMD's embedded ARK || ASK PEM bundle (from
each SDK's shipped trust store) when no inline override is set, so this
fixture is fully hermetic — no AMD KDS network calls happen during
verification.
"""

from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = REPO_ROOT / "vectors" / "attestation-sev"
ASSETS = VECTORS_DIR / "_assets"

BUNDLE = json.loads((ASSETS / "real_genoa_bundle.json").read_text())

# 2026-06-01 00:00:00 UTC — inside the VCEK validity window
# (2026-01-11 .. 2033-01-11) for the staged bundle.
DEFAULT_DATE = 1780272000


def _decompress_body(body_b64: str) -> bytes:
    gz_bytes = base64.standard_b64decode(body_b64)
    return gzip.decompress(gz_bytes)


def _decoded_body_fields(report: bytes) -> dict:
    """Decode the 1184-byte SEV-SNP report body into the fields the Go
    conformance binary emits — must stay byte-for-byte aligned with
    buildSevOutputs() in cmd/tinfoil-conformance/verify_attestation_sev.go.
    """
    def u32(off): return int.from_bytes(report[off:off + 4], "little")
    def u64(off): return int.from_bytes(report[off:off + 8], "little")

    policy = u64(0x08)
    current_tcb = u64(0x38)
    platform_info = u64(0x40)

    return {
        "version": u32(0x00),
        "guest_svn": u32(0x04),
        "policy_hex": f"{policy:016x}",
        "policy_decoded": {
            "abi_minor": policy & 0xff,
            "abi_major": (policy >> 8) & 0xff,
            "smt": bool(policy & (1 << 16)),
            "reserved_mbo": bool(policy & (1 << 17)),
            "migrate_ma": bool(policy & (1 << 18)),
            "debug": bool(policy & (1 << 19)),
            "single_socket": bool(policy & (1 << 20)),
            "cxl_allow": bool(policy & (1 << 21)),
            "mem_aes_256_xts": bool(policy & (1 << 22)),
            "raplmsr_dis": bool(policy & (1 << 23)),
            "ciphertext_hiding_dram": bool(policy & (1 << 24)),
        },
        "family_id_hex": report[0x10:0x20].hex(),
        "image_id_hex": report[0x20:0x30].hex(),
        "vmpl": u32(0x30),
        "signature_algo": u32(0x34),
        "current_tcb_hex": f"{current_tcb:016x}",
        "current_tcb_decoded": {
            "bl_spl": current_tcb & 0xff,
            "tee_spl": (current_tcb >> 8) & 0xff,
            "snp_spl": (current_tcb >> 48) & 0xff,
            "ucode_spl": (current_tcb >> 56) & 0xff,
        },
        "platform_info_hex": f"{platform_info:016x}",
        "platform_info_decoded": {
            "smt_en": bool(platform_info & (1 << 0)),
            "tsme_en": bool(platform_info & (1 << 1)),
            "ecc_en": bool(platform_info & (1 << 2)),
            "rapl_dis": bool(platform_info & (1 << 3)),
            "ciphertext_hiding": bool(platform_info & (1 << 4)),
        },
        "signer_info_hex": f"{u32(0x48):08x}",
        "report_data_hex": report[0x50:0x90].hex(),
        "measurement_hex": report[0x90:0x90 + 48].hex(),
        "host_data_hex": report[0xC0:0xC0 + 32].hex(),
        "id_key_digest_hex": report[0xE0:0xE0 + 48].hex(),
        "author_key_digest_hex": report[0x110:0x110 + 48].hex(),
        "report_id_hex": report[0x140:0x140 + 32].hex(),
        "report_id_ma_hex": report[0x160:0x160 + 32].hex(),
        "reported_tcb_hex": report[0x180:0x180 + 8].hex(),
        "chip_id_hex": report[0x1A0:0x1A0 + 64].hex(),
        "committed_tcb_hex": report[0x1E8:0x1E8 + 8].hex(),
        "current_build": report[0x1F0],
        "current_minor": report[0x1F1],
        "current_major": report[0x1F2],
        "committed_build": report[0x1F4],
        "committed_minor": report[0x1F5],
        "committed_major": report[0x1F6],
        "launch_tcb_hex": report[0x1F8:0x1F8 + 8].hex(),
    }


def write_fixture(
    *,
    fixture_id: str,
    title: str,
    notes: str,
    spec_refs: list[str],
) -> None:
    body_b64 = BUNDLE["enclaveAttestationReport"]["body"]
    vcek_b64 = BUNDLE["vcek"]
    report = _decompress_body(body_b64)
    assert len(report) == 1184, f"SEV report must be 1184 bytes, got {len(report)}"

    inp = {
        "schema_version": "1",
        "attestation_doc_b64": body_b64,
        "vcek_der_b64": vcek_b64,
        "expiration_check_date_unix": DEFAULT_DATE,
    }
    body_fields = _decoded_body_fields(report)
    expected = {
        "stage": "verify-attestation-sev",
        "accepted": True,
        "outputs": {
            "measurement": {
                "type": "https://tinfoil.sh/predicate/sev-snp-guest/v2",
                "registers": [body_fields["measurement_hex"]],
            },
            "body_fields": body_fields,
        },
    }

    dst = VECTORS_DIR / fixture_id
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "input.json").write_text(json.dumps(inp, indent=2))
    (dst / "expected.json").write_text(json.dumps(expected, indent=2))

    manifest = (
        f"id: {fixture_id}\n"
        f"stage: verify-attestation-sev\n"
        f"title: |\n  {title}\n"
        f"spec_refs: {json.dumps(spec_refs)}\n"
        f"expects:\n"
        f"  exit_code: 0\n"
        f"required_capabilities:\n"
        f"  attestation_sev.supported: true\n"
        f"  attestation_sev.injected_collateral_supported: true\n"
        f"fixture_kind: real-frozen-bundle\n"
        f"notes: |\n"
    )
    for line in notes.strip().splitlines():
        manifest += f"  {line}\n"
    (dst / "manifest.yaml").write_text(manifest)


def main() -> None:
    write_fixture(
        fixture_id="200-real-sev-snp-happy",
        title="Real AMD-signed SEV-SNP v3 Genoa attestation verifies with embedded ARK||ASK.",
        spec_refs=["3", "3.1", "3.3", "3.6"],
        notes=(
            "Phase 1 happy path — the foundation fixture for verify-attestation-sev.\n"
            "\n"
            "Sourced from a real Tinfoil Genoa enclave's attestation bundle\n"
            "(staged at vectors/attestation-sev/_assets/real_genoa_bundle.json).\n"
            "The 1184-byte SEV-SNP v3 report is gzip+base64-encoded; the\n"
            "matching VCEK certificate is DER-encoded and signed by AMD's real\n"
            "Genoa SEV Key, with the ARK||ASK chain served from the SDK's\n"
            "embedded Genoa cert_chain trust store (no AMD KDS network call).\n"
            "\n"
            "expiration_check_date_unix = 1780272000 (2026-06-01 00:00:00 UTC)\n"
            "is inside the VCEK validity window (2026-01-11 .. 2033-01-11).\n"
            "\n"
            "Notable body fields (parser sanity check):\n"
            "  * version          = 3            (SEV-SNP SPEC §3.1)\n"
            "  * debug bit        = 0            (production enclave; trustable)\n"
            "  * reserved_mbo     = 1            (guest_policy bit 17 must be 1)\n"
            "  * migrate_ma       = 0            (no migration allowed)\n"
            "  * single_socket    = 0            (multi-socket Genoa)\n"
            "  * smt              = 1            (SMT allowed per policy)\n"
            "  * smt_en/tsme_en/ecc_en = 1       (platform_info: SMT+TSME+ECC)\n"
            "\n"
            "Pinned outputs cover the measurement (SPEC §7.1 single register)\n"
            "and all decoded body fields. host_data / report_data / chip_id are\n"
            "deterministic from the report bytes and pinned in expected.json.\n"
            "qv_result-style status codes don't apply to SEV-SNP — once the\n"
            "VCEK chain + report signature verify, success is binary.\n"
            "\n"
            "Gated on attestation_sev.supported. tinfoil-go declares true\n"
            "(google/go-sev-guest). Python and JS are wired in P1's Phase 1B/1C."
        ),
    )
    print("Wrote Phase 1A attestation-sev fixtures:")
    print(f"  - {VECTORS_DIR / '200-real-sev-snp-happy'}")


if __name__ == "__main__":
    main()
