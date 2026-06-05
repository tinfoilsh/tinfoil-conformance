#!/usr/bin/env python3
"""Generate Phase 4 verify-attestation-sev fixtures: policy pins.

Each fixture takes the real Genoa attestation bundle from
vectors/attestation-sev/_assets/ and pins one or more policy.expected_*_hex
values to either match (accept) or mismatch (reject). Exercises SDK
SPEC §3.7 / §3.8 / §8.2 / §8.3 policy enforcement on top of signature
verification — i.e. the bytes-on-the-wire validate cleanly but the SDK
must still reject when caller-supplied expectations don't match.

Gates on attestation_sev.extended_checks_supported. SDKs that only do
structural cryptographic verification (no caller-pinned policy) declare
extended_checks_supported=false and these fixtures skip cleanly.
"""

from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = REPO_ROOT / "vectors" / "attestation-sev"
ASSETS = VECTORS_DIR / "_assets"

BUNDLE = json.loads((ASSETS / "real_genoa_bundle.json").read_text())
BASE_BODY_B64 = BUNDLE["enclaveAttestationReport"]["body"]
BASE_VCEK_B64 = BUNDLE["vcek"]
BASE_REPORT = gzip.decompress(base64.standard_b64decode(BASE_BODY_B64))
assert len(BASE_REPORT) == 1184

# 2026-06-01 — Phase 1A baseline.
DEFAULT_DATE = 1780272000

# Real values extracted from the bundle (cross-referenced against
# vectors/attestation-sev/200-real-sev-snp-happy/expected.json).
REAL_MEASUREMENT_HEX = BASE_REPORT[0x90:0x90 + 48].hex()
REAL_HOST_DATA_HEX = BASE_REPORT[0xC0:0xC0 + 32].hex()
REAL_REPORT_DATA_HEX = BASE_REPORT[0x50:0x90].hex()
REAL_ID_KEY_DIGEST_HEX = BASE_REPORT[0xE0:0xE0 + 48].hex()
REAL_AUTHOR_KEY_DIGEST_HEX = BASE_REPORT[0x110:0x110 + 48].hex()


def _flip_hex(s: str) -> str:
    """Flip first hex char of a hex string (deterministic 1-char mutation)."""
    return ("f" if s[0] != "f" else "0") + s[1:]


def make_input(*, policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "attestation_doc_b64": BASE_BODY_B64,
        "vcek_der_b64": BASE_VCEK_B64,
        "expiration_check_date_unix": DEFAULT_DATE,
        "policy": policy,
    }


def write_fixture(
    *,
    fixture_id: str,
    title: str,
    notes: str,
    policy: dict[str, Any],
    accepted: bool,
    rejection_code: str | None = None,
    spec_refs: list[str],
    extra_caps: dict[str, Any] | None = None,
) -> None:
    inp = make_input(policy=policy)
    if accepted:
        expected: dict[str, Any] = {
            "stage": "verify-attestation-sev",
            "accepted": True,
        }
    else:
        assert rejection_code is not None, "rejection_code required when accepted=false"
        expected = {
            "stage": "verify-attestation-sev",
            "accepted": False,
            "rejection": {"code": rejection_code},
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
        f"  exit_code: {0 if accepted else 10}\n"
    )
    if not accepted:
        manifest += f"  rejection_code: {json.dumps(rejection_code)}\n"
    manifest += (
        f"required_capabilities:\n"
        f"  attestation_sev.supported: true\n"
        f"  attestation_sev.injected_collateral_supported: true\n"
        f"  attestation_sev.extended_checks_supported: true\n"
    )
    for cap_path, cap_value in (extra_caps or {}).items():
        manifest += f"  {cap_path}: {json.dumps(cap_value)}\n"
    manifest += (
        "fixture_kind: real-frozen-bundle-policy-pin\n"
        "notes: |\n"
    )
    for line in notes.strip().splitlines():
        manifest += f"  {line}\n"
    (dst / "manifest.yaml").write_text(manifest)


def main() -> None:
    # ---- Reject fixtures: mismatched pins ---------------------------------
    write_fixture(
        fixture_id="400-measurement-pin-mismatch",
        title="policy.expected_measurement_hex pinned to wrong value → MEASUREMENT_MISMATCH.",
        rejection_code="MEASUREMENT_MISMATCH",
        spec_refs=["3.8"],
        policy={"expected_measurement_hex": _flip_hex(REAL_MEASUREMENT_HEX)},
        accepted=False,
        notes=(
            "Real Genoa bundle has measurement=09ef32...eb519. Pin a value\n"
            "with the first hex char flipped (f9ef32...). Per SPEC §3.8 the\n"
            "SDK MUST enforce caller-supplied measurement pins; mismatch is\n"
            "MEASUREMENT_MISMATCH. Tests the policy-enforcement pipeline\n"
            "after-signature: the report verifies fine, the SDK then rejects."
        ),
    )
    write_fixture(
        fixture_id="410-host-data-pin-mismatch",
        title="policy.expected_host_data_hex mismatch → HOST_DATA_MISMATCH.",
        rejection_code="HOST_DATA_MISMATCH",
        spec_refs=["8.3"],
        policy={"expected_host_data_hex": "f" * 64},
        accepted=False,
        notes=(
            "Real bundle has host_data=0x00*32. Pin host_data=0xff*32. Per\n"
            "SPEC §8.3 host_data is the TLS pinning binding — the SDK MUST\n"
            "reject when the pinned value doesn't match what the enclave\n"
            "self-attested. Surfaces as HOST_DATA_MISMATCH."
        ),
    )
    write_fixture(
        fixture_id="420-report-data-pin-mismatch",
        title="policy.expected_report_data_hex mismatch → REPORT_DATA_MISMATCH.",
        rejection_code="REPORT_DATA_MISMATCH",
        spec_refs=["8.2"],
        policy={"expected_report_data_hex": _flip_hex(REAL_REPORT_DATA_HEX)},
        accepted=False,
        notes=(
            "Real bundle has report_data=71c31f...8603d. Pin first hex char\n"
            "flipped (f1c31f...). Per SPEC §8.2 report_data carries the TLS\n"
            "pubkey FP + HPKE pubkey binding; pin mismatch → REPORT_DATA_MISMATCH."
        ),
    )
    write_fixture(
        fixture_id="430-id-key-digest-pin-mismatch",
        title="policy.expected_id_key_digest_hex mismatch → ID_KEY_DIGEST_MISMATCH.",
        rejection_code="ID_KEY_DIGEST_MISMATCH",
        spec_refs=["3.1.1"],
        policy={"expected_id_key_digest_hex": "f" * 96},
        accepted=False,
        notes=(
            "Real bundle has id_key_digest=0x00*48 (no ID block). Pin a\n"
            "non-zero digest → ID_KEY_DIGEST_MISMATCH per SPEC §3.1.1.\n"
            "Use case: a fixture pinning ID block fingerprint catches an\n"
            "enclave that wasn't launched with the expected signing key."
        ),
    )
    write_fixture(
        fixture_id="440-author-key-digest-pin-mismatch",
        title="policy.expected_author_key_digest_hex mismatch → AUTHOR_KEY_DIGEST_MISMATCH.",
        rejection_code="AUTHOR_KEY_DIGEST_MISMATCH",
        spec_refs=["3.1.1"],
        policy={"expected_author_key_digest_hex": "f" * 96},
        accepted=False,
        notes=(
            "Real bundle has author_key_digest=0x00*48 (no author block).\n"
            "Pin a non-zero digest → AUTHOR_KEY_DIGEST_MISMATCH per SPEC §3.1.1.\n"
            "Parallel to fixture 430 for the author-key field."
        ),
    )
    write_fixture(
        fixture_id="450-tcb-bl-spl-below-min",
        title="policy.min_tcb_bl_spl above actual current_tcb.bl_spl → TCB_OUT_OF_DATE.",
        rejection_code="TCB_OUT_OF_DATE",
        spec_refs=["3.7"],
        policy={"min_tcb_bl_spl": 20},
        accepted=False,
        notes=(
            "Real bundle has current_tcb.bl_spl=10. Pin minimum=20. Per\n"
            "SPEC §3.7 the SDK MUST reject reports whose TCB is below the\n"
            "caller's minimum — TCB_OUT_OF_DATE. Same pattern for tee_spl,\n"
            "snp_spl, ucode_spl (see fixture 451)."
        ),
    )
    write_fixture(
        fixture_id="451-tcb-ucode-spl-below-min",
        title="policy.min_tcb_ucode_spl above actual current_tcb.ucode_spl → TCB_OUT_OF_DATE.",
        rejection_code="TCB_OUT_OF_DATE",
        spec_refs=["3.7"],
        policy={"min_tcb_ucode_spl": 200},
        accepted=False,
        notes=(
            "Real bundle has current_tcb.ucode_spl=84. Pin minimum=200. Per\n"
            "SPEC §3.7 → TCB_OUT_OF_DATE. Parallels fixture 450."
        ),
    )

    # ---- Accept fixtures: pins match --------------------------------------
    # Confirm the policy pin code paths are exercised (not just no-op'd).

    write_fixture(
        fixture_id="460-measurement-pin-match",
        title="policy.expected_measurement_hex equals report measurement → accepted.",
        spec_refs=["3.8"],
        policy={"expected_measurement_hex": REAL_MEASUREMENT_HEX},
        accepted=True,
        notes=(
            "Positive-accept companion to 400. Pins the exact measurement\n"
            "the report carries — confirms SDKs actually run the pin check\n"
            "(not just always-accept when set). Required for cross-SDK\n"
            "extended_checks_supported parity."
        ),
    )
    write_fixture(
        fixture_id="461-all-pins-match",
        title="All policy.expected_*_hex pins match → accepted.",
        spec_refs=["3.7", "3.8", "8.2", "8.3"],
        policy={
            "expected_measurement_hex": REAL_MEASUREMENT_HEX,
            "expected_host_data_hex": REAL_HOST_DATA_HEX,
            "expected_report_data_hex": REAL_REPORT_DATA_HEX,
            "expected_id_key_digest_hex": REAL_ID_KEY_DIGEST_HEX,
            "expected_author_key_digest_hex": REAL_AUTHOR_KEY_DIGEST_HEX,
            "min_tcb_bl_spl": 5,
            "min_tcb_ucode_spl": 50,
        },
        accepted=True,
        notes=(
            "Stacks every policy field at its actual real-bundle value.\n"
            "Exercises every pin path simultaneously. Future Phase 4B-SEV\n"
            "will use a synth-chain re-signed report to test the negative\n"
            "side of normative checks (DEBUG bit set, reserved bit set)\n"
            "without breaking signature verification."
        ),
    )

    print("Wrote Phase 4 attestation-sev fixtures:")
    for fid in (
        "400-measurement-pin-mismatch",
        "410-host-data-pin-mismatch",
        "420-report-data-pin-mismatch",
        "430-id-key-digest-pin-mismatch",
        "440-author-key-digest-pin-mismatch",
        "450-tcb-bl-spl-below-min",
        "451-tcb-ucode-spl-below-min",
        "460-measurement-pin-match",
        "461-all-pins-match",
    ):
        print(f"  - {VECTORS_DIR / fid}")


if __name__ == "__main__":
    main()
