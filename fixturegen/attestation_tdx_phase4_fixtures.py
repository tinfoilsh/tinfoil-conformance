#!/usr/bin/env python3
"""Generate Phase 4 verify-attestation-tdx fixtures: extended TD checks.

Tests SPEC §4.8 / Intel §2.3.2 — the policy-validation layer the Intel
QVL does NOT run but the relying party must. Each fixture takes the
unmutated real Intel-signed SPR E4 quote and pins a single
policy.expected_*_hex field to a value that mismatches what's in the
quote, triggering the corresponding rejection code.

Why policy-pin and not byte-mutation: mutating any body byte breaks the
AK signature → quote sig verification rejects before policy enforcement
ever runs. Pinning an expected value against the real quote tests the
policy-comparison machinery, which is what SPEC §4.8 actually mandates.

Pattern matches the JS feat/tdx-support branch's empirically-observed
behavior: its defaultTdxValidationOptions hardcoded a Tinfoil-pinned
TDATTRIBUTES expected value (`0000001000000000`) and rejected anything
else — the same expected value used by the SPEC §4.8.6 defaults.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = REPO_ROOT / "vectors" / "attestation-tdx"
ASSETS = VECTORS_DIR / "_assets"

BASE_QUOTE = (ASSETS / "tdx_prod_quote_SPR_E4.dat").read_bytes()
BASE_TCB_INFO = (ASSETS / "tcb_info_v15_fmspc_50806f.json").read_text()
BASE_QE_IDENTITY = (ASSETS / "qe_identity_v15.json").read_text()
BASE_PCK_CRL = (ASSETS / "pck_crl.der").read_bytes()
BASE_ROOT_CRL = (ASSETS / "root_crl.der").read_bytes()

DEFAULT_DATE = 1688083200


def write_fixture(
    *,
    fixture_id: str,
    title: str,
    notes: str,
    policy: dict[str, Any],
    rejection_code: str | list[str],
    spec_refs: list[str] | None = None,
) -> None:
    """Write a Phase 4 reject-path fixture. Quote is the unmutated real
    one; policy carries the pin that triggers rejection."""
    inp: dict[str, Any] = {
        "schema_version": "1",
        "quote_b64": base64.standard_b64encode(BASE_QUOTE).decode(),
        "collateral": {
            "tcb_info_json": BASE_TCB_INFO,
            "qe_identity_json": BASE_QE_IDENTITY,
            "pck_crl_der_b64": base64.standard_b64encode(BASE_PCK_CRL).decode(),
            "root_crl_der_b64": base64.standard_b64encode(BASE_ROOT_CRL).decode(),
        },
        "expiration_check_date_unix": DEFAULT_DATE,
        "policy": {"tcb_evaluation_required": False, **policy},
    }
    dst = VECTORS_DIR / fixture_id
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "input.json").write_text(json.dumps(inp, indent=2))
    (dst / "expected.json").write_text(json.dumps(
        {"stage": "verify-attestation-tdx", "accepted": False,
         "rejection": {"code": rejection_code}}, indent=2))

    refs = spec_refs or ["4.8"]
    manifest = (
        f"id: {fixture_id}\n"
        f"stage: verify-attestation-tdx\n"
        f"title: |\n  {title}\n"
        f"spec_refs: {json.dumps(refs)}\n"
        f"expects:\n"
        f"  exit_code: 10\n"
        f"  rejection_code: {json.dumps(rejection_code)}\n"
        "required_capabilities:\n"
        "  attestation_tdx.supported: true\n"
        "  attestation_tdx.injected_collateral_supported: true\n"
        "  attestation_tdx.extended_td_checks_supported: true\n"
        "fixture_kind: synthetic-policy-pin\n"
        "notes: |\n"
    )
    for line in notes.strip().splitlines():
        manifest += f"  {line}\n"
    (dst / "manifest.yaml").write_text(manifest)


ZERO_48 = "00" * 48
ZERO_8 = "00" * 8


def main() -> None:
    # 400 — TD Attributes policy pin mismatch
    write_fixture(
        fixture_id="400-td-attributes-mismatch",
        title="policy.expected_td_attributes=SPEC default → real quote has PKS bit set → reject.",
        notes=(
            "SPEC §4.8.6 default is 0000001000000000 (only SEPT_VE_DIS=1).\n"
            "The base quote has 0000004000000000 (PKS=1, all other bits 0\n"
            "including DEBUG=0). Mismatch under strict-pin policy → reject.\n"
            "Empirically the JS feat/tdx-support branch's defaultTdxValidation\n"
            "Options uses exactly this default; the same SPR E4 test quote\n"
            "triggers the same rejection there ('TD attributes mismatch:\n"
            "got 0000004000000000, expected 0000001000000000').\n"
            "\n"
            "Beyond pin enforcement: SPEC §4.8.2 requires DEBUG=0 — the real\n"
            "quote satisfies that, so this fixture verifies the pin\n"
            "comparison machinery, not the DEBUG bit policy specifically.\n"
            "A DEBUG=1 fixture would need either a debug-mode quote we don't\n"
            "have, or an extraction-only mode that bypasses AK signature\n"
            "verification."
        ),
        policy={"expected_td_attributes_hex": "0000001000000000"},
        rejection_code="TD_ATTRIBUTES_MISMATCH",
        spec_refs=["4.8.2"],
    )

    # 410 — XFAM policy pin mismatch
    write_fixture(
        fixture_id="410-xfam-mismatch",
        title="policy.expected_xfam pinned to a value the quote doesn't match → reject.",
        notes=(
            "Real quote has xfam=e71a060000000000. Policy pins\n"
            "0000000000000000 (all zero — would violate SPEC §4.8.1\n"
            "XFAM_FIXED1 requirement that FP+SSE bits be set). The fixture\n"
            "verifies the pin comparison works."
        ),
        policy={"expected_xfam_hex": "0000000000000000"},
        rejection_code="XFAM_MISMATCH",
        spec_refs=["4.8.1"],
    )

    # 420 — MR_SIGNER_SEAM mismatch (real is zero, pin non-zero)
    write_fixture(
        fixture_id="420-mrsignerseam-pinned-mismatch",
        title="policy.expected_mr_signer_seam pinned non-zero; real quote has all-zero → reject.",
        notes=(
            "SPEC §4.8.4 requires MR_SIGNER_SEAM be all-zero for current\n"
            "Intel TDX module releases. Real quote satisfies that. Pinning\n"
            "the policy to a non-zero expected value triggers a mismatch,\n"
            "demonstrating the binary enforces the pin even when the SPEC\n"
            "default would have been satisfied."
        ),
        policy={"expected_mr_signer_seam_hex": "aa" * 48},
        rejection_code="MR_SIGNER_SEAM_MISMATCH",
        spec_refs=["4.8.4"],
    )

    # 421 — SEAM_ATTRIBUTES mismatch (real is zero, pin non-zero)
    write_fixture(
        fixture_id="421-seam-attributes-pinned-mismatch",
        title="policy.expected_seam_attributes pinned non-zero; real quote has all-zero → reject.",
        notes=(
            "SPEC §4.8.3 requires SEAM_ATTRIBUTES be all-zero for TDX\n"
            "1.0/1.5/2.0. Real quote satisfies. Pin non-zero → mismatch."
        ),
        policy={"expected_seam_attributes_hex": "aabbccdd11223344"},
        rejection_code="SEAM_ATTRIBUTES_MISMATCH",
        spec_refs=["4.8.3"],
    )

    # 430 — MR_SEAM not in allowlist
    write_fixture(
        fixture_id="430-mrseam-not-in-allowlist",
        title="MR_SEAM not in policy allowlist → reject (SPEC §4.8.5).",
        notes=(
            "SPEC §4.8.5 requires exact 48-byte match against a list of\n"
            "known-good Intel TDX module MR_SEAM values. Real quote's\n"
            "MR_SEAM is 2fd279c1...c656; allowlist contains two other\n"
            "values from the SPEC §4.8.5 table (TDX 2.0.08 and 1.5.16).\n"
            "Neither matches → MR_SEAM_NOT_ALLOWED."
        ),
        policy={"expected_mrseam_allowlist": [
            # SPEC §4.8.5 known values:
            "476a2997c62bccc78370913d0a80b956e3721b24272bc66c4d6307ced4be2865c40e26afac75f12df3425b03eb59ea7c",
            "7bf063280e94fb051f5dd7b1fc59ce9aac42bb961df8d44b709c9b0ff87a7b4df648657ba6d1189589feab1d5a3c9a9d",
        ]},
        rejection_code="MR_SEAM_NOT_ALLOWED",
        spec_refs=["4.8.5"],
    )

    # 440 — MRTD pinned mismatch
    write_fixture(
        fixture_id="440-mrtd-pinned-mismatch",
        title="MRTD pinned to a different build digest → reject.",
        notes=(
            "Real quote's MRTD is the SPR E4 test TD's build hash. Policy\n"
            "pins a different 48-byte value, representing 'expected a\n"
            "different release.' Catches the case where the TLS pinning is\n"
            "wired but the verifier doesn't actually cross-check the build."
        ),
        policy={"expected_mrtd_hex": "ff" * 48},
        rejection_code="MRTD_MISMATCH",
        spec_refs=["4.10"],
    )

    # 450 — RTMR3 must be zero (real satisfies; pin non-zero to trigger mismatch)
    write_fixture(
        fixture_id="450-rtmr3-pinned-mismatch",
        title="RTMR3 pinned non-zero; real quote is all-zero → reject.",
        notes=(
            "SPEC §7.3.6 carries to TDX: RTMR3 MUST be all zeros. Real\n"
            "quote satisfies. Pinning non-zero verifies the binary applies\n"
            "the pin (catches a verifier that extracts RTMR3 but never\n"
            "compares it)."
        ),
        policy={"expected_rtmr3_hex": "01" + "00" * 47},
        rejection_code="RTMR3_NONZERO",
        spec_refs=["4.10", "7.3.6"],
    )

    # 460 — REPORT_DATA pinned mismatch
    write_fixture(
        fixture_id="460-report-data-pinned-mismatch",
        title="REPORT_DATA pinned to a different value → reject.",
        notes=(
            "SPEC §8.2 binds REPORT_DATA[0:32] = SHA-256(TLS public key\n"
            "SPKI). Real quote's REPORT_DATA is 6c62dec1...; policy pins a\n"
            "different 64-byte value. Reject confirms the verifier cross-\n"
            "checks the binding — without this, an attacker could replay a\n"
            "valid TDX quote against an unrelated TLS endpoint."
        ),
        policy={"expected_report_data_hex": "11" * 64},
        rejection_code="REPORT_DATA_MISMATCH",
        spec_refs=["8.2"],
    )

    # 470 — MR_CONFIG_ID mismatch (real is zero, pin non-zero)
    write_fixture(
        fixture_id="470-mr-config-id-pinned-mismatch",
        title="MR_CONFIG_ID pinned non-zero; real is all-zero → reject.",
        notes="SPEC §4.8.6 default is all-zero. Real satisfies. Pin non-zero → mismatch.",
        policy={"expected_mr_config_id_hex": "ab" * 48},
        rejection_code="MR_CONFIG_ID_MISMATCH",
        spec_refs=["4.8.6"],
    )

    # 471 — MR_OWNER mismatch (real is zero, pin non-zero)
    write_fixture(
        fixture_id="471-mr-owner-pinned-mismatch",
        title="MR_OWNER pinned non-zero; real is all-zero → reject.",
        notes="SPEC §4.8.6 default is all-zero. Real satisfies. Pin non-zero → mismatch.",
        policy={"expected_mr_owner_hex": "cd" * 48},
        rejection_code="MR_OWNER_MISMATCH",
        spec_refs=["4.8.6"],
    )

    # 472 — MR_OWNER_CONFIG mismatch (real is zero, pin non-zero)
    write_fixture(
        fixture_id="472-mr-owner-config-pinned-mismatch",
        title="MR_OWNER_CONFIG pinned non-zero; real is all-zero → reject.",
        notes="SPEC §4.8.6 default is all-zero. Real satisfies. Pin non-zero → mismatch.",
        policy={"expected_mr_owner_config_hex": "ef" * 48},
        rejection_code="MR_OWNER_CONFIG_MISMATCH",
        spec_refs=["4.8.6"],
    )

    # 480 — Min TEE_TCB_SVN above quote's
    write_fixture(
        fixture_id="480-tee-tcb-svn-below-minimum",
        title="policy.min_tee_tcb_svn higher than quote's components → reject (SPEC §4.8.7).",
        notes=(
            "Real quote has tee_tcb_svn=03000400000000000000000000000000.\n"
            "Min policy pins each byte to 0xFF — the quote's byte 0 (3) is\n"
            "below 0xFF, triggering rejection on the very first comparison.\n"
            "Verifies the component-wise comparison runs left-to-right."
        ),
        policy={"min_tee_tcb_svn_hex": "ff" * 16},
        rejection_code="TEE_TCB_SVN_BELOW_MINIMUM",
        spec_refs=["4.8.7"],
    )

    # 490 — QE Vendor ID mismatch
    write_fixture(
        fixture_id="490-qe-vendor-id-mismatch",
        title="QE Vendor ID pinned to a non-Intel value → real quote has Intel UUID → reject.",
        notes=(
            "SPEC §4.8.6 default is 939a7233f79c4ca9940a0db3957f0607\n"
            "(Intel). Real quote matches. Pinning a different UUID\n"
            "demonstrates the binary applies the QE Vendor pin (catches an\n"
            "SDK that reads the field but never compares it)."
        ),
        policy={"expected_qe_vendor_id_hex": "00" * 16},
        rejection_code="QE_VENDOR_ID_MISMATCH",
        spec_refs=["4.8.6"],
    )

    print("Wrote Phase 4 attestation-tdx fixtures:")
    for d in sorted(VECTORS_DIR.iterdir()):
        if d.is_dir() and d.name[:1] == "4":
            print(f"  {d.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
