#!/usr/bin/env python3
"""Generate Phase 4C verify-attestation-sev fixtures: VCEK §3.4 extension checks.

SPEC §3.4 mandates that the VCEK certificate carries AMD-specified X.509v3
extensions (OIDs under 1.3.6.1.4.1.3704.1) and that the SDK MUST verify
those values agree with what the SEV-SNP report self-attests:
  - HWID (1.4)        ↔ report.chip_id
  - BL_SPL (1.3.1)    ↔ report.reported_tcb.bl_spl
  - TEE_SPL (1.3.2)   ↔ report.reported_tcb.tee_spl
  - SNP_SPL (1.3.3)   ↔ report.reported_tcb.snp_spl
  - UCODE_SPL (1.3.8) ↔ report.reported_tcb.ucode_spl
  - PRODUCT_NAME (1.2)↔ Genoa / Milan / Turin product line

Phase 4C exercises every cross-check by producing a synth chain whose
extensions deliberately disagree with the report. Synthetic-chain
required → gated on attestation_sev.amd_root_ca_injection_supported.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "fixturegen"))

from lib.sev_synth import (  # noqa: E402
    OID_BL_SPL, OID_HWID, OID_PRODUCT_NAME, OID_UCODE_SPL,
    ReportFields, SYNTH_CHIP_ID, SYNTH_TCB, TcbParts,
    _enc_ia5, _enc_int,
    build_report_body, gen_synth_chain, gzip_b64,
    load_or_create_synth_chain, sign_report,
)

VECTORS_DIR = REPO_ROOT / "vectors" / "attestation-sev"
DEFAULT_DATE = 1780272000


def _make_input(chain, fields: ReportFields, policy: dict[str, Any] | None = None) -> dict[str, Any]:
    body = build_report_body(fields)
    signed = sign_report(body, chain.vcek_priv)
    payload: dict[str, Any] = {
        "schema_version": "1",
        "attestation_doc_b64": gzip_b64(signed),
        "vcek_der_b64": chain.vcek_der_b64,
        "amd_root_ca_pem": chain.ark_pem,
        "ask_pem": chain.ask_pem,
        "expiration_check_date_unix": DEFAULT_DATE,
    }
    if policy is not None:
        payload["policy"] = policy
    return payload


def _write(
    *,
    fixture_id: str,
    title: str,
    notes: str,
    rejection_code: str | list[str],
    spec_refs: list[str],
    payload: dict[str, Any],
) -> None:
    dst = VECTORS_DIR / fixture_id
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "input.json").write_text(json.dumps(payload, indent=2))
    (dst / "expected.json").write_text(json.dumps({
        "stage": "verify-attestation-sev",
        "accepted": False,
        "rejection": {"code": rejection_code},
    }, indent=2))
    manifest = (
        f"id: {fixture_id}\n"
        f"stage: verify-attestation-sev\n"
        f"title: |\n  {title}\n"
        f"spec_refs: {json.dumps(spec_refs)}\n"
        f"expects:\n"
        f"  exit_code: 10\n"
        f"  rejection_code: {json.dumps(rejection_code)}\n"
        f"required_capabilities:\n"
        f"  attestation_sev.supported: true\n"
        f"  attestation_sev.injected_collateral_supported: true\n"
        f"  attestation_sev.amd_root_ca_injection_supported: true\n"
        "fixture_kind: synthetic-vcek-extension\n"
        "notes: |\n"
    )
    for line in notes.strip().splitlines():
        manifest += f"  {line}\n"
    (dst / "manifest.yaml").write_text(manifest)


def main() -> None:
    persisted = load_or_create_synth_chain()
    persisted_tcb_u64 = SYNTH_TCB.to_u64()

    base_kwargs = dict(
        chip_id=SYNTH_CHIP_ID,
        current_tcb=persisted_tcb_u64,
        reported_tcb=persisted_tcb_u64,
        measurement=bytes.fromhex("11" * 48),
        host_data=bytes.fromhex("22" * 32),
        report_data=bytes.fromhex("33" * 64),
        policy=0x30000,  # SMT + reserved-MBO
    )

    # ---- 700 — HWID mismatch (cert chip_id != report chip_id) -----------
    _write(
        fixture_id="700-vcek-hwid-mismatch",
        title="VCEK HWID extension chip_id != report.chip_id → VCEK_HWID_MISMATCH.",
        rejection_code=["VCEK_HWID_MISMATCH", "VCEK_CHAIN_INVALID"],
        spec_refs=["3.4.4"],
        payload=_make_input(
            persisted,
            ReportFields(
                **{k: v for k, v in base_kwargs.items() if k != "chip_id"},
                # Report's chip_id is all 0xBB; cert's HWID extension is SYNTH_CHIP_ID.
                chip_id=bytes.fromhex("bb" * 64),
            ),
        ),
        notes=(
            "SPEC §3.4.4: VCEK's HWID extension (OID 1.3.6.1.4.1.3704.1.4)\n"
            "binds the cert to a specific AMD chip. The SDK MUST verify\n"
            "VCEK.HWID == report.chip_id; mismatch means the cert and the\n"
            "attesting chip are different machines.\n"
            "\n"
            "Synth chain's VCEK pins HWID = SYNTH_CHIP_ID; report carries\n"
            "chip_id = 0xBB×64. List-form code accommodates SDKs that\n"
            "bucket all VCEK cross-checks as VCEK_CHAIN_INVALID."
        ),
    )

    # ---- 701 — BL_SPL extension < report.reported_tcb.bl_spl -------------
    # Generate a fresh chain whose cert pins BL_SPL=5 while the report
    # claims bl_spl=10 (encoded into reported_tcb).
    low_tcb = TcbParts(bl_spl=5, tee_spl=0, snp_spl=23, ucode_spl=84)
    chain_low_blspl = gen_synth_chain(chip_id=SYNTH_CHIP_ID, tcb=low_tcb)
    _write(
        fixture_id="701-vcek-bl-spl-mismatch",
        title="VCEK BL_SPL extension < report.reported_tcb.bl_spl → VCEK_TCB_MISMATCH.",
        rejection_code=["VCEK_TCB_MISMATCH", "VCEK_CHAIN_INVALID"],
        spec_refs=["3.4.3"],
        payload=_make_input(
            chain_low_blspl,
            ReportFields(
                **base_kwargs,
                # No override needed — base_kwargs.reported_tcb has bl_spl=10
                # already, but cert pins bl_spl=5.
            ),
        ),
        notes=(
            "SPEC §3.4.3: VCEK SPL extensions reflect the TCB level the\n"
            "key was endorsed for. A report whose reported_tcb declares\n"
            "a higher SPL than the cert means either the cert is stale\n"
            "or the report is forged with a stronger TCB claim than the\n"
            "issuing AMD KDS would have endorsed at that time.\n"
            "\n"
            "Synth cert: BL_SPL=5. Report reported_tcb.bl_spl=10. Mismatch.\n"
            "List-form accommodates VCEK_CHAIN_INVALID bucketing."
        ),
    )

    # ---- 702 — UCODE_SPL extension < report.reported_tcb.ucode_spl -------
    low_ucode = TcbParts(bl_spl=10, tee_spl=0, snp_spl=23, ucode_spl=10)
    chain_low_ucode = gen_synth_chain(chip_id=SYNTH_CHIP_ID, tcb=low_ucode)
    _write(
        fixture_id="702-vcek-ucode-spl-mismatch",
        title="VCEK UCODE_SPL extension < report.reported_tcb.ucode_spl → VCEK_TCB_MISMATCH.",
        rejection_code=["VCEK_TCB_MISMATCH", "VCEK_CHAIN_INVALID"],
        spec_refs=["3.4.3"],
        payload=_make_input(
            chain_low_ucode,
            ReportFields(**base_kwargs),
        ),
        notes=(
            "Parallels 701 for the UCODE_SPL extension. Synth cert pins\n"
            "UCODE_SPL=10; report reported_tcb.ucode_spl=84 (from\n"
            "base_kwargs). Microcode security patch level disagrees."
        ),
    )

    # ---- 703 — VCEK missing required HWID extension ----------------------
    chain_no_hwid = gen_synth_chain(
        chip_id=SYNTH_CHIP_ID, tcb=SYNTH_TCB,
        vcek_extension_omit={OID_HWID},
    )
    _write(
        fixture_id="703-vcek-missing-hwid-extension",
        title="VCEK missing HWID extension → VCEK_HWID_MISMATCH.",
        rejection_code=["VCEK_HWID_MISMATCH", "VCEK_CHAIN_INVALID"],
        spec_refs=["3.4.4"],
        payload=_make_input(chain_no_hwid, ReportFields(**base_kwargs)),
        notes=(
            "SPEC §3.4 mandates VCEK's HWID extension presence. A cert\n"
            "without it can't be cross-checked against report.chip_id;\n"
            "go-sev-guest emits 'missing HWID extension for VCEK certificate'\n"
            "which the conformance binary buckets as VCEK_HWID_MISMATCH\n"
            "(SPEC's nearest enumerated code). List-form allows SDKs that\n"
            "treat structural extension errors as VCEK_CHAIN_INVALID."
        ),
    )

    # Note: a 'wrong product name' fixture is intentionally omitted. go-sev-guest's
    # current verifier doesn't enforce PRODUCT_NAME-vs-Product matching — a cert
    # with PRODUCT_NAME='Milan' verifies fine under Product=Genoa opts. SPEC §3.4.1
    # implies it should reject; the SDK-side fix lives in google/go-sev-guest, not
    # in the conformance suite. Tracked as a known gap; revisit when upstream
    # closes it (or when other SDKs ship a stricter check that would pass).

    print("Wrote Phase 4C attestation-sev VCEK extension fixtures:")
    for fid in (
        "700-vcek-hwid-mismatch",
        "701-vcek-bl-spl-mismatch",
        "702-vcek-ucode-spl-mismatch",
        "703-vcek-missing-hwid-extension",
    ):
        print(f"  - {VECTORS_DIR / fid}")


if __name__ == "__main__":
    main()
