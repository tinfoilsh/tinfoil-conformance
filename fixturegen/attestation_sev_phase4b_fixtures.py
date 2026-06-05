#!/usr/bin/env python3
"""Generate Phase 4B verify-attestation-sev fixtures: synthetic policy violations.

Phase 4B mirrors the TDX Phase 4B pattern: each fixture builds a SEV-SNP
report whose cryptographic verification (cert chain + signature) succeeds
but which carries a normative SPEC §3.2.2 / §3.7 policy violation —
DEBUG bit set, reserved bits, MIGRATE_MA, etc. The lib's policy validator
(or the conformance binary's enforce_spec_defaults checks) MUST reject.

All fixtures use the persisted synth ARK/ASK/VCEK chain from
vectors/attestation-sev/_assets/synth_chain/. Cross-SDK gating:
  - Go binary: honors input.amd_root_ca_pem / input.ask_pem natively.
  - Python: same, after _maybe_override_amd_root monkey-patch lands.
  - JS: @tinfoilsh/verifier embeds ARK_CERT/ASK_CERT as frozen constants
    with no injection API → fixtures gate on a new
    attestation_sev.amd_root_ca_injection_supported capability and skip
    cleanly on JS until the lib gains an injection point.
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
    ReportFields, SYNTH_CHIP_ID, SYNTH_TCB,
    build_report_body, gzip_b64, load_or_create_synth_chain, sign_report,
)

VECTORS_DIR = REPO_ROOT / "vectors" / "attestation-sev"

# 2026-06-01 — well inside the synth chain's 2020..2099 validity window.
DEFAULT_DATE = 1780272000


def make_input(
    *,
    chain,
    fields: ReportFields,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = build_report_body(fields)
    signed_report = sign_report(body, chain.vcek_priv)
    payload: dict[str, Any] = {
        "schema_version": "1",
        "attestation_doc_b64": gzip_b64(signed_report),
        "vcek_der_b64": chain.vcek_der_b64,
        "amd_root_ca_pem": chain.ark_pem,
        "ask_pem": chain.ask_pem,
        "expiration_check_date_unix": DEFAULT_DATE,
    }
    if policy is not None:
        payload["policy"] = policy
    return payload


def write_fixture(
    *,
    fixture_id: str,
    title: str,
    notes: str,
    rejection_code: str | list[str],
    spec_refs: list[str],
    chain,
    fields: ReportFields,
    policy: dict[str, Any] | None = None,
) -> None:
    inp = make_input(chain=chain, fields=fields, policy=policy)
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
        f"  exit_code: 10\n"
        f"  rejection_code: {json.dumps(rejection_code)}\n"
        f"required_capabilities:\n"
        f"  attestation_sev.supported: true\n"
        f"  attestation_sev.injected_collateral_supported: true\n"
        f"  attestation_sev.amd_root_ca_injection_supported: true\n"
        "fixture_kind: synthetic-violation\n"
        "notes: |\n"
    )
    for line in notes.strip().splitlines():
        manifest += f"  {line}\n"
    (dst / "manifest.yaml").write_text(manifest)


def main() -> None:
    chain = load_or_create_synth_chain()
    tcb_u64 = SYNTH_TCB.to_u64()

    # Baseline fields shared by every Phase 4B fixture: synth chip_id +
    # TCB consistent with the cert, real-bundle measurement/host_data so
    # nothing unexpected mismatches. Each fixture overrides the field
    # under test.
    base_kwargs = dict(
        current_tcb=tcb_u64,
        reported_tcb=tcb_u64,
        chip_id=SYNTH_CHIP_ID,
        measurement=bytes.fromhex("11" * 48),
        host_data=bytes.fromhex("22" * 32),
        report_data=bytes.fromhex("33" * 64),
    )

    # ---- 600 — DEBUG bit set ---------------------------------------------
    # SPEC §3.2.2 GUEST_POLICY bit 19. SPEC §3.7 normative: a production-
    # attesting enclave MUST have debug=0. With bit 17 (reserved-MBO)
    # also set so go-sev-guest's lib-level validate.SnpAttestation runs
    # the DEBUG check before any other rejection.
    write_fixture(
        fixture_id="600-synth-debug-bit-set",
        title="Synth report with guest_policy.debug=1 → must reject as GUEST_POLICY_DEBUG_SET.",
        rejection_code="GUEST_POLICY_DEBUG_SET",
        spec_refs=["3.2.2", "3.7"],
        chain=chain,
        fields=ReportFields(
            **base_kwargs,
            # bits set: 17 (reserved-MBO must be 1), 19 (DEBUG — the
            # violation), 16 (SMT — Tinfoil-policy allows). Hex: 0xB0000.
            policy=0xB0000,
        ),
        policy={"enforce_spec_defaults": True},
        notes=(
            "Synth report signed by the persisted synth VCEK; signature\n"
            "verifies fine but bit 19 (DEBUG) is set. SPEC §3.7 says the\n"
            "SDK MUST reject any production-attesting report with DEBUG=1\n"
            "(a debug-mode enclave can be inspected by the host so its\n"
            "measurements are not trustworthy).\n"
            "\n"
            "Two paths to rejection:\n"
            "  (a) lib-level: validate.SnpAttestation with GuestPolicy.Debug=false\n"
            "      catches this regardless of fixture policy.\n"
            "  (b) conformance-binary: enforce_spec_defaults=true triggers\n"
            "      the explicit DEBUG bit check.\n"
            "Either should produce GUEST_POLICY_DEBUG_SET."
        ),
    )

    # ---- 601 — reserved-MBO bit (17) cleared -----------------------------
    write_fixture(
        fixture_id="601-synth-reserved-mbo-cleared",
        title="Synth report with guest_policy bit 17 (reserved-MBO) cleared → GUEST_POLICY_RESERVED_BIT_SET.",
        rejection_code="GUEST_POLICY_RESERVED_BIT_SET",
        spec_refs=["3.2.2", "3.7"],
        chain=chain,
        fields=ReportFields(
            **base_kwargs,
            # bits: 16 (SMT) only — bit 17 deliberately cleared (must-be-1
            # per AMD APM Vol 3 Table B-3).
            policy=0x10000,
        ),
        policy={"enforce_spec_defaults": True},
        notes=(
            "Bit 17 of guest_policy is reserved-must-be-one per AMD APM\n"
            "Vol 3 Table B-3. Clearing it is a SPEC §3.2.2 violation that\n"
            "the conformance binary's enforce_spec_defaults check MUST\n"
            "catch. Surfaces as GUEST_POLICY_RESERVED_BIT_SET."
        ),
    )

    # ---- 602 — reserved-MBZ bit (>=25) set -------------------------------
    write_fixture(
        fixture_id="602-synth-reserved-mbz-set",
        title="Synth report with guest_policy bit 30 (reserved-MBZ) set → GUEST_POLICY_RESERVED_BIT_SET.",
        rejection_code="GUEST_POLICY_RESERVED_BIT_SET",
        spec_refs=["3.2.2", "3.7"],
        chain=chain,
        fields=ReportFields(
            **base_kwargs,
            # bits: 16 (SMT), 17 (reserved-MBO), 30 (reserved-MBZ — the violation).
            # Hex: 0x40030000.
            policy=0x40030000,
        ),
        policy={"enforce_spec_defaults": True},
        notes=(
            "Bits 25..63 of guest_policy are reserved-must-be-zero per\n"
            "AMD APM Vol 3 Table B-3. Setting bit 30 forces the\n"
            "enforce_spec_defaults reserved-MBZ check to reject."
        ),
    )

    # ---- 603 — MIGRATE_MA set --------------------------------------------
    # Tinfoil's production policy forbids migration. Lib-level validate.
    # SnpAttestation has MigrateMA: false, so the lib catches this even
    # without enforce_spec_defaults.
    write_fixture(
        fixture_id="603-synth-migrate-ma-set",
        title="Synth report with guest_policy.migrate_ma=1 (bit 18) → GUEST_POLICY_MIGRATE_MA_SET.",
        rejection_code="GUEST_POLICY_MIGRATE_MA_SET",
        spec_refs=["3.2.2", "3.7"],
        chain=chain,
        fields=ReportFields(
            **base_kwargs,
            # bits: 16 (SMT), 17 (MBO), 18 (MIGRATE_MA — violation).
            policy=0x70000,
        ),
        notes=(
            "Tinfoil's production policy forbids migration (guest_policy.migrate_ma\n"
            "must be 0). go-sev-guest's validate.SnpAttestation with\n"
            "GuestPolicy.MigrateMA=false rejects with 'found unauthorized\n"
            "migration agent capability'. The conformance binary translates\n"
            "this into a dedicated GUEST_POLICY_MIGRATE_MA_SET rejection code\n"
            "(not in SPEC §3.7's enumeration but cleaner than the\n"
            "QV_RESULT_TERMINAL_UNSPECIFIED fallback).\n"
            "\n"
            "Note: SPEC §3.7 doesn't enumerate MIGRATE_MA as a normative\n"
            "rejection — this is Tinfoil-policy tightening on top of the\n"
            "AMD-defined guest policy bits."
        ),
    )

    # ---- 604 — synth baseline accept (sanity) ----------------------------
    # Mirror Phase 4B baseline: a synth report with NO policy violations
    # MUST be accepted. Confirms the synth chain itself isn't producing
    # spurious rejections.
    accept_inp = make_input(
        chain=chain,
        fields=ReportFields(**base_kwargs, policy=0x30000),  # SMT + reserved-MBO
        policy={"enforce_spec_defaults": True},
    )
    (VECTORS_DIR / "604-synth-baseline-accept").mkdir(parents=True, exist_ok=True)
    (VECTORS_DIR / "604-synth-baseline-accept" / "input.json").write_text(json.dumps(accept_inp, indent=2))
    (VECTORS_DIR / "604-synth-baseline-accept" / "expected.json").write_text(json.dumps({
        "stage": "verify-attestation-sev",
        "accepted": True,
    }, indent=2))
    (VECTORS_DIR / "604-synth-baseline-accept" / "manifest.yaml").write_text(
        "id: 604-synth-baseline-accept\n"
        "stage: verify-attestation-sev\n"
        "title: |\n"
        "  Synth chain + clean policy report (SMT+MBO only) verifies → accepted.\n"
        "spec_refs: [\"3.2.2\", \"3.7\"]\n"
        "expects:\n"
        "  exit_code: 0\n"
        "required_capabilities:\n"
        "  attestation_sev.supported: true\n"
        "  attestation_sev.injected_collateral_supported: true\n"
        "  attestation_sev.amd_root_ca_injection_supported: true\n"
        "fixture_kind: synthetic-baseline\n"
        "notes: |\n"
        "  Sanity-companion to fixtures 600-603. Synth chain + synth report\n"
        "  with the minimal-correct guest_policy (bits 16+17 = SMT+MBO only,\n"
        "  no DEBUG/MIGRATE/reserved-MBZ) — the SDK MUST accept. Confirms\n"
        "  the negative fixtures fail on policy alone, not on a defect in\n"
        "  the synth chain.\n"
    )

    print("Wrote Phase 4B attestation-sev fixtures:")
    for fid in (
        "600-synth-debug-bit-set",
        "601-synth-reserved-mbo-cleared",
        "602-synth-reserved-mbz-set",
        "603-synth-migrate-ma-set",
        "604-synth-baseline-accept",
    ):
        print(f"  - {VECTORS_DIR / fid}")


if __name__ == "__main__":
    main()
