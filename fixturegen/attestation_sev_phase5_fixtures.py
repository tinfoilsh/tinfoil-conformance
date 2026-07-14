#!/usr/bin/env python3
"""Phase 5 verify-attestation-sev fixtures: SPEC §3.7 policy-validation coverage
+ AMD/paper hardening probes.

The earlier phases covered the crypto chain, guest-policy reserved bits, and
BL/UCODE TCB minimums. SPEC §3.7.2 mandates a lot more that had no fixtures —
per-SPL TCB minimums (incl. committed/launch), the provisional-firmware
committed==current rule, firmware build/version minimums, PLATFORM_INFO (TSME),
and VMPL range. Each fixture here mutates exactly one field on the synth report;
the §3.7.1 default policy is expected to reject.

The fixtures deliberately pass NO fixture policy — they test whether an SDK
applies the §3.7.1 *defaults* automatically. rs/js drive their default
ValidationOptions, so they reject; go/py's conformance-adapter path skips these,
so they accept → the divergence surfaces (fixture fails on go/py).

Two are "decide-later" probes (behavior not pinned by spec): VMPL!=0 (rs alone
requires 0) and a masked CHIP_ID (should accept; py's adapter mishandles it).

All gate on attestation_sev.amd_root_ca_injection_supported (synthetic ARK/ASK),
so JS-without-injection would skip — but tinfoil-js supports injection, so it
runs.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "fixturegen"))

from lib.sev_synth import (  # noqa: E402
    ReportFields, SYNTH_CHIP_ID, SYNTH_TCB, TcbParts,
    build_report_body, gzip_b64, load_or_create_synth_chain, sign_report,
)

VECTORS_DIR = REPO_ROOT / "vectors" / "attestation-sev"
DEFAULT_DATE = 1780272000  # 2026-06-01

_CHAIN = load_or_create_synth_chain()


def _report_b64(fields: ReportFields) -> str:
    return gzip_b64(sign_report(build_report_body(fields), _CHAIN.vcek_priv))


def _base_fields(**overrides) -> ReportFields:
    """SYNTH baseline report fields (matches 604) with per-fixture overrides."""
    kw: dict[str, Any] = dict(
        current_tcb=SYNTH_TCB.to_u64(),
        reported_tcb=SYNTH_TCB.to_u64(),
        chip_id=SYNTH_CHIP_ID,
        measurement=bytes.fromhex("11" * 48),
        host_data=bytes.fromhex("22" * 32),
        report_data=bytes.fromhex("33" * 64),
        policy=0x30000,  # SMT + reserved-MBO — clean guest policy
    )
    kw.update(overrides)
    return ReportFields(**kw)


def _write(fixture_id, title, notes, spec_refs, fields, *, accepted, extra_caps=None):
    dst = VECTORS_DIR / fixture_id
    dst.mkdir(parents=True, exist_ok=True)
    inp = {
        "schema_version": "1",
        "attestation_doc_b64": _report_b64(fields),
        "vcek_der_b64": _CHAIN.vcek_der_b64,
        "amd_root_ca_pem": _CHAIN.ark_pem,
        "ask_pem": _CHAIN.ask_pem,
        "expiration_check_date_unix": DEFAULT_DATE,
    }
    (dst / "input.json").write_text(json.dumps(inp, indent=2) + "\n")
    expected: dict[str, Any] = {"stage": "verify-attestation-sev", "accepted": accepted}
    (dst / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")
    caps = {
        "attestation_sev.supported": True,
        "attestation_sev.injected_collateral_supported": True,
        "attestation_sev.amd_root_ca_injection_supported": True,
    }
    caps.update(extra_caps or {})
    manifest = (
        f"id: {fixture_id}\n"
        f"stage: verify-attestation-sev\n"
        f"title: |\n  {title}\n"
        f"spec_refs: {json.dumps(spec_refs)}\n"
        f"expects:\n"
        f"  exit_code: {0 if accepted else 10}\n"
        f"required_capabilities:\n"
    )
    for k, v in caps.items():
        manifest += f"  {k}: {json.dumps(v)}\n"
    manifest += "fixture_kind: synthetic-policy\nnotes: |\n"
    for line in notes.strip().splitlines():
        manifest += f"  {line}\n"
    (dst / "manifest.yaml").write_text(manifest)


def main() -> None:
    snp_low = TcbParts(bl_spl=10, tee_spl=0, snp_spl=13, ucode_spl=84).to_u64()  # snp < min 0x0E

    # 260 — SNP SPL below minimum (§3.7.2 #5). current+committed both low so the
    # provisional (committed==current) rule still holds; reported stays synth so
    # the VCEK-TCB match (§3.4.3) passes — isolating the SPL-minimum check.
    _write(
        "260-tcb-snp-spl-below-min",
        "current/committed TCB snp_spl below §3.7.1 minimum must reject (SPEC §3.7.2 #5).",
        """
current_tcb and committed_tcb carry snp_spl=13 (< default minimum 0x0E=14);
reported_tcb stays synth (23) so the VCEK↔reported TCB match passes. The
per-component TCB minimum (§3.7.2 #5) must reject. Companion to 450/451
(bl/ucode); adds the snp component. Rejects on SDKs that apply the §3.7.1
defaults; an SDK that skips default TCB-minimum enforcement accepts.
""",
        ["3.7.2", "3.2.1"],
        _base_fields(current_tcb=snp_low),
        accepted=False,
    )

    # 261 — provisional firmware: committed_build != current_build (§3.7.2 #12).
    # (Uses the build fields at 0x1F4/0x1F0 rather than committed_tcb, whose top
    # byte collides with an MBZ reserved byte at 0x1EF.)
    _write(
        "261-provisional-committed-ne-current",
        "committed firmware != current (provisional firmware) must reject (SPEC §3.7.2 #12).",
        """
current_build=30, committed_build=31 — both above the minimum (21) but unequal.
§3.7.1 sets permit_provisional_firmware=false (MUST be false), so §3.7.2 #12
requires committed == current (build/minor/major/tcb). Must reject. Directly
probes the provisional rule — an SDK running with permit_provisional_firmware
=true (a conformance adapter that sets it) accepts.
""",
        ["3.7.2", "3.7.1"],
        _base_fields(current_build=30, committed_build=31),
        accepted=False,
    )

    # 262 — firmware build below minimum (§3.7.2 #3, min build 21).
    _write(
        "262-firmware-build-below-min",
        "current+committed firmware build below §3.7.1 minimum (21) must reject (SPEC §3.7.2 #3).",
        """
current_build = committed_build = 10 (< minimum_build 21); equal, so the
provisional rule holds. §3.7.2 #3 requires both builds >= minimum_build. Must
reject.
""",
        ["3.7.2", "3.7.1"],
        _base_fields(current_build=10, committed_build=10),
        accepted=False,
    )

    # 263 — firmware API version below minimum (§3.7.2 #4, min 0x0137 = 1.55).
    _write(
        "263-firmware-version-below-min",
        "current+committed firmware version below §3.7.1 minimum (1.55) must reject (SPEC §3.7.2 #4).",
        """
current/committed major=1, minor=0 → version 0x0100 < minimum_version 0x0137
(1.55). Build left at the synth template. §3.7.2 #4 requires both versions >=
minimum_version. Must reject.
""",
        ["3.7.2", "3.7.1"],
        _base_fields(current_major=1, current_minor=0, committed_major=1, committed_minor=0),
        accepted=False,
    )

    # 264 — PLATFORM_INFO TSME not set (§3.7.2 #10; default tsme_enabled=true).
    _write(
        "264-platform-info-tsme-not-set",
        "PLATFORM_INFO with TSME_EN=0 must reject (SPEC §3.7.2 #10, default requires TSME).",
        """
platform_info = 0x01 (SMT_EN=1, TSME_EN=0). §3.7.1's default platform info sets
tsme_enabled=true, so §3.7.2 #10 requires TSME to be reported. Must reject. An
SDK whose conformance path never validates PLATFORM_INFO accepts.
""",
        ["3.7.2", "3.2.3"],
        _base_fields(platform_info=0x01),
        accepted=False,
    )

    # 265 — VMPL out of range (§3.7.2 #11: MUST be in 0..3).
    _write(
        "265-vmpl-out-of-range",
        "VMPL outside 0..3 must reject (SPEC §3.7.2 #11).",
        """
vmpl = 4, outside the mandated 0..3 range. §3.7.2 #11 says VMPL MUST be in range
0-3 (unconditionally). Must reject. An SDK that only checks VMPL when an expected
value is configured accepts.
""",
        ["3.7.2"],
        _base_fields(vmpl=4),
        accepted=False,
    )

    # 266 — VMPL non-zero but in range (DECIDE-LATER: spec only pins exact match
    # "when configured"; rs alone defaults to requiring VMPL==0).
    _write(
        "266-vmpl-nonzero-in-range",
        "VMPL=2 (in range, non-zero): spec accepts unless configured; probes SDKs that hard-require 0.",
        """
vmpl = 2 — valid range, non-zero. §3.7.2 #11 only mandates an exact match "when
configured", and the §3.7.1 defaults do not configure an expected VMPL, so the
spec-compliant outcome is ACCEPT. This probe surfaces SDKs that default to
requiring VMPL==0 (a hardening choice not in the spec). DECIDE-LATER: whether to
mandate VMPL==0 in the spec. Expected accept reflects the current spec.
""",
        ["3.7.2"],
        _base_fields(vmpl=2),
        accepted=True,
    )

    # 267 — masked CHIP_ID (§3.4.4 / §3.7.2 #9): MASK_CHIP_KEY set + zeroed
    # chip_id MUST be accepted (HWID binding skipped).
    _write(
        "267-mask-chip-id-accept",
        "Masked CHIP_ID (MASK_CHIP_KEY set, chip_id zeroed) must be accepted (SPEC §3.4.4).",
        """
signer_info = 0x02 (MASK_CHIP_KEY=1, signing_key=VCEK), chip_id all-zero. When
the platform masks the chip key, CHIP_ID is zeroed and the VCEK HWID binding is
skipped — the report is still valid. Expected ACCEPT. Probes SDKs whose adapter
does an unconditional HWID==chip_id comparison and wrongly rejects a masked
report.
""",
        ["3.4.4", "3.7.2"],
        _base_fields(signer_info=0x02, chip_id=bytes(64)),
        accepted=True,
    )

    print("Wrote Phase 5 attestation-sev §3.7 policy fixtures: 260-267")


if __name__ == "__main__":
    main()
