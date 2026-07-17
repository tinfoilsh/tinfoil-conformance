#!/usr/bin/env python3
"""Phase 6 verify-attestation-sev fixtures: close remaining SPEC §3.7.2 coverage
gaps found in the 2026-07 coverage audit.

Each fixture mutates exactly one field on the synth baseline and is expected to
reject under the §3.7.1 default policy (or, for the platform-info "required"
probes, encodes the hardened stance so the gap surfaces — same pattern as
270/271). Gates on attestation_sev.amd_root_ca_injection_supported (synthetic
ARK/ASK), like the other 6xx/2xx synth fixtures.

Coverage added:
  452  §3.7.2 #7   launch_tcb below minimum_launch_tcb
  605  §3.7.2 #1   guest policy cxl_allowed set (not allowed by default)
  606  §3.7.2 #1   guest policy mem_aes256_xts set (not allowed by default)
  272  §3.7.2 #10  platform_info ECC not enabled (required-probe; not required by default)
  273  §3.7.2 #10  platform_info RAPL not disabled (required-probe; PLATYPUS-class)
  274  §3.7.2 #10  platform_info TIO not enabled (required-probe; SEV-TIO)
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

# guest-policy bit values (SPEC §3.2.2 / field 0x08)
POLICY_BASE = 0x30000       # smt(16) + reserved-MBO(17)
POLICY_CXL = 1 << 21        # cxl_allowed
POLICY_MEM_AES256_XTS = 1 << 22

# platform_info bit values (SPEC §3.2.3 / field 0x40)
PI_SMT = 1 << 0
PI_TSME = 1 << 1
PI_ECC = 1 << 2
PI_RAPL_DIS = 1 << 3
PI_TIO = 1 << 7


def _report_b64(fields: ReportFields) -> str:
    return gzip_b64(sign_report(build_report_body(fields), _CHAIN.vcek_priv))


def _base_fields(**overrides) -> ReportFields:
    kw: dict[str, Any] = dict(
        current_tcb=SYNTH_TCB.to_u64(),
        reported_tcb=SYNTH_TCB.to_u64(),
        committed_tcb=SYNTH_TCB.to_u64(),  # == current: keep provisional check clean
        chip_id=SYNTH_CHIP_ID,
        measurement=bytes.fromhex("11" * 48),
        host_data=bytes.fromhex("22" * 32),
        report_data=bytes.fromhex("33" * 64),
        policy=POLICY_BASE,
        platform_info=PI_SMT | PI_TSME,
    )
    kw.update(overrides)
    return ReportFields(**kw)


def _write(fixture_id, title, notes, spec_refs, fields, *, accepted):
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
    (dst / "expected.json").write_text(
        json.dumps({"stage": "verify-attestation-sev", "accepted": accepted}, indent=2) + "\n"
    )
    manifest = (
        f"id: {fixture_id}\n"
        f"stage: verify-attestation-sev\n"
        f"title: |\n  {title}\n"
        f"spec_refs: {json.dumps(spec_refs)}\n"
        f"expects:\n"
        f"  exit_code: {0 if accepted else 10}\n"
        f"required_capabilities:\n"
        f"  attestation_sev.supported: true\n"
        f"  attestation_sev.injected_collateral_supported: true\n"
        f"  attestation_sev.amd_root_ca_injection_supported: true\n"
        f"fixture_kind: synthetic-policy\n"
        f"notes: |\n"
    )
    for line in notes.strip().splitlines():
        manifest += f"  {line}\n"
    (dst / "manifest.yaml").write_text(manifest)


def main() -> None:
    snp_low = TcbParts(bl_spl=10, tee_spl=0, snp_spl=13, ucode_spl=84).to_u64()  # snp < 0x0E

    # 452 — launch_tcb below minimum_launch_tcb (§3.7.2 #7). current/committed/
    # reported all stay at the valid SYNTH baseline; only launch_tcb is low.
    _write(
        "452-tcb-launch-below-min",
        "launch_tcb below §3.7.1 minimum_launch_tcb must reject (SPEC §3.7.2 #7).",
        """
launch_tcb carries snp_spl=13 (< default minimum 0x0E); current/committed/
reported TCB all stay at the valid SYNTH baseline so only the launch TCB is
anomalous. §3.7.2 #7 requires launch_tcb to meet minimum_launch_tcb
component-wise. An SDK that skips the launch-TCB check accepts (TCB-rollback of
the launch measurement).
""",
        ["3.7.2", "3.7.1"],
        _base_fields(launch_tcb=snp_low),
        accepted=False,
    )

    # 605 — guest policy cxl_allowed set (§3.7.2 #1; default NOT allowed).
    _write(
        "605-guest-policy-cxl-allowed",
        "Guest policy with cxl_allowed set must reject (SPEC §3.7.2 #1, default not allowed).",
        """
policy bit 21 (cxl_allowed) set. §3.7.1's default guest policy does NOT allow
CXL, and §3.7.2 #1 rejects a report that enables cxl_allowed when not allowed.
Companion to 600/603 (debug/migrate_ma). An SDK whose default guest policy omits
the cxl_allowed constraint accepts.
""",
        ["3.7.2", "3.2.2"],
        _base_fields(policy=POLICY_BASE | POLICY_CXL),
        accepted=False,
    )

    # 606 — guest policy mem_aes256_xts set (§3.7.2 #1; default NOT allowed).
    _write(
        "606-guest-policy-mem-aes256-xts",
        "Guest policy with mem_aes256_xts set must reject (SPEC §3.7.2 #1, default not allowed).",
        """
policy bit 22 (mem_aes256_xts) set. §3.7.1's default guest policy leaves
mem_aes256_xts false, and §3.7.2 #1 rejects a report that enables it when not
allowed. An SDK that doesn't constrain mem_aes256_xts accepts.
""",
        ["3.7.2", "3.2.2"],
        _base_fields(policy=POLICY_BASE | POLICY_MEM_AES256_XTS),
        accepted=False,
    )

    # 272/273/274 — platform_info "required but not reported" probes (§3.7.2 #10).
    # These features are NOT required by the §3.7.1 default (ecc/rapl/tio all
    # false), so today every SDK accepts. Expected=reject encodes the hardened
    # stance so the gap surfaces (same pattern as 270/271). Each isolates one
    # missing bit by setting the other two.
    _write(
        "272-platform-info-ecc-not-enabled",
        "PLATFORM_INFO ECC not enabled: no spec mandate; probe surfaces the gap (SPEC §3.7.2 #10).",
        """
platform_info = SMT+TSME+RAPL_DIS, ECC (bit 2) clear (TIO left off to avoid the
go-sev-guest TIO allowlist rejection). §3.7.1 default does not require ECC, so
all SDKs accept. Expected=reject encodes a hardened stance (memory ECC
integrity). DECIDE-LATER: mandate ecc_enabled.
""",
        ["3.7.2", "3.2.3"],
        _base_fields(platform_info=PI_SMT | PI_TSME | PI_RAPL_DIS),
        accepted=False,
    )
    _write(
        "273-platform-info-rapl-not-disabled",
        "PLATFORM_INFO RAPL not disabled: no spec mandate; probe surfaces the gap (SPEC §3.7.2 #10).",
        """
platform_info = SMT+TSME+ECC, RAPL_DIS (bit 3) clear (TIO left off to avoid the
go-sev-guest TIO allowlist rejection). §3.7.1 default does not require RAPL
disabled, so all SDKs accept. Expected=reject encodes a hardened stance (RAPL
power side-channel, PLATYPUS-class). DECIDE-LATER: mandate rapl_disabled.
""",
        ["3.7.2", "3.2.3"],
        _base_fields(platform_info=PI_SMT | PI_TSME | PI_ECC),
        accepted=False,
    )
    _write(
        "274-platform-info-tio-not-enabled",
        "PLATFORM_INFO TIO not enabled: no spec mandate; probe surfaces the gap (SPEC §3.7.2 #10).",
        """
platform_info = SMT+TSME+ECC+RAPL_DIS, TIO (bit 7) clear. §3.7.1 default does not
require SEV-TIO (trusted I/O), so all SDKs accept. Expected=reject encodes a
hardened stance for TIO deployments. DECIDE-LATER: mandate tio_enabled.
""",
        ["3.7.2", "3.2.3"],
        _base_fields(platform_info=PI_SMT | PI_TSME | PI_ECC | PI_RAPL_DIS),
        accepted=False,
    )

    # 275 — TIO enabled, no requirement configured: spec-accept (§3.7.2 #10 uses
    # require-semantics for tio, so tio-ON is not a rejection reason). Surfaces a
    # go divergence: go-sev-guest v0.15.0 doesn't recognize PLATFORM_INFO bit 7
    # (TIO) and treats it as a reserved bit, rejecting the report; py/rs/js accept.
    _write(
        "275-platform-info-tio-enabled",
        "PLATFORM_INFO TIO enabled with no TIO requirement must be accepted (SPEC §3.7.2 #10).",
        """
platform_info = SMT+TSME+TIO (bit 7). §3.7.2 #10 lists tio_enabled with
require-semantics ("reject if required but not reported"); a report that HAS TIO
when nothing requires/forbids it is spec-compliant and must be ACCEPTED. Probes a
go divergence: go-sev-guest v0.15.0 doesn't know bit 7 and rejects it as a
reserved/unknown bit (QV_RESULT_TERMINAL_UNSPECIFIED); py/rs/js accept. Resolves
when go's go-sev-guest gains TIO awareness.
""",
        ["3.7.2", "3.2.3"],
        _base_fields(platform_info=PI_SMT | PI_TSME | PI_TIO),
        accepted=True,
    )

    print("Wrote Phase 6 attestation-sev coverage fixtures: 272-275, 452, 605-606")


if __name__ == "__main__":
    main()
