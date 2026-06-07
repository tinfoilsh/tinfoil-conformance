#!/usr/bin/env python3
"""Generate Phase 3 verify-attestation-tdx fixtures: TCB status matrix.

Each fixture builds a complete synthetic Intel-mimicking chain via
lib.tdx_synth: synth Root CA → Platform CA → PCK leaf + TCB Signing,
plus a synthetic TDX quote signed by a synthetic AK. The TCB Info JSON
carries a single tcbLevel whose SVN values exactly match the synthetic
quote's TEE_TCB_SVN and PCESVN — only the `tcbStatus` varies across
fixtures, producing each Intel §B.1 result code in turn.

Why synthetic: real Intel-signed TCB Info has SVNs calibrated to reject
real SPR E4 sample quotes (verifying the rejection path; see
google/go-tdx-guest verify_test.go:749-753). To test the Up-To-Date and
non-OK-non-terminal status branches separately, we need control over
both the quote's TEE_TCB_SVN AND the TCB Info levels. Synthetic chain
swaps the embedded Intel Root CA out (via input.collateral.intel_root_
ca_pem) so the lib's chain validation accepts our self-issued root.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = REPO_ROOT / "vectors" / "attestation-tdx"
sys.path.insert(0, str(REPO_ROOT / "fixturegen"))

from lib.tdx_synth import (  # noqa: E402
    build_synth_chain,
    build_tdx_quote_v4,
    build_tcb_info_response,
    build_qe_identity_response,
    build_empty_crl,
)


def make_input(
    *,
    tcb_status: str,
    pcesvn: int = 11,
    tee_tcb_svn_bytes: bytes | None = None,
    tcb_evaluation_data_number: int = 18,
) -> tuple[dict[str, Any], str]:
    """Build a synthetic input.json. Returns (payload, tcb_status_returned)."""
    chain = build_synth_chain(pce_svn=pcesvn)
    # tee_tcb_svn default matches what the synth chain's PCK extensions encode:
    # the SPEC §4.7.6 step 3 comparison will accept when the level's
    # tdxtcbcomponents svn ≤ quote.tee_tcb_svn byte-wise.
    if tee_tcb_svn_bytes is None:
        tee_tcb_svn_bytes = b"\x00\x03\x05\x00" + b"\x00" * 12
    from lib.tdx_synth import TdBodyFields
    body = TdBodyFields(tee_tcb_svn=tee_tcb_svn_bytes)
    quote, body = build_tdx_quote_v4(chain, body=body)

    tcb_levels = [
        {
            "tcb": {
                "sgxtcbcomponents": [{"svn": b} for b in [5, 5, 2, 2, 3, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0]],
                "pcesvn": pcesvn,
                "tdxtcbcomponents": [{"svn": b} for b in [3, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]],
            },
            "tcbDate": "2023-02-15T00:00:00Z",
            "tcbStatus": tcb_status,
        },
    ]
    tcb_info = build_tcb_info_response(
        chain, tcb_levels=tcb_levels,
        tcb_evaluation_data_number=tcb_evaluation_data_number,
    )
    qe_identity = build_qe_identity_response(
        chain, mrsigner_hex="DC" * 32, isv_prod_id=2, isv_svn=8,
        tcb_evaluation_data_number=tcb_evaluation_data_number,
    )
    pck_crl = build_empty_crl(chain.platform_ca)
    root_crl = build_empty_crl(chain.root_ca)

    payload = {
        "schema_version": "1",
        "quote_b64": base64.standard_b64encode(quote).decode(),
        "collateral": {
            "tcb_info_json": tcb_info,
            "qe_identity_json": qe_identity,
            "pck_crl_der_b64": base64.standard_b64encode(pck_crl).decode(),
            "root_crl_der_b64": base64.standard_b64encode(root_crl).decode(),
            "intel_root_ca_pem": chain.root_ca.pem,
            "tcb_info_issuer_chain_pem": chain.tcb_signer.pem + chain.root_ca.pem,
            "qe_identity_issuer_chain_pem": chain.tcb_signer.pem + chain.root_ca.pem,
            "pck_crl_issuer_chain_pem": chain.platform_ca.pem + chain.root_ca.pem,
        },
        "expiration_check_date_unix": 1688083200,
        "policy": {"tcb_evaluation_required": True},
    }
    return payload, tcb_status


def write_fixture(
    *,
    fixture_id: str,
    title: str,
    notes: str,
    tcb_status: str,
    pcesvn: int = 11,
    accepted: bool = False,
    rejection_code: str | list[str] | None = None,
    policy: dict[str, Any] | None = None,
    spec_refs: list[str] | None = None,
    extra_caps: dict[str, Any] | None = None,
) -> None:
    payload, _ = make_input(tcb_status=tcb_status, pcesvn=pcesvn)
    if policy:
        payload["policy"].update(policy)
    dst = VECTORS_DIR / fixture_id
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "input.json").write_text(json.dumps(payload, indent=2))

    if accepted:
        # Pin only minimal fields — synthetic measurement values are random
        # per-build (key generation), so we don't pin them here.
        expected = {
            "stage": "verify-attestation-tdx",
            "accepted": True,
            "outputs": {
                "tee_type": "TDX",
                "quote_version": 4,
            },
        }
    else:
        expected = {
            "stage": "verify-attestation-tdx",
            "accepted": False,
            "rejection": {"code": rejection_code},
        }
    (dst / "expected.json").write_text(json.dumps(expected, indent=2))

    refs = spec_refs or ["4.7"]
    manifest = (
        f"id: {fixture_id}\n"
        f"stage: verify-attestation-tdx\n"
        f"title: |\n  {title}\n"
        f"spec_refs: {json.dumps(refs)}\n"
        f"expects:\n"
        f"  exit_code: {0 if accepted else 10}\n"
    )
    if rejection_code is not None:
        manifest += f"  rejection_code: {json.dumps(rejection_code)}\n"
    manifest += (
        "required_capabilities:\n"
        "  attestation_tdx.supported: true\n"
        "  attestation_tdx.injected_collateral_supported: true\n"
        "  attestation_tdx.tcb_evaluation_supported: true\n"
    )
    for cap_path, cap_value in (extra_caps or {}).items():
        manifest += f"  {cap_path}: {json.dumps(cap_value)}\n"
    manifest += (
        "fixture_kind: synthetic-intel-chain\n"
        "notes: |\n"
    )
    for line in notes.strip().splitlines():
        manifest += f"  {line}\n"
    (dst / "manifest.yaml").write_text(manifest)


def main() -> None:
    # 350 — UpToDate (qv_result=OK)
    write_fixture(
        fixture_id="350-tcb-uptodate",
        title="Synthetic chain + TCB level UpToDate → accept (qv_result=OK).",
        notes=(
            "Phase 3 happy path. Synthetic Intel-mimicking chain via\n"
            "lib.tdx_synth; the TCB Info has a single tcbLevel whose\n"
            "tdxtcbcomponents.svn array matches the quote's TEE_TCB_SVN\n"
            "component-wise, with status=UpToDate. Verifies the full §4.7\n"
            "collateral path (signature, chain, freshness, CRL, TCB level\n"
            "matching) accepts when every check passes."
        ),
        tcb_status="UpToDate",
        accepted=True,
        spec_refs=["4.7", "4.7.7"],
    )

    # 360-364 — non-terminal non-OK statuses
    _NON_TERM_CAP = {"attestation_tdx.accepts_non_terminal_tcb_statuses": True}

    write_fixture(
        fixture_id="360-tcb-swhardening-needed",
        title="TCB level SWHardeningNeeded → accept (SPEC §4.7.7 non-terminal default).",
        notes=(
            "Tinfoil SPEC §4.7.7 lists SWHardeningNeeded as 'Yes (default)'\n"
            "— SDKs MAY reject for stricter posture but the default is\n"
            "acceptance. Intel §B.1: SW_HARDENING_NEEDED is a non-terminal\n"
            "result requiring relying-party policy decision.\n"
            "\n"
            "Cross-SDK divergence: tinfoil-python's validate_tcb_status\n"
            "accepts these statuses (SPEC-aligned). go-tdx-guest's\n"
            "ErrTcbStatus rejects every non-UpToDate status. Gated on\n"
            "accepts_non_terminal_tcb_statuses; Go skips honestly until\n"
            "the lib gains a permissive-policy knob."
        ),
        tcb_status="SWHardeningNeeded",
        accepted=True,
        spec_refs=["4.7.7"],
        extra_caps=_NON_TERM_CAP,
    )

    write_fixture(
        fixture_id="361-tcb-configuration-needed",
        title="TCB level ConfigurationNeeded → accept (SPEC §4.7.7 non-terminal default).",
        notes="Tinfoil SPEC §4.7.7 'Yes (default)'. Same gating as 360.",
        tcb_status="ConfigurationNeeded",
        accepted=True,
        spec_refs=["4.7.7"],
        extra_caps=_NON_TERM_CAP,
    )

    write_fixture(
        fixture_id="362-tcb-config-and-sw-hardening-needed",
        title="TCB level ConfigurationAndSWHardeningNeeded → accept (SPEC §4.7.7 default).",
        notes="Tinfoil SPEC §4.7.7 'Yes (default)'. Same gating as 360.",
        tcb_status="ConfigurationAndSWHardeningNeeded",
        accepted=True,
        spec_refs=["4.7.7"],
        extra_caps=_NON_TERM_CAP,
    )

    write_fixture(
        fixture_id="365-tcb-swhardening-needed-policy-rejected",
        title="TCB level SWHardeningNeeded with accepted_qv_results=[OK] → reject by policy.",
        notes=(
            "SWHardeningNeeded is non-terminal, so a verifier with a\n"
            "permissive default can accept it. This fixture tightens the\n"
            "relying-party policy to accepted_qv_results=[OK], so reaching\n"
            "the non-terminal result is not enough: the SDK must reject\n"
            "with QV_RESULT_NOT_ACCEPTED_BY_POLICY rather than accepting or\n"
            "misclassifying it as a terminal TCB revocation."
        ),
        tcb_status="SWHardeningNeeded",
        policy={"accepted_qv_results": ["OK"]},
        rejection_code="QV_RESULT_NOT_ACCEPTED_BY_POLICY",
        spec_refs=["4.7.7"],
        extra_caps={
            "attestation_tdx.accepts_non_terminal_tcb_statuses": True,
            "attestation_tdx.policy_fields_supported.accepted_qv_results": True,
        },
    )

    write_fixture(
        fixture_id="363-tcb-out-of-date",
        title="TCB level OutOfDate → SPEC §4.7.7 always reject.",
        notes=(
            "SPEC §4.7.7 explicitly lists OutOfDate as 'No' (always\n"
            "rejected) regardless of policy strictness. Tests that the lib\n"
            "treats OutOfDate as terminal-reject, not non-terminal."
        ),
        tcb_status="OutOfDate",
        rejection_code=[
            "TCB_REVOKED",
            "QV_RESULT_TERMINAL_UNSPECIFIED",
            "QV_RESULT_NOT_ACCEPTED_BY_POLICY",
        ],
        spec_refs=["4.7.7"],
    )

    write_fixture(
        fixture_id="364-tcb-out-of-date-config-needed",
        title="TCB level OutOfDateConfigurationNeeded → SPEC §4.7.7 always reject.",
        notes="Combined OutOfDate + Configuration. SPEC §4.7.7 always reject.",
        tcb_status="OutOfDateConfigurationNeeded",
        rejection_code=[
            "TCB_REVOKED",
            "QV_RESULT_TERMINAL_UNSPECIFIED",
            "QV_RESULT_NOT_ACCEPTED_BY_POLICY",
        ],
        spec_refs=["4.7.7"],
    )

    # 368 — Revoked (terminal)
    write_fixture(
        fixture_id="368-tcb-revoked",
        title="TCB level Revoked → qv_result=REVOKED (terminal).",
        notes=(
            "Intel §B.1 Revoked is terminal — Intel has revoked the TCB.\n"
            "Verifier MUST reject regardless of policy strictness. Tests\n"
            "the most security-critical rejection path."
        ),
        tcb_status="Revoked",
        rejection_code=[
            "TCB_REVOKED",
            "QV_RESULT_TERMINAL_UNSPECIFIED",
            "QV_RESULT_NOT_ACCEPTED_BY_POLICY",
        ],
        spec_refs=["4.7.7"],
    )

    print("Wrote Phase 3 attestation-tdx fixtures:")
    for d in sorted(VECTORS_DIR.iterdir()):
        if d.is_dir() and d.name.startswith(("350-", "36")):
            print(f"  {d.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
