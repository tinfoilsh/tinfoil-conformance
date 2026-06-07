#!/usr/bin/env python3
"""Generate Phase 4B verify-attestation-tdx fixtures: SPEC §4.8 normative
+ §4.7.10/§4.7.11 collateral-edge synthetic violations.

The current Phase 4 fixtures (400-490) test policy-pin COMPARISON. They
prove the verifier extracts a field and compares against an expected
value. But Intel §2.3.2 + SPEC §4.8 require NORMATIVE checks that ALWAYS
apply regardless of policy: DEBUG bit must be 0, reserved bits must be 0,
XFAM FP/SSE bits must be set, etc.

Phase 4B synthesizes quotes with the violating bit set/cleared and
collateral with the violating field value. Same synthetic Intel-mimicking
chain from lib.tdx_synth — only the body bytes or collateral content vary.
"""

from __future__ import annotations

import base64
import copy
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = REPO_ROOT / "vectors" / "attestation-tdx"
sys.path.insert(0, str(REPO_ROOT / "fixturegen"))

from lib.tdx_synth import (  # noqa: E402
    build_synth_chain, build_tdx_quote_v4,
    build_tcb_info_response, build_qe_identity_response,
    build_empty_crl, TdBodyFields,
)


DEFAULT_DATE = 1688083200


def _base_collateral(chain, tcb_eval_data_number: int = 18) -> dict[str, Any]:
    tcb_levels = [{
        "tcb": {
            "sgxtcbcomponents": [{"svn": b} for b in [5, 5, 2, 2, 3, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0]],
            "pcesvn": 11,
            "tdxtcbcomponents": [{"svn": b} for b in [3, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]],
        },
        "tcbDate": "2023-02-15T00:00:00Z",
        "tcbStatus": "UpToDate",
    }]
    tcb_info = build_tcb_info_response(
        chain, tcb_levels=tcb_levels,
        tcb_evaluation_data_number=tcb_eval_data_number,
    )
    qe_identity = build_qe_identity_response(
        chain, mrsigner_hex="DC" * 32, isv_prod_id=2, isv_svn=8,
        tcb_evaluation_data_number=tcb_eval_data_number,
    )
    return {
        "tcb_info_json": tcb_info,
        "qe_identity_json": qe_identity,
        "pck_crl_der_b64": base64.standard_b64encode(build_empty_crl(chain.platform_ca)).decode(),
        "root_crl_der_b64": base64.standard_b64encode(build_empty_crl(chain.root_ca)).decode(),
        "intel_root_ca_pem": chain.root_ca.pem,
        "tcb_info_issuer_chain_pem": chain.tcb_signer.pem + chain.root_ca.pem,
        "qe_identity_issuer_chain_pem": chain.tcb_signer.pem + chain.root_ca.pem,
        "pck_crl_issuer_chain_pem": chain.platform_ca.pem + chain.root_ca.pem,
    }


def write_fixture(
    *,
    fixture_id: str,
    title: str,
    notes: str,
    body_override: TdBodyFields | None = None,
    collateral_overrides: dict[str, Any] | None = None,
    tcb_eval_data_number: int = 18,
    rejection_code: str | list[str],
    policy: dict[str, Any] | None = None,
    spec_refs: list[str] | None = None,
    extra_caps: dict[str, Any] | None = None,
) -> None:
    chain = build_synth_chain()
    quote, _ = build_tdx_quote_v4(chain, body=body_override)
    collateral = _base_collateral(chain, tcb_eval_data_number=tcb_eval_data_number)
    if collateral_overrides:
        collateral.update(collateral_overrides)

    pol = {"tcb_evaluation_required": True}
    if policy:
        pol.update(policy)

    payload = {
        "schema_version": "1",
        "quote_b64": base64.standard_b64encode(quote).decode(),
        "collateral": collateral,
        "expiration_check_date_unix": DEFAULT_DATE,
        "policy": pol,
    }
    dst = VECTORS_DIR / fixture_id
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "input.json").write_text(json.dumps(payload, indent=2))
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
        "  attestation_tdx.tcb_evaluation_supported: true\n"
        "  attestation_tdx.extended_td_checks_supported: true\n"
    )
    for cap_path, cap_value in (extra_caps or {}).items():
        manifest += f"  {cap_path}: {json.dumps(cap_value)}\n"
    manifest += "fixture_kind: synthetic-spec-violation\n"
    manifest += "notes: |\n"
    for line in notes.strip().splitlines():
        manifest += f"  {line}\n"
    (dst / "manifest.yaml").write_text(manifest)


def main() -> None:
    # ------ §4.8.2 TD Attributes normative checks ------

    # 401 — DEBUG bit set
    write_fixture(
        fixture_id="401-td-attributes-debug-bit-set",
        title="Synthetic quote with TUD.DEBUG=1 → reject per Intel §2.3.2 / SPEC §4.8.2.",
        notes=(
            "Intel §2.3.2 step 2a: 'Verify that all TD Under Debug flags\n"
            "(TDATTIBUTES.TUD) are set to zero. If any flag is non-zero,\n"
            "the TD should not be trusted'.\n"
            "\n"
            "SPEC §4.8.2: (td_attributes & TD_ATTRIBUTES_DEBUG) == 0\n"
            "\n"
            "Synth quote sets bit 0 (DEBUG) of td_attributes. This is the\n"
            "CANONICAL 'debug TD' case — the host VMM has visibility into\n"
            "the TD's CPU state and private memory. Provisioning secrets\n"
            "to such a TD defeats the whole point of TDX."
        ),
        body_override=TdBodyFields(td_attributes=b"\x01\x00\x00\x00\x00\x00\x00\x00"),
        policy={"enforce_spec_defaults": True},
        rejection_code="TD_ATTRIBUTES_DEBUG_SET",
        spec_refs=["4.8.2", "A.3.4"],
    )

    # 402 — TUD reserved bit (bit 7) set
    write_fixture(
        fixture_id="402-td-attributes-tud-reserved-bit-set",
        title="Synth quote with TUD reserved bit 7 set → reject (bit outside FIXED0).",
        notes=(
            "Intel §A.3.4: TUD group bits 7:1 are 'Reserved for future TUD\n"
            "flags – must be 0'.\n"
            "\n"
            "SPEC §4.8.2 FIXED0 mask test: bit 7 isn't in FIXED0 (bits\n"
            "{0, 28, 30, 63}), so this bit being set fails (td_attr &\n"
            "~FIXED0) == 0. Guards against future spec drift where a new\n"
            "TUD flag would unintentionally pass verification."
        ),
        body_override=TdBodyFields(td_attributes=b"\x80\x00\x00\x00\x00\x00\x00\x00"),
        policy={"enforce_spec_defaults": True},
        rejection_code="TD_ATTRIBUTES_RESERVED_BIT_SET",
        spec_refs=["4.8.2", "A.3.4"],
    )

    # 403 — SEC lower reserved bit (bit 8) set
    write_fixture(
        fixture_id="403-td-attributes-sec-reserved-lower-set",
        title="Synth quote with SEC reserved bit 8 set → reject (bit outside FIXED0).",
        notes=(
            "Intel §A.3.4: SEC group bits 27:8 are 'Reserved for future SEC\n"
            "flags – must be 0'. Catches a malicious quote that sets a bit\n"
            "the SDK doesn't recognize as policy-relevant."
        ),
        body_override=TdBodyFields(td_attributes=b"\x00\x01\x00\x00\x00\x00\x00\x00"),
        policy={"enforce_spec_defaults": True},
        rejection_code="TD_ATTRIBUTES_RESERVED_BIT_SET",
        spec_refs=["4.8.2", "A.3.4"],
    )

    # 404 — SEC bit 29 reserved set
    write_fixture(
        fixture_id="404-td-attributes-sec-bit29-reserved-set",
        title="Synth quote with SEC bit 29 (reserved) set → reject.",
        notes=(
            "Intel §A.3.4: bit 29 is reserved between SEPT_VE_DISABLE (28)\n"
            "and PKS (30). Setting it must reject."
        ),
        body_override=TdBodyFields(td_attributes=b"\x00\x00\x00\x20\x00\x00\x00\x00"),
        policy={"enforce_spec_defaults": True},
        rejection_code="TD_ATTRIBUTES_RESERVED_BIT_SET",
        spec_refs=["4.8.2", "A.3.4"],
    )

    # 405 — OTHER reserved bit (bit 32) set
    write_fixture(
        fixture_id="405-td-attributes-other-reserved-set",
        title="Synth quote with OTHER reserved bit 32 set → reject.",
        notes=(
            "Intel §A.3.4: OTHER group bits 62:32 are 'Reserved for future\n"
            "OTHER flags – must be 0'."
        ),
        body_override=TdBodyFields(td_attributes=b"\x00\x00\x00\x00\x01\x00\x00\x00"),
        policy={"enforce_spec_defaults": True},
        rejection_code="TD_ATTRIBUTES_RESERVED_BIT_SET",
        spec_refs=["4.8.2", "A.3.4"],
    )

    # ------ §4.8.1 XFAM normative checks ------

    # 412 — XFAM FP/SSE required bits clear
    write_fixture(
        fixture_id="412-xfam-fp-sse-not-set",
        title="Synth quote with XFAM bit 0 (FP) clear → reject.",
        notes=(
            "SPEC §4.8.1: XFAM_FIXED1 = 0x00000003 (FP + SSE required).\n"
            "Quote MUST have bits 0 and 1 set. Synth quote sets XFAM=0x2\n"
            "(SSE set, FP cleared) — fails required-bit check."
        ),
        body_override=TdBodyFields(xfam=b"\x02\x00\x00\x00\x00\x00\x00\x00"),
        policy={"enforce_spec_defaults": True},
        rejection_code="XFAM_REQUIRED_BIT_CLEAR",
        spec_refs=["4.8.1"],
    )

    # 413 — XFAM bit outside FIXED0 set
    write_fixture(
        fixture_id="413-xfam-forbidden-bit-set",
        title="Synth quote with XFAM bit outside FIXED0 mask set → reject.",
        notes=(
            "SPEC §4.8.1: XFAM_FIXED0 = 0x0006DBE7. Only these bits may be\n"
            "set. Synth quote sets bit 31 (outside FIXED0): xfam=0x80000003\n"
            "(FP + SSE + forbidden bit 31). Fails forbidden-bit check."
        ),
        body_override=TdBodyFields(xfam=b"\x03\x00\x00\x80\x00\x00\x00\x00"),
        policy={"enforce_spec_defaults": True},
        rejection_code="XFAM_FORBIDDEN_BIT_SET",
        spec_refs=["4.8.1"],
    )

    # ------ §4.7.11 Min TCB Evaluation Data Number ------

    # 346 — TCB Info tcbEvaluationDataNumber too low
    write_fixture(
        fixture_id="346-tcb-eval-data-number-too-low",
        title="TCB Info tcbEvaluationDataNumber=10 (below SPEC §4.7.11 default 18) → reject.",
        notes=(
            "SPEC §4.7.11: 'The default minimum TCB evaluation data number\n"
            "is 18, corresponding to the TCB recovery event of\n"
            "2024-11-12.' Collateral with a lower number indicates a\n"
            "TCB recovery has occurred but the collateral predates it —\n"
            "the platform may be vulnerable to the recovered CVE.\n"
            "\n"
            "tinfoil-go's NewTDXGetter enforces this via MinimumTcbEval\n"
            "uationDataNumber. tinfoil-python's check_collateral_freshness\n"
            "enforces via min_tcb_evaluation_data_number parameter (the\n"
            "conformance binary currently passes 0 to allow lower numbers\n"
            "in Phase 2B+3 fixtures; this one explicitly sets a higher\n"
            "minimum so the lib's check fires)."
        ),
        tcb_eval_data_number=10,
        policy={"min_tcb_evaluation_data_number": 18},
        rejection_code=[
            "TCB_EVAL_DATA_NUMBER_TOO_LOW",
            "TCB_INFO_EXPIRED",
            "QV_RESULT_TERMINAL_UNSPECIFIED",
        ],
        spec_refs=["4.7.11"],
        extra_caps={"attestation_tdx.enforces_tcb_evaluation_data_number_minimum": True},
    )

    print("Wrote Phase 4B attestation-tdx fixtures:")
    for d in sorted(VECTORS_DIR.iterdir()):
        if d.is_dir() and d.name[:3] in ("346", "401", "402", "403", "404", "405", "412", "413"):
            print(f"  {d.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
