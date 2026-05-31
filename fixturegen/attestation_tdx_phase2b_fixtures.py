#!/usr/bin/env python3
"""Generate Phase 2B verify-attestation-tdx fixtures: collateral tampering.

Tests the §4.7 collateral evaluation layer that runs only when
policy.tcb_evaluation_required=true:
  * PCK CRL signature / structure
  * Root CRL signature / structure
  * TCB Info signature, chain, expiration
  * QE Identity signature, chain, expiration

Honest scope: we can only break the signature or expire the response, not
manipulate inner fields without invalidating the Intel-signed envelope.
Field-level mismatch fixtures (345 MRSIGNER, 346 ISVPRODID) thus collapse
into signature-failure outcomes — the rejection_code list documents that.
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

DEFAULT_DATE = 1688083200  # 2023-06-30 — inside both collateral validity windows.
PAST_COLLATERAL_DATE = 1721347200  # 2024-07-19 — after TCB Info nextUpdate (2023-07-18).


def write_fixture(
    *,
    fixture_id: str,
    title: str,
    notes: str,
    tcb_info_json: str = BASE_TCB_INFO,
    qe_identity_json: str = BASE_QE_IDENTITY,
    pck_crl_der: bytes = BASE_PCK_CRL,
    root_crl_der: bytes = BASE_ROOT_CRL,
    rejection_code: str | list[str] = "QV_RESULT_TERMINAL_UNSPECIFIED",
    spec_refs: list[str] | None = None,
    date_unix: int = DEFAULT_DATE,
) -> None:
    inp: dict[str, Any] = {
        "schema_version": "1",
        "quote_b64": base64.standard_b64encode(BASE_QUOTE).decode(),
        "collateral": {
            "tcb_info_json": tcb_info_json,
            "qe_identity_json": qe_identity_json,
            "pck_crl_der_b64": base64.standard_b64encode(pck_crl_der).decode(),
            "root_crl_der_b64": base64.standard_b64encode(root_crl_der).decode(),
        },
        "expiration_check_date_unix": date_unix,
        "policy": {"tcb_evaluation_required": True},
    }
    dst = VECTORS_DIR / fixture_id
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "input.json").write_text(json.dumps(inp, indent=2))
    (dst / "expected.json").write_text(json.dumps(
        {"stage": "verify-attestation-tdx", "accepted": False,
         "rejection": {"code": rejection_code}}, indent=2))

    refs = spec_refs or ["4.7"]
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
    )
    manifest += "fixture_kind: synthetic-mutation\n"
    manifest += "notes: |\n"
    for line in notes.strip().splitlines():
        manifest += f"  {line}\n"
    (dst / "manifest.yaml").write_text(manifest)


def _byte_flip(data: bytes, offset: int, new_value: int = 0x32) -> bytes:
    b = bytearray(data)
    b[offset] = new_value
    return bytes(b)


def _patch_tcb_info_signature(tcb_info: str) -> str:
    """Flip one hex char inside the trailing signature field."""
    d = json.loads(tcb_info)
    sig = d["signature"]
    # Replace first char with a different one (preserve hex-ness)
    d["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    return json.dumps(d)


def _patch_qe_identity_signature(qe_id: str) -> str:
    d = json.loads(qe_id)
    sig = d["signature"]
    d["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    return json.dumps(d)


def _patch_tcb_info_field(tcb_info: str, field: str, value: Any) -> str:
    """Modify an inner field of the signed tcbInfo. Breaks Intel's
    signature — that's the point; the test verifies the lib detects it."""
    d = json.loads(tcb_info)
    d["tcbInfo"][field] = value
    return json.dumps(d)


def _patch_qe_identity_field(qe_id: str, field: str, value: Any) -> str:
    d = json.loads(qe_id)
    d["enclaveIdentity"][field] = value
    return json.dumps(d)


def main() -> None:
    # 326 — PCK CRL signature byte flipped
    write_fixture(
        fixture_id="326-pck-crl-sig-broken",
        title="PCK CRL DER byte flipped → CRL signature verification fails (revocation path unreachable).",
        notes=(
            "Byte mutation inside the PCK CRL DER (toward the end, in the\n"
            "Intel intermediate's signature region). We can't add a real\n"
            "revocation entry (would require Intel's intermediate key);\n"
            "this fixture instead exercises the lib's CRL signature\n"
            "validation, which must reject before any revocation match is\n"
            "considered. Real-world incident analog: an attacker corrupting\n"
            "the cached CRL to bypass revocation."
        ),
        pck_crl_der=_byte_flip(BASE_PCK_CRL, len(BASE_PCK_CRL) - 32, 0x99),
        rejection_code=[
            "PCK_REVOKED",
            "PCK_CHAIN_INVALID",
            "TCB_REVOKED",
            "QV_RESULT_TERMINAL_UNSPECIFIED",
        ],
        spec_refs=["4.7"],
    )

    # 327 — Root CRL signature byte flipped
    write_fixture(
        fixture_id="327-root-crl-sig-broken",
        title="Root CRL DER byte flipped → Root CRL signature verification fails.",
        notes=(
            "Symmetric to 326 but for the Intel SGX Root CA CRL. Tests that\n"
            "the lib won't trust a tampered Root CRL — protects against an\n"
            "attacker substituting an empty/forged Root CRL to mask\n"
            "intermediate revocation."
        ),
        root_crl_der=_byte_flip(BASE_ROOT_CRL, len(BASE_ROOT_CRL) - 32, 0x99),
        rejection_code=[
            "ROOT_CA_UNTRUSTED",
            "INTERMEDIATE_REVOKED",
            "PCK_CHAIN_INVALID",
            "TCB_REVOKED",
            "QV_RESULT_TERMINAL_UNSPECIFIED",
        ],
        spec_refs=["4.7"],
    )

    # 340 — TCB Info signature broken
    write_fixture(
        fixture_id="340-tcb-info-sig-broken",
        title="TCB Info JSON signature field byte flipped → TCB_INFO_SIGNATURE_INVALID.",
        notes=(
            "Flips one hex char inside the trailing 'signature' field of\n"
            "the TCB Info JSON. Intel's signature over the inner tcbInfo no\n"
            "longer verifies. Must reject before any TCB level matching."
        ),
        tcb_info_json=_patch_tcb_info_signature(BASE_TCB_INFO),
        rejection_code=[
            "TCB_INFO_SIGNATURE_INVALID",
            "TCB_INFO_CHAIN_INVALID",
            "TCB_REVOKED",
            "QV_RESULT_TERMINAL_UNSPECIFIED",
        ],
        spec_refs=["4.7"],
    )

    # 341 — TCB Info expired
    write_fixture(
        fixture_id="341-tcb-info-expired",
        title="expiration_check_date past TCB Info nextUpdate → tcb info expired.",
        notes=(
            "No mutation. TCB Info nextUpdate is 2023-07-18. Setting\n"
            "expiration_check_date_unix to 2024-07-19 puts us past it.\n"
            "Per Intel §4.1.2 expired collateral does NOT by itself fail\n"
            "verification — it sets p_collateral_expiration_status. SDKs\n"
            "vary in policy on whether to surface this as a terminal\n"
            "rejection or a warning. The list-form rejection_code accepts\n"
            "both interpretations, plus QV_RESULT_OUT_OF_DATE since the\n"
            "TCB Info's tcbEvaluationDataNumber (15) may be below tinfoil-\n"
            "go's MinimumTcbEvaluationDataNumber threshold by now."
        ),
        date_unix=PAST_COLLATERAL_DATE,
        rejection_code=[
            "TCB_INFO_EXPIRED",
            "QV_RESULT_TERMINAL_UNSPECIFIED",
            "TCB_REVOKED",
        ],
        spec_refs=["4.7"],
    )

    # 342 — QE Identity signature broken
    write_fixture(
        fixture_id="342-qe-identity-sig-broken",
        title="QE Identity JSON signature field byte flipped → QE_IDENTITY_SIGNATURE_INVALID.",
        notes=(
            "Same idea as 340. Intel's signature over the inner\n"
            "enclaveIdentity no longer verifies; the lib must reject\n"
            "before any QE identity field comparison."
        ),
        qe_identity_json=_patch_qe_identity_signature(BASE_QE_IDENTITY),
        rejection_code=[
            "QE_IDENTITY_SIGNATURE_INVALID",
            "QE_IDENTITY_FIELD_MISMATCH",
            "TCB_REVOKED",
            "QV_RESULT_TERMINAL_UNSPECIFIED",
        ],
        spec_refs=["4.7"],
    )

    # 343 — QE Identity expired
    write_fixture(
        fixture_id="343-qe-identity-expired",
        title="expiration_check_date past QE Identity nextUpdate → qe identity expired.",
        notes=(
            "QE Identity nextUpdate is 2023-07-08. expiration_check_date_\n"
            "unix=2024-07-19 puts us past it. Same nuance as 341: per Intel\n"
            "§4.1.2 expiration alone is non-terminal; SDKs vary."
        ),
        date_unix=PAST_COLLATERAL_DATE,
        rejection_code=[
            "QE_IDENTITY_EXPIRED",
            "TCB_INFO_EXPIRED",
            "QV_RESULT_TERMINAL_UNSPECIFIED",
            "TCB_REVOKED",
        ],
        spec_refs=["4.7"],
    )

    # 344 — TCB Info inner field mutated (breaks Intel's signature)
    write_fixture(
        fixture_id="344-tcb-info-fmspc-tampered",
        title="TCB Info inner fmspc field tampered → signature mismatch.",
        notes=(
            "Modifies tcbInfo.fmspc from 50806f000000 to 000000000000.\n"
            "Intel's signature over the canonical tcbInfo JSON no longer\n"
            "verifies. Naturally collapses into TCB_INFO_SIGNATURE_INVALID\n"
            "(we can't re-sign with Intel's key). Documents that field-\n"
            "level mismatch and signature failure are indistinguishable\n"
            "without synthetic-Intel-root fixturegen."
        ),
        tcb_info_json=_patch_tcb_info_field(BASE_TCB_INFO, "fmspc", "000000000000"),
        rejection_code=[
            "TCB_INFO_SIGNATURE_INVALID",
            "PCK_FMSPC_MISMATCH",
            "QV_RESULT_TERMINAL_UNSPECIFIED",
        ],
        spec_refs=["4.7"],
    )

    # 345 — QE Identity inner field mutated (breaks Intel's signature)
    write_fixture(
        fixture_id="345-qe-identity-mrsigner-tampered",
        title="QE Identity inner mrsigner field tampered → signature mismatch.",
        notes=(
            "Modifies enclaveIdentity.mrsigner to all-zero. Intel's signature\n"
            "no longer verifies. Same caveat as 344 — field-level mismatch\n"
            "collapses into signature failure. The 'precise' QE_IDENTITY_\n"
            "MRSIGNER_MISMATCH code needs synthetic-root fixturegen to be\n"
            "reachable independently."
        ),
        qe_identity_json=_patch_qe_identity_field(
            BASE_QE_IDENTITY,
            "mrsigner",
            "00000000000000000000000000000000000000000000000000000000000000",
        ),
        rejection_code=[
            "QE_IDENTITY_SIGNATURE_INVALID",
            "QE_IDENTITY_MRSIGNER_MISMATCH",
            "TCB_REVOKED",
            "QV_RESULT_TERMINAL_UNSPECIFIED",
        ],
        spec_refs=["4.7"],
    )

    print("Wrote Phase 2B attestation-tdx fixtures:")
    for d in sorted(VECTORS_DIR.iterdir()):
        if d.is_dir() and d.name[:3] in ("326", "327", "340", "341", "342", "343", "344", "345"):
            print(f"  {d.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
