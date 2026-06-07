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
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = REPO_ROOT / "vectors" / "attestation-tdx"
ASSETS = VECTORS_DIR / "_assets"
sys.path.insert(0, str(REPO_ROOT / "fixturegen"))

from lib.tdx_synth import (  # noqa: E402
    TdBodyFields,
    build_empty_crl,
    build_qe_identity_response,
    build_synth_chain,
    build_tcb_info_response,
    build_tdx_quote_v4,
)

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


def _synth_tcb_levels(pcesvn: int = 11) -> list[dict[str, Any]]:
    return [
        {
            "tcb": {
                "sgxtcbcomponents": [
                    {"svn": b} for b in [5, 5, 2, 2, 3, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0]
                ],
                "pcesvn": pcesvn,
                "tdxtcbcomponents": [
                    {"svn": b} for b in [3, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                ],
            },
            "tcbDate": "2023-02-15T00:00:00Z",
            "tcbStatus": "UpToDate",
        },
    ]


def make_synth_input(
    *,
    ak_mismatch: bool = False,
    qe_report_data: bytes | None = None,
    pck_crl_not_after: datetime | None = None,
    root_crl_not_after: datetime | None = None,
    revoke_intermediate: bool = False,
    wrong_tcb_info_issuer_chain: bool = False,
    qe_identity_mrsigner_hex: str = "DC" * 32,
    qe_identity_isv_prod_id: int = 2,
    qe_identity_id: str = "TD_QE",
    qe_identity_version: int = 2,
    tcb_info_next_update: str = "2030-07-18T08:42:58Z",
    qe_identity_next_update: str = "2030-07-08T07:24:59Z",
    tcb_eval: bool = True,
) -> dict[str, Any]:
    """Build a signed synthetic-root TDX input for semantic collateral tests."""
    chain = build_synth_chain()
    wrong_ak_chain = build_synth_chain() if ak_mismatch else None
    quote, _ = build_tdx_quote_v4(
        chain,
        body=TdBodyFields(),
        quote_signing_key=wrong_ak_chain.ak_key if wrong_ak_chain else None,
        qe_report_data=qe_report_data,
    )
    tcb_info = build_tcb_info_response(
        chain,
        tcb_levels=_synth_tcb_levels(),
        next_update=tcb_info_next_update,
    )
    qe_identity = build_qe_identity_response(
        chain,
        mrsigner_hex=qe_identity_mrsigner_hex,
        isv_prod_id=qe_identity_isv_prod_id,
        isv_svn=8,
        identity_id=qe_identity_id,
        version=qe_identity_version,
        next_update=qe_identity_next_update,
    )
    pck_crl = build_empty_crl(chain.platform_ca, not_after=pck_crl_not_after)
    root_crl = build_empty_crl(
        chain.root_ca,
        not_after=root_crl_not_after,
        revoked_certs=[chain.platform_ca] if revoke_intermediate else None,
    )
    bad_tcb_chain = build_synth_chain() if wrong_tcb_info_issuer_chain else None
    return {
        "schema_version": "1",
        "quote_b64": base64.standard_b64encode(quote).decode(),
        "collateral": {
            "tcb_info_json": tcb_info,
            "qe_identity_json": qe_identity,
            "pck_crl_der_b64": base64.standard_b64encode(pck_crl).decode(),
            "root_crl_der_b64": base64.standard_b64encode(root_crl).decode(),
            "intel_root_ca_pem": chain.root_ca.pem,
            "tcb_info_issuer_chain_pem": (
                bad_tcb_chain.tcb_signer.pem + bad_tcb_chain.root_ca.pem
                if bad_tcb_chain
                else chain.tcb_signer.pem + chain.root_ca.pem
            ),
            "qe_identity_issuer_chain_pem": chain.tcb_signer.pem + chain.root_ca.pem,
            "pck_crl_issuer_chain_pem": chain.platform_ca.pem + chain.root_ca.pem,
        },
        "expiration_check_date_unix": DEFAULT_DATE,
        "policy": {"tcb_evaluation_required": tcb_eval},
    }


def write_synth_fixture(
    *,
    fixture_id: str,
    title: str,
    notes: str,
    rejection_code: str | list[str],
    spec_refs: list[str] | None = None,
    ak_mismatch: bool = False,
    qe_report_data: bytes | None = None,
    pck_crl_not_after: datetime | None = None,
    root_crl_not_after: datetime | None = None,
    revoke_intermediate: bool = False,
    wrong_tcb_info_issuer_chain: bool = False,
    qe_identity_mrsigner_hex: str = "DC" * 32,
    qe_identity_isv_prod_id: int = 2,
    qe_identity_id: str = "TD_QE",
    qe_identity_version: int = 2,
    tcb_info_next_update: str = "2030-07-18T08:42:58Z",
    qe_identity_next_update: str = "2030-07-08T07:24:59Z",
    tcb_eval: bool = True,
) -> None:
    dst = VECTORS_DIR / fixture_id
    dst.mkdir(parents=True, exist_ok=True)
    payload = make_synth_input(
        ak_mismatch=ak_mismatch,
        qe_report_data=qe_report_data,
        pck_crl_not_after=pck_crl_not_after,
        root_crl_not_after=root_crl_not_after,
        revoke_intermediate=revoke_intermediate,
        wrong_tcb_info_issuer_chain=wrong_tcb_info_issuer_chain,
        qe_identity_mrsigner_hex=qe_identity_mrsigner_hex,
        qe_identity_isv_prod_id=qe_identity_isv_prod_id,
        qe_identity_id=qe_identity_id,
        qe_identity_version=qe_identity_version,
        tcb_info_next_update=tcb_info_next_update,
        qe_identity_next_update=qe_identity_next_update,
        tcb_eval=tcb_eval,
    )
    (dst / "input.json").write_text(json.dumps(payload, indent=2))
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
    manifest += "fixture_kind: synthetic-intel-chain\n"
    manifest += "notes: |\n"
    for line in notes.strip().splitlines():
        manifest += f"  {line}\n"
    (dst / "manifest.yaml").write_text(manifest)


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

    # 328 — PCK CRL expired
    expired_crl_next_update = datetime(2023, 6, 1, tzinfo=timezone.utc)
    write_synth_fixture(
        fixture_id="328-pck-crl-expired",
        title="Synthetic PCK CRL nextUpdate before verification time → PCK_CRL_EXPIRED.",
        notes=(
            "The PCK CRL is correctly signed by the synthetic Platform CA,\n"
            "but its nextUpdate is 2023-06-01 while verification time is\n"
            "2023-06-30. This isolates CRL freshness from CRL signature and\n"
            "revocation-entry checks."
        ),
        pck_crl_not_after=expired_crl_next_update,
        rejection_code="PCK_CRL_EXPIRED",
        spec_refs=["4.7.4"],
    )

    # 329 — Root CRL expired
    write_synth_fixture(
        fixture_id="329-root-crl-expired",
        title="Synthetic Root CRL nextUpdate before verification time → ROOT_CRL_EXPIRED.",
        notes=(
            "The Root CRL is correctly signed by the synthetic Root CA, but\n"
            "its nextUpdate is before the fixture verification time. This\n"
            "catches SDKs that verify PCK CRLs but forget Root CA CRL\n"
            "freshness."
        ),
        root_crl_not_after=expired_crl_next_update,
        rejection_code="ROOT_CRL_EXPIRED",
        spec_refs=["4.7.4"],
    )

    # 333 — Quote signed by an AK different from the embedded AK
    write_synth_fixture(
        fixture_id="333-ak-mismatch",
        title="Quote signature made by a different AK than the quote embeds → AK_MISMATCH ideal.",
        notes=(
            "The quote embeds AK A and the QE report data correctly binds AK A,\n"
            "but the quote signature over header || body is produced by AK B.\n"
            "A verifier can only prove the embedded AK did not sign the quote;\n"
            "most SDKs surface that as QUOTE_SIGNATURE_INVALID. The fixture\n"
            "keeps AK_MISMATCH as the ideal taxonomy code and allows the\n"
            "cryptographically equivalent quote-signature collapse."
        ),
        ak_mismatch=True,
        tcb_eval=False,
        rejection_code=[
            "AK_MISMATCH",
            "QUOTE_SIGNATURE_INVALID",
        ],
        spec_refs=["4.3", "4.5"],
    )

    # 334 — Platform/intermediate CA revoked by Root CRL
    write_synth_fixture(
        fixture_id="334-intermediate-revoked",
        title="Synthetic Root CRL revokes the Platform CA → INTERMEDIATE_REVOKED.",
        notes=(
            "The Root CRL is correctly signed and fresh, but it contains the\n"
            "synthetic Platform CA serial number. This isolates the Root CRL\n"
            "revocation-entry path from Root CRL signature and freshness."
        ),
        revoke_intermediate=True,
        rejection_code=[
            "INTERMEDIATE_REVOKED",
            "PCK_REVOKED",
            "TCB_REVOKED",
            "QV_RESULT_TERMINAL_UNSPECIFIED",
        ],
        spec_refs=["4.7.4"],
    )

    # 335 — TCB Info issuer chain does not anchor to trusted Intel root
    write_synth_fixture(
        fixture_id="335-tcb-info-chain-invalid",
        title="Synthetic TCB Info issuer chain uses an untrusted root → TCB_INFO_CHAIN_INVALID.",
        notes=(
            "The TCB Info JSON itself is signed by the quote's synthetic TCB\n"
            "signer, but the supplied TCB Info issuer chain is from a\n"
            "different synthetic root. Verifiers must reject the collateral\n"
            "issuer chain before trusting the signed TCB payload."
        ),
        wrong_tcb_info_issuer_chain=True,
        rejection_code=[
            "TCB_INFO_CHAIN_INVALID",
            "TCB_INFO_SIGNATURE_INVALID",
            "QV_RESULT_TERMINAL_UNSPECIFIED",
        ],
        spec_refs=["4.7.3"],
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

    # 336 — QE Identity MRSIGNER mismatch, with valid signature
    write_synth_fixture(
        fixture_id="336-qe-identity-mrsigner-mismatch",
        title="Signed QE Identity MRSIGNER differs from QE report → QE_IDENTITY_MRSIGNER_MISMATCH.",
        notes=(
            "The QE Identity envelope is signed and fresh, but its MRSIGNER\n"
            "field is all-zero while the QE report carries the synthetic DC*\n"
            "MRSIGNER. This reaches the field comparison path directly."
        ),
        qe_identity_mrsigner_hex="00" * 32,
        rejection_code=[
            "QE_IDENTITY_MRSIGNER_MISMATCH",
            "QE_IDENTITY_FIELD_MISMATCH",
            "QV_RESULT_TERMINAL_UNSPECIFIED",
        ],
        spec_refs=["4.7.9"],
    )

    # 337 — QE Identity field mismatch, with valid signature
    write_synth_fixture(
        fixture_id="337-qe-identity-field-mismatch",
        title="Signed QE Identity ISVPRODID differs from QE report → QE_IDENTITY_FIELD_MISMATCH.",
        notes=(
            "The QE Identity envelope is signed and fresh, but isvprodid=3\n"
            "while the QE report has ISVPRODID=2. This is the generic QE\n"
            "identity field-mismatch path distinct from MRSIGNER."
        ),
        qe_identity_isv_prod_id=3,
        rejection_code=[
            "QE_IDENTITY_FIELD_MISMATCH",
            "QV_RESULT_TERMINAL_UNSPECIFIED",
        ],
        spec_refs=["4.7.9"],
    )

    # 338 — QE Identity expired while TCB Info remains fresh
    write_synth_fixture(
        fixture_id="338-qe-identity-expired-only",
        title="Synthetic QE Identity nextUpdate before verification time while TCB Info is fresh → QE_IDENTITY_EXPIRED.",
        notes=(
            "The synthetic TCB Info is still fresh at verification time,\n"
            "but QE Identity nextUpdate is 2023-06-01 while verification\n"
            "time is 2023-06-30. This isolates QE Identity freshness from\n"
            "TCB Info freshness so SDKs cannot legitimately stop first at\n"
            "TCB_INFO_EXPIRED."
        ),
        qe_identity_next_update="2023-06-01T00:00:00Z",
        rejection_code=[
            "QE_IDENTITY_EXPIRED",
            "QE_IDENTITY_FIELD_MISMATCH",
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

    # 347 — QE report data does not bind to the attestation key
    write_synth_fixture(
        fixture_id="347-ak-binding-invalid",
        title="QE report data signed by PCK but not SHA256(AK) → AK_BINDING_INVALID.",
        notes=(
            "Synthetic quote keeps both signatures valid: the quote is\n"
            "signed by the embedded AK and the QE report is signed by the\n"
            "PCK leaf. Only QE.ReportData is wrong. A verifier that checks\n"
            "signatures but skips the AK ↔ QE report binding would accept a\n"
            "substituted attestation key."
        ),
        qe_report_data=b"\x99" * 32 + b"\x00" * 32,
        tcb_eval=False,
        rejection_code="AK_BINDING_INVALID",
        spec_refs=["4.5", "A.3.10"],
    )

    # 348 — QE Identity id is wrong but signature is valid
    write_synth_fixture(
        fixture_id="348-qe-identity-id-invalid",
        title="Signed QE Identity with id != TD_QE → QE_IDENTITY_ID_INVALID.",
        notes=(
            "The QE Identity JSON is signed by the synthetic TCB signer, so\n"
            "this is not a tamper/signature failure. The verifier must still\n"
            "reject because Intel TDX requires enclaveIdentity.id == TD_QE."
        ),
        qe_identity_id="SGX_QE",
        rejection_code="QE_IDENTITY_ID_INVALID",
        spec_refs=["4.7.9"],
    )

    # 349 — QE Identity version is wrong but signature is valid
    write_synth_fixture(
        fixture_id="349-qe-identity-version-invalid",
        title="Signed QE Identity with version != 2 → QE_IDENTITY_VERSION_INVALID.",
        notes=(
            "The QE Identity envelope is signed and fresh, but the inner\n"
            "version is 3 instead of the TDX-supported version 2. This\n"
            "guards parsers that accept future/foreign identity formats\n"
            "without an explicit compatibility decision."
        ),
        qe_identity_version=3,
        rejection_code="QE_IDENTITY_VERSION_INVALID",
        spec_refs=["4.7.9"],
    )

    print("Wrote Phase 2B attestation-tdx fixtures:")
    for d in sorted(VECTORS_DIR.iterdir()):
        if d.is_dir() and d.name[:3] in (
            "326", "327", "328", "329",
            "333", "334", "335", "336", "337", "338",
            "340", "341", "342", "343", "344", "345",
            "347", "348", "349",
        ):
            print(f"  {d.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
