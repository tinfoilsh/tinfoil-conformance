#!/usr/bin/env python3
"""Generate Phase 2 verify-attestation-tdx fixtures: byte-mutation tampering.

Phase 2 of the SPEC §4 / Intel TDX DCAP conformance buildout. Each fixture
takes the real SPR E4 quote from vectors/attestation-tdx/_assets/ and flips
one byte at an offset that targets a specific verification check. Offsets
are cross-referenced with google/go-tdx-guest's TestNegativeVerification
(verify/verify_test.go), so the rejection paths are anchored to known-good
upstream behavior.

All fixtures run in structural mode (policy.tcb_evaluation_required=false).
Collateral-mode fixtures (TCB Info / QE Identity tampering, PCK CRL
revocation) land in Phase 2B once collateral injection ships across more
SDKs.
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

# 2023-06-30 — inside TCB Info ∩ QE Identity validity (see fixture 300).
DEFAULT_DATE = 1688083200

# Far-future date used by 324-pck-expired to push past the PCK leaf's
# NotAfter without disturbing any other field.
FAR_FUTURE_DATE = 4102444800  # 2100-01-01


def quote_with_byte(offset: int, value: int) -> bytes:
    b = bytearray(BASE_QUOTE)
    b[offset] = value
    return bytes(b)


def quote_with_bytes(offset: int, replacement: bytes) -> bytes:
    b = bytearray(BASE_QUOTE)
    b[offset : offset + len(replacement)] = replacement
    return bytes(b)


def make_input(
    quote_bytes: bytes,
    *,
    date_unix: int = DEFAULT_DATE,
    tcb_eval: bool = False,
    expected_fmspc_hex: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "1",
        "quote_b64": base64.standard_b64encode(quote_bytes).decode(),
        "collateral": {
            "tcb_info_json": BASE_TCB_INFO,
            "qe_identity_json": BASE_QE_IDENTITY,
            "pck_crl_der_b64": base64.standard_b64encode(BASE_PCK_CRL).decode(),
            "root_crl_der_b64": base64.standard_b64encode(BASE_ROOT_CRL).decode(),
        },
        "expiration_check_date_unix": date_unix,
        "policy": {"tcb_evaluation_required": tcb_eval},
    }
    if expected_fmspc_hex is not None:
        payload["policy"]["expected_fmspc_hex"] = expected_fmspc_hex
    return payload


def write_fixture(
    *,
    fixture_id: str,
    title: str,
    notes: str,
    quote_bytes: bytes,
    rejection_code: str | list[str],
    spec_refs: list[str] | None = None,
    date_unix: int = DEFAULT_DATE,
    tcb_eval: bool = False,
    expected_fmspc_hex: str | None = None,
    extra_caps: dict[str, Any] | None = None,
) -> None:
    dst = VECTORS_DIR / fixture_id
    dst.mkdir(parents=True, exist_ok=True)
    inp = make_input(
        quote_bytes,
        date_unix=date_unix,
        tcb_eval=tcb_eval,
        expected_fmspc_hex=expected_fmspc_hex,
    )
    (dst / "input.json").write_text(json.dumps(inp, indent=2))
    expected = {
        "stage": "verify-attestation-tdx",
        "accepted": False,
        "rejection": {"code": rejection_code},
    }
    (dst / "expected.json").write_text(json.dumps(expected, indent=2))

    refs = spec_refs or ["4", "A.3"]
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
    )
    for cap_path, cap_value in (extra_caps or {}).items():
        manifest += f"  {cap_path}: {json.dumps(cap_value)}\n"
    manifest += (
        "fixture_kind: synthetic-mutation\n"
        "notes: |\n"
    )
    for line in notes.strip().splitlines():
        manifest += f"  {line}\n"
    (dst / "manifest.yaml").write_text(manifest)


# ---- Phase 2A fixtures ------------------------------------------------

def main() -> None:
    # 310 — wrong quote version (Intel §A.3 v4 spec)
    write_fixture(
        fixture_id="310-wrong-quote-version",
        title="Quote header.version byte set to 3 → must reject as format unsupported.",
        notes=(
            "Single-byte mutation at offset 0x00 → 0x03. go-tdx-guest's parser\n"
            "rejects at QuoteToProto with 'quote format not supported'. We only\n"
            "support v4 (§A.3) and v5 (§A.4) — versions 1-3 are EPID-era SGX\n"
            "quotes that aren't applicable to TDX. Anchor: go-tdx-guest test\n"
            "'Version byte Changed' (verify_test.go:294)."
        ),
        quote_bytes=quote_with_byte(0x00, 3),
        rejection_code="QUOTE_FORMAT_UNSUPPORTED",
    )

    # 311 — wrong TEE type (SGX masquerading as TDX)
    write_fixture(
        fixture_id="311-wrong-tee-type-sgx",
        title="Quote header.tee_type set to 0x00000000 (SGX) — must reject as TDX-only.",
        notes=(
            "Quote header bytes 4..7 (TEE Type field) zeroed. The TDX path\n"
            "(verify-attestation-tdx) MUST refuse to process a quote whose\n"
            "tee_type isn't 0x81 — accepting one would let an SGX enclave\n"
            "spoof a TDX attestation. The exact failure code depends on the\n"
            "SDK: some refuse at parse, some at signature verification (the\n"
            "tampered header invalidates the signed bytes). Both are honest\n"
            "rejections."
        ),
        quote_bytes=quote_with_bytes(0x04, b"\x00\x00\x00\x00"),
        rejection_code=[
            "WRONG_TEE_TYPE",
            "QUOTE_FORMAT_UNSUPPORTED",
            "QUOTE_SIGNATURE_INVALID",
        ],
    )

    # 312 — unsupported attestation key type (ECDSA-P-384)
    write_fixture(
        fixture_id="312-akt-p384-unsupported",
        title="Quote header.attestation_key_type set to 3 (P-384) — must reject (not supported).",
        notes=(
            "Intel §A.3.1 lists AKT=3 (ECDSA-P-384) but marks it 'currently\n"
            "not supported'. AKT=2 (P-256) is the only one in the wild. SDKs\n"
            "must either reject the AKT value up-front or fail at signature\n"
            "verification when the supposed P-384 key fails to load as P-256."
        ),
        quote_bytes=quote_with_bytes(0x02, b"\x03\x00"),
        rejection_code=[
            "ATTESTATION_KEY_TYPE_UNSUPPORTED",
            "QUOTE_FORMAT_UNSUPPORTED",
            "QUOTE_SIGNATURE_INVALID",
        ],
    )

    # 313 — wrong QE Vendor ID
    write_fixture(
        fixture_id="313-wrong-qe-vendor",
        title="Quote header.qe_vendor_id != Intel UUID — should reject; some libs may silently accept.",
        notes=(
            "Quote header bytes 12..27 (QE Vendor ID, 16-byte UUID) zeroed.\n"
            "Intel §A.3.1 fixes this field to 939A7233F79C4CA9940A0DB3957F0607\n"
            "for Intel-issued QEs. SDKs SHOULD reject non-Intel vendor IDs\n"
            "(prevents impersonation), but many today don't check this field\n"
            "and rely on PCK chain trust anchor. Either rejection (at\n"
            "vendor-check or at signature) or honest acceptance is a real\n"
            "documented behavior."
        ),
        quote_bytes=quote_with_bytes(0x0C, b"\x00" * 16),
        rejection_code=[
            "QE_VENDOR_UNKNOWN",
            "QUOTE_SIGNATURE_INVALID",
            "QUOTE_FORMAT_UNSUPPORTED",
        ],
    )

    # 314 — truncated quote
    truncated = BASE_QUOTE[:64]  # keep header + first 16 bytes of body
    write_fixture(
        fixture_id="314-truncated-quote",
        title="Quote truncated to 64 bytes (header + 16 body bytes) — must reject as truncated.",
        notes=(
            "v4 quote minimum size is 48 (header) + 584 (body) + 4 (sig len) +\n"
            "≥some signature data. 64 bytes can't possibly parse. Anchor: any\n"
            "SDK's bounds-check during parsing."
        ),
        quote_bytes=truncated,
        rejection_code=[
            "QUOTE_TRUNCATED",
            "QUOTE_FORMAT_UNSUPPORTED",
        ],
    )

    # 315 — signed data size byte tampered
    write_fixture(
        fixture_id="315-wrong-signed-data-size",
        title="Quote Signature Data Len byte changed → size mismatch must reject.",
        notes=(
            "go-tdx-guest's parser cross-checks the declared signature-data\n"
            "size against actual remaining bytes. Mutation at byte 0x278\n"
            "(within the sig_len field) makes the declared size inconsistent.\n"
            "Anchor: go-tdx-guest test 'Signed data size byte Changed'\n"
            "(verify_test.go:299)."
        ),
        quote_bytes=quote_with_byte(0x278, 0x10),
        rejection_code=[
            "QUOTE_FORMAT_UNSUPPORTED",
            "QUOTE_TRUNCATED",
        ],
    )

    # 320 — PCK leaf cert signature broken
    write_fixture(
        fixture_id="320-pck-leaf-sig-broken",
        title="Byte inside the PCK leaf certificate flipped → cert signature verification fails.",
        notes=(
            "Byte 0xB77 (inside the PCK leaf cert's signed portion) mutated.\n"
            "The intermediate CA's signature over the PCK leaf no longer\n"
            "verifies → PCK_CHAIN_INVALID. Anchor: go-tdx-guest test 'PCK\n"
            "Certificate byte Changed' (verify_test.go:319)."
        ),
        quote_bytes=quote_with_byte(0xB77, 0x32),
        rejection_code="PCK_CHAIN_INVALID",
        spec_refs=["4.2"],
    )

    # 321 — intermediate CA cert signature broken
    write_fixture(
        fixture_id="321-pck-intermediate-sig-broken",
        title="Byte inside the Intermediate Platform CA cert flipped → chain verification fails.",
        notes=(
            "Byte 0xF5F (inside Intermediate CA cert's signed portion) mutated.\n"
            "The Root CA's signature over the Intermediate no longer verifies\n"
            "→ PCK_CHAIN_INVALID. Anchor: go-tdx-guest test 'Intermediate\n"
            "Certificate byte Changed' (verify_test.go:314)."
        ),
        quote_bytes=quote_with_byte(0xF5F, 0x32),
        rejection_code="PCK_CHAIN_INVALID",
        spec_refs=["4.2"],
    )

    # 322 — Root CA cert byte changed
    write_fixture(
        fixture_id="322-pck-root-byte-changed",
        title="Byte inside the embedded Root CA cert (in quote sig data) → root rejected.",
        notes=(
            "Byte 0x1329 (inside the Root CA cert in the quote's PCK chain)\n"
            "mutated. The mutated root cert doesn't match the trusted Intel\n"
            "SGX Root CA, so the chain is rejected. SDKs may surface this as\n"
            "PCK_CHAIN_INVALID (chain doesn't anchor) or ROOT_CA_UNTRUSTED\n"
            "(the root in the chain doesn't match the embedded one).\n"
            "Anchor: go-tdx-guest test 'Root Certificate byte Changed'\n"
            "(verify_test.go:309)."
        ),
        quote_bytes=quote_with_byte(0x1329, 0x32),
        rejection_code=[
            "PCK_CHAIN_INVALID",
            "ROOT_CA_UNTRUSTED",
        ],
        spec_refs=["4.2"],
    )

    # 323 — overall cert chain byte changed
    write_fixture(
        fixture_id="323-pck-chain-byte-changed",
        title="Byte inside the PCK cert chain section → chain parse/verify rejects.",
        notes=(
            "Byte 0x1343 (within the PCK cert chain serialized bytes) mutated.\n"
            "Anchor: go-tdx-guest test 'Certificate chain byte Changed'\n"
            "(verify_test.go:304). Depending on the offset's PEM context,\n"
            "this surfaces as either INCOMPLETE (PEM boundary munged → can't\n"
            "find 3 blocks) or INVALID (3 blocks present but one sig fails)."
        ),
        quote_bytes=quote_with_byte(0x1343, 0x32),
        rejection_code=["PCK_CHAIN_INCOMPLETE", "PCK_CHAIN_INVALID"],
        spec_refs=["4.2"],
    )

    # 324 — PCK leaf cert expired (via expiration_check_date past NotAfter)
    write_fixture(
        fixture_id="324-pck-leaf-expired",
        title="expiration_check_date past PCK leaf NotAfter → cert expired rejection.",
        notes=(
            "No byte mutation. The base quote's PCK leaf cert NotAfter is\n"
            "2029-09-20 (from the cert chain). Setting\n"
            "expiration_check_date_unix to 2100-01-01 (far past) triggers\n"
            "the expiration check during chain validation. Some SDKs surface\n"
            "this as PCK_EXPIRED, others fold it into PCK_CHAIN_INVALID.\n"
            "Gated on attestation_tdx.verification_time_override='supported'\n"
            "— SDKs whose verifier reads datetime.now() unconditionally (e.g.\n"
            "tinfoil-python's cert_utils.verify_intel_chain) skip cleanly."
        ),
        quote_bytes=BASE_QUOTE,
        date_unix=FAR_FUTURE_DATE,
        rejection_code=[
            "PCK_EXPIRED",
            "PCK_CHAIN_INVALID",
        ],
        spec_refs=["4.2"],
        extra_caps={
            "attestation_tdx.verification_time_override": "supported",
        },
    )

    # 325 — FMSPC pin mismatch
    write_fixture(
        fixture_id="325-pck-fmspc-mismatch",
        title="policy.expected_fmspc_hex pinned to a different value → PCK_FMSPC_MISMATCH.",
        notes=(
            "The base quote's PCK leaf cert encodes FMSPC '50806f000000'\n"
            "(Sapphire Rapids E4). Pinning expected_fmspc_hex to '000000000000'\n"
            "in policy makes the verifier reject — guards against platform\n"
            "substitution where a valid PCK chain is for the wrong silicon.\n"
            "Gated on attestation_tdx.policy_fields_supported.expected_fmspc_hex\n"
            "because reading the FMSPC out of the PCK leaf requires either\n"
            "lib-internal API access or a hand-rolled PEM/X.509 ext parser."
        ),
        quote_bytes=BASE_QUOTE,
        expected_fmspc_hex="000000000000",
        rejection_code=[
            "PCK_FMSPC_MISMATCH",
            "QV_RESULT_TERMINAL_UNSPECIFIED",
        ],
        spec_refs=["4.6"],
        extra_caps={
            "attestation_tdx.policy_fields_supported.expected_fmspc_hex": True,
        },
    )

    # 330 — quote signature broken (via header byte mutation)
    write_fixture(
        fixture_id="330-quote-sig-broken-via-header",
        title="Header byte mutated → quote signature verification fails (signed-bytes integrity).",
        notes=(
            "Byte 0x1E (inside the header, signed by the AK) mutated. The\n"
            "AK signature over (header || body) no longer matches → quote\n"
            "signature invalid. Anchor: go-tdx-guest test 'Header Byte\n"
            "Changed' (verify_test.go:324)."
        ),
        quote_bytes=quote_with_byte(0x1E, 0x32),
        rejection_code="QUOTE_SIGNATURE_INVALID",
        spec_refs=["4.3"],
    )

    # 331 — TD body byte mutation (also breaks quote signature, different surface)
    write_fixture(
        fixture_id="331-quote-sig-broken-via-body",
        title="TD body byte mutated → quote signature verification fails.",
        notes=(
            "Byte 0x3C (inside the TD Quote Body, also signed by the AK)\n"
            "mutated. Symmetric to 330 but exercises body integrity: a\n"
            "single bit-flip inside MR_SEAM / MR_TD / RTMRs invalidates the\n"
            "AK signature. Anchor: go-tdx-guest test 'TD Quote Body Changed'\n"
            "(verify_test.go:329)."
        ),
        quote_bytes=quote_with_byte(0x3C, 0x32),
        rejection_code="QUOTE_SIGNATURE_INVALID",
        spec_refs=["4.3"],
    )

    # 332 — QE report signature broken
    write_fixture(
        fixture_id="332-qe-report-sig-broken",
        title="QE report signature byte mutated → PCK signature over QE report fails.",
        notes=(
            "Byte 0x482 is the first byte of the QE Report Signature inside\n"
            "the v4 quote's Type-6 QE Report Certification Data. The quote\n"
            "signature and PCK chain remain intact, but the PCK leaf's\n"
            "signature over the 384-byte QE report no longer verifies.\n"
            "This isolates Intel §4.4 from the earlier AK quote-signature\n"
            "check in 330/331."
        ),
        quote_bytes=quote_with_byte(0x482, 0x32),
        rejection_code="QE_REPORT_SIGNATURE_INVALID",
        spec_refs=["4.4", "A.3.11"],
    )

    print("Wrote Phase 2A attestation-tdx fixtures:")
    for d in sorted(VECTORS_DIR.iterdir()):
        if d.is_dir() and d.name[:3] in ("310", "311", "312", "313", "314", "315",
                                          "320", "321", "322", "323", "324", "325",
                                          "330", "331", "332"):
            print(f"  {d.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
