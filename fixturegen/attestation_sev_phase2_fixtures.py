#!/usr/bin/env python3
"""Generate Phase 2A verify-attestation-sev fixtures: real-bundle byte mutations.

Phase 2A of SPEC §3 conformance. Each fixture takes the real Genoa
attestation bundle from vectors/attestation-sev/_assets/ and mutates
one byte (or short range) to target a specific verification check —
signature, parser, VCEK chain, or expiration.

Synthetic-violation policy fixtures (DEBUG bit set, reserved bit set,
guest_policy.migrate_ma set) — which require a re-signed report so the
signature passes but policy validation fails — live in a future Phase
4B once the SEV synth chain library lands.
"""

from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = REPO_ROOT / "vectors" / "attestation-sev"
ASSETS = VECTORS_DIR / "_assets"

BUNDLE = json.loads((ASSETS / "real_genoa_bundle.json").read_text())
BASE_BODY_GZ = base64.standard_b64decode(BUNDLE["enclaveAttestationReport"]["body"])
BASE_REPORT = gzip.decompress(BASE_BODY_GZ)
assert len(BASE_REPORT) == 1184
BASE_VCEK_DER = base64.standard_b64decode(BUNDLE["vcek"])

# 2026-06-01 — same as Phase 1A baseline; inside the VCEK validity window.
DEFAULT_DATE = 1780272000
# Past the VCEK NotAfter (2033-01-11): 2034-01-01 = 2019686400.
PAST_NOTAFTER_DATE = 2019686400


def _regzip(report: bytes) -> str:
    return base64.standard_b64encode(gzip.compress(report)).decode()


def report_with_byte(offset: int, value: int) -> bytes:
    b = bytearray(BASE_REPORT)
    b[offset] = value
    return bytes(b)


def report_with_bytes(offset: int, replacement: bytes) -> bytes:
    b = bytearray(BASE_REPORT)
    b[offset:offset + len(replacement)] = replacement
    return bytes(b)


def vcek_with_byte(offset: int, value: int) -> bytes:
    b = bytearray(BASE_VCEK_DER)
    b[offset] = value
    return bytes(b)


def make_input(
    *,
    report_bytes: bytes | None = None,
    vcek_bytes: bytes | None = None,
    date_unix: int = DEFAULT_DATE,
    policy: dict | None = None,
) -> dict[str, Any]:
    report = report_bytes if report_bytes is not None else BASE_REPORT
    vcek = vcek_bytes if vcek_bytes is not None else BASE_VCEK_DER
    payload: dict[str, Any] = {
        "schema_version": "1",
        "attestation_doc_b64": _regzip(report),
        "vcek_der_b64": base64.standard_b64encode(vcek).decode(),
        "expiration_check_date_unix": date_unix,
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
    report_bytes: bytes | None = None,
    vcek_bytes: bytes | None = None,
    date_unix: int = DEFAULT_DATE,
    policy: dict | None = None,
    extra_caps: dict[str, Any] | None = None,
) -> None:
    inp = make_input(
        report_bytes=report_bytes,
        vcek_bytes=vcek_bytes,
        date_unix=date_unix,
        policy=policy,
    )
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


def main() -> None:
    # ---- 210 — wrong report version --------------------------------------
    # SEV-SNP v3 only; flipping byte 0x00 from 0x03 → 0x02 surfaces as a
    # wrong-version parse rejection upstream. go-sev-guest's abi.ReportToProto
    # accepts both v2 and v3 layouts; v2's signed-region offsets differ so the
    # signature check then fails. Either rejection is SPEC-correct (the report
    # doesn't match what was signed).
    write_fixture(
        fixture_id="210-wrong-report-version",
        title="Report version byte set to 2 → must reject as wrong-version, format-unsupported, or signature-invalid.",
        rejection_code=[
            "WRONG_REPORT_VERSION",
            "REPORT_FORMAT_UNSUPPORTED",
            "REPORT_SIGNATURE_INVALID",
        ],
        spec_refs=["3.1"],
        report_bytes=report_with_byte(0x00, 0x02),
        notes=(
            "Single-byte mutation at offset 0x00 (report.version) from 0x03 → 0x02.\n"
            "\n"
            "v2 reports use a different layout than v3 — different fields end\n"
            "up in the must-be-zero ranges go-sev-guest sanity-checks at parse\n"
            "(e.g. MBZ at 0x188..0x1a0 for v3 has guest_svn-ish bytes from v2).\n"
            "\n"
            "Cross-SDK divergence captured in list-form rejection_code:\n"
            "  - SDKs with a strict version check emit WRONG_REPORT_VERSION.\n"
            "  - SDKs that hit a parser MBZ violation emit REPORT_FORMAT_UNSUPPORTED.\n"
            "  - SDKs that parse leniently reach the signature step and emit\n"
            "    REPORT_SIGNATURE_INVALID (v2 signed region ≠ v3 signed region).\n"
            "All three are SPEC §3.1-anchored."
        ),
    )

    # ---- 211 — truncated report ------------------------------------------
    # Drop the last byte so the report is 1183 bytes; SPEC §3.1 requires 1184.
    write_fixture(
        fixture_id="211-truncated-report",
        title="Report truncated to 1183 bytes → must reject as REPORT_TRUNCATED.",
        rejection_code=["REPORT_TRUNCATED", "REPORT_FORMAT_UNSUPPORTED"],
        spec_refs=["3.1"],
        report_bytes=BASE_REPORT[:-1],
        notes=(
            "Truncates the report by one byte (1184 → 1183). Per SPEC §3.1 a\n"
            "SEV-SNP attestation report MUST be exactly 1184 bytes (16-byte\n"
            "fixed prefix + 1168-byte body). SDKs that detect the wrong length\n"
            "before parsing emit REPORT_TRUNCATED; those that try to parse and\n"
            "fail emit REPORT_FORMAT_UNSUPPORTED. List-form rejection_code\n"
            "captures the divergence."
        ),
    )

    # ---- 220 — signature byte flipped ------------------------------------
    # The signature lives at offset 0x2A0..0x4A0 (ECDSA P-384 R || S in
    # little-endian, padded). Flipping any byte breaks the signature.
    write_fixture(
        fixture_id="220-signature-byte-flipped",
        title="VCEK report signature first byte flipped → must reject as REPORT_SIGNATURE_INVALID.",
        rejection_code="REPORT_SIGNATURE_INVALID",
        spec_refs=["3.6"],
        report_bytes=report_with_byte(0x2A0, BASE_REPORT[0x2A0] ^ 0xFF),
        notes=(
            "Flips byte 0x2A0 (first byte of the ECDSA P-384 signature). Per\n"
            "SPEC §3.6 the SDK MUST verify the report's signature over bytes\n"
            "0..0x2A0 with the VCEK public key. Any mutation in the signature\n"
            "field surfaces as REPORT_SIGNATURE_INVALID."
        ),
    )

    # ---- 221 — signed-region tampered ------------------------------------
    # Mutate inside the signed region (e.g., measurement at offset 0x90) so
    # the signature no longer covers the bytes-on-the-wire.
    write_fixture(
        fixture_id="221-signed-region-measurement-tampered",
        title="Measurement first byte flipped → must reject as REPORT_SIGNATURE_INVALID.",
        rejection_code="REPORT_SIGNATURE_INVALID",
        spec_refs=["3.6", "3.8"],
        report_bytes=report_with_byte(0x90, BASE_REPORT[0x90] ^ 0xFF),
        notes=(
            "Flips byte 0x90 (first byte of the 48-byte measurement field).\n"
            "Per SPEC §3.6 the signature covers bytes 0..0x2A0; mutating any\n"
            "byte inside that range invalidates the signature. SDKs MUST NOT\n"
            "rely on the measurement field for anything before signature\n"
            "verification passes — this fixture pins that ordering: signature\n"
            "check rejects FIRST, MEASUREMENT_MISMATCH is unreachable here."
        ),
    )

    # ---- 230 — VCEK first byte flipped -----------------------------------
    # The VCEK is a DER-encoded X.509 cert. Flipping the first byte (0x30 =
    # SEQUENCE tag) breaks DER parsing.
    write_fixture(
        fixture_id="230-vcek-first-byte-flipped",
        title="VCEK DER first byte flipped → must reject as VCEK_CHAIN_INVALID.",
        rejection_code=["VCEK_CHAIN_INVALID", "REPORT_FORMAT_UNSUPPORTED"],
        spec_refs=["3.3.3"],
        vcek_bytes=vcek_with_byte(0x00, BASE_VCEK_DER[0x00] ^ 0xFF),
        notes=(
            "Flips byte 0x00 of the DER VCEK certificate (0x30 SEQUENCE tag).\n"
            "Per SPEC §3.3.3 the VCEK MUST chain to AMD's ARK via ASK; any\n"
            "structural corruption surfaces as VCEK_CHAIN_INVALID. SDKs that\n"
            "reject at DER parse (before chain verification) emit\n"
            "REPORT_FORMAT_UNSUPPORTED."
        ),
    )

    # ---- 231 — VCEK signature byte flipped -------------------------------
    # The VCEK's signature is at the end of its DER (last few hundred bytes).
    # Flipping a byte in the signature breaks ASK→VCEK verification.
    sig_offset = len(BASE_VCEK_DER) - 8  # well inside the signatureValue field
    write_fixture(
        fixture_id="231-vcek-signature-tampered",
        title="VCEK ASK signature byte flipped → must reject as VCEK_CHAIN_INVALID.",
        rejection_code="VCEK_CHAIN_INVALID",
        spec_refs=["3.3.5"],
        vcek_bytes=vcek_with_byte(sig_offset, BASE_VCEK_DER[sig_offset] ^ 0xFF),
        notes=(
            f"Flips byte {sig_offset:#x} (8 bytes from end of VCEK DER, inside\n"
            "the ASK-issued signatureValue OCTET STRING). Per SPEC §3.3.5 the\n"
            "SDK MUST verify VCEK.signature with ASK.public_key. Any mutation\n"
            "of those bytes surfaces as VCEK_CHAIN_INVALID — DER parses fine\n"
            "but ASK→VCEK signature verification fails."
        ),
    )

    # ---- 240 — VCEK expired ----------------------------------------------
    # Push the verification date past the VCEK's NotAfter (2033-01-11).
    write_fixture(
        fixture_id="240-vcek-expired",
        title="Verification date past VCEK NotAfter → must reject as VCEK_EXPIRED.",
        rejection_code="VCEK_EXPIRED",
        spec_refs=["3.3.3"],
        date_unix=PAST_NOTAFTER_DATE,
        notes=(
            "Sets expiration_check_date_unix = 2019686400 (2034-01-01 UTC),\n"
            "past the staged VCEK's NotAfter (2033-01-11 16:38:56 UTC). Per\n"
            "SPEC §3.3.3 the SDK MUST reject when the verification time is\n"
            "outside the VCEK's validity window. Surfaces as VCEK_EXPIRED.\n"
            "\n"
            "Skips on SDKs with verification_time_override=system-clock-only —\n"
            "they consult datetime.now() unconditionally and the fixture-\n"
            "supplied date is ignored."
        ),
        extra_caps={"attestation_sev.verification_time_override": "supported"},
    )

    print("Wrote Phase 2A attestation-sev fixtures:")
    for fid in (
        "210-wrong-report-version",
        "211-truncated-report",
        "220-signature-byte-flipped",
        "221-signed-region-measurement-tampered",
        "230-vcek-first-byte-flipped",
        "231-vcek-signature-tampered",
        "240-vcek-expired",
    ):
        print(f"  - {VECTORS_DIR / fid}")


if __name__ == "__main__":
    main()
