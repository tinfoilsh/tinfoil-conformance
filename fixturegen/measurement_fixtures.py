#!/usr/bin/env python3
"""Generate verify-measurement (SPEC §7) fixtures.

Stateless / pure-function fixtures — no key material, no cert chains.
Just input/output pairs exercising the fingerprint computation (§7.2)
and cross-platform comparison rules (§7.3)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = REPO_ROOT / "vectors" / "measurement"

SEV_URI = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
TDX_URI = "https://tinfoil.sh/predicate/tdx-guest/v2"
MP_URI = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"

RTMR3_ZERO = "0" * 96

# Stable register values for fixtures. 96 hex chars = 48 bytes.
SNP_MEASUREMENT = "a" * 96
RTMR1_VALUE = "b" * 96
RTMR2_VALUE = "c" * 96
MRTD_VALUE = "d" * 96
RTMR0_VALUE = "e" * 96


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def fingerprint_multi(type_uri: str, registers: list[str]) -> str:
    return sha256_hex(type_uri + "".join(registers))


def fingerprint(measurement: dict[str, Any]) -> str:
    """SPEC §7.2 fingerprint of `measurement` for its own type."""
    regs = measurement["registers"]
    if len(regs) == 1:
        return regs[0].lower()
    return fingerprint_multi(measurement["type"], [r.lower() for r in regs])


def write_fixture(
    *,
    fixture_id: str,
    title: str,
    spec_refs: list[str],
    notes: str,
    source: dict[str, Any],
    target: dict[str, Any] | None,
    expected_accept: bool,
    rejection_code: str | list[str] | None = None,
    required_capabilities: dict[str, Any] | None = None,
) -> None:
    input_payload = {
        "schema_version": "1",
        "source": source,
    }
    if target is not None:
        input_payload["target"] = target
    else:
        input_payload["target"] = None

    if expected_accept:
        outputs = {"source_fingerprint_hex": fingerprint(source)}
        if target is not None:
            outputs["target_fingerprint_hex"] = fingerprint(target)
        else:
            outputs["target_fingerprint_hex"] = None
        expected = {
            "stage": "verify-measurement",
            "accepted": True,
            "outputs": outputs,
        }
    else:
        expected = {
            "stage": "verify-measurement",
            "accepted": False,
            "rejection": {"code": rejection_code},
        }

    dst = VECTORS_DIR / fixture_id
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "input.json").write_text(json.dumps(input_payload, indent=2))
    (dst / "expected.json").write_text(json.dumps(expected, indent=2))

    caps = required_capabilities or {}

    manifest = (
        f"id: {fixture_id}\n"
        f"stage: verify-measurement\n"
        f"title: |\n  {title}\n"
        f"spec_refs: {json.dumps(spec_refs)}\n"
        f"expects:\n"
        f"  exit_code: {0 if expected_accept else 10}\n"
    )
    if rejection_code is not None:
        manifest += f"  rejection_code: {json.dumps(rejection_code)}\n"
    manifest += "required_capabilities:\n"
    if caps:
        for path, value in caps.items():
            manifest += f"  {path}: {json.dumps(value)}\n"
    else:
        manifest += "  {}\n"
    manifest += "fixture_kind: synthetic\n"
    manifest += "notes: |\n"
    for line in notes.strip().splitlines():
        manifest += f"  {line}\n"
    (dst / "manifest.yaml").write_text(manifest)


def main() -> None:
    VECTORS_DIR.mkdir(parents=True, exist_ok=True)

    # ---- 100s: Fingerprint computation (§7.2) ----------------------------
    write_fixture(
        fixture_id="100-fingerprint-sev-single-register",
        title="SEV single-register fingerprint equals the register value itself.",
        spec_refs=["7.2"],
        notes=(
            "SPEC §7.2: 'Single-register measurements (e.g., SevGuestV2):\n"
            "The fingerprint is the register value itself (the hex string).'"
        ),
        source={"type": SEV_URI, "registers": [SNP_MEASUREMENT]},
        target=None,
        expected_accept=True,
    )

    write_fixture(
        fixture_id="101-fingerprint-tdx-multi-register",
        title="TDX 5-register fingerprint = hex(SHA-256(type || join(registers, ''))).",
        spec_refs=["7.2"],
        notes=(
            "SPEC §7.2: 'Multi-register measurements: fingerprint =\n"
            "hex(SHA-256(predicate_type_uri + join(registers, \"\"))).' The\n"
            "predicate_type_uri is the literal string of the measurement's OWN\n"
            "type — important for the cross-platform fingerprinting case (§7.2)."
        ),
        source={
            "type": TDX_URI,
            "registers": [MRTD_VALUE, RTMR0_VALUE, RTMR1_VALUE, RTMR2_VALUE, RTMR3_ZERO],
        },
        target=None,
        expected_accept=True,
    )

    write_fixture(
        fixture_id="102-fingerprint-multiplatform-multi-register",
        title="MultiPlatform 3-register fingerprint = hex(SHA-256(MP_URI || join)).",
        spec_refs=["7.2"],
        notes=(
            "Same fingerprint formula as §7.2 multi-register, with the MP type\n"
            "as prefix. Catches an SDK that uses the wrong type prefix\n"
            "(e.g., concatenating the target's type instead of the source's)."
        ),
        source={
            "type": MP_URI,
            "registers": [SNP_MEASUREMENT, RTMR1_VALUE, RTMR2_VALUE],
        },
        target=None,
        expected_accept=True,
    )

    write_fixture(
        fixture_id="103-fingerprint-uppercase-normalized",
        title="Uppercase register hex must produce same fingerprint as lowercase.",
        spec_refs=["7.2", "7.3"],
        notes=(
            "SPEC §7.3: 'Implementations MUST normalize register values to\n"
            "lowercase before any comparison or storage.' Fingerprint output\n"
            "is itself lowercase hex. Catches SDKs that pass mixed-case bytes\n"
            "directly into SHA-256 without normalizing first — a real source\n"
            "of cross-platform fingerprint divergence."
        ),
        source={
            "type": MP_URI,
            "registers": [
                SNP_MEASUREMENT.upper(),
                RTMR1_VALUE.upper(),
                RTMR2_VALUE.upper(),
            ],
        },
        target=None,
        expected_accept=True,
    )

    # ---- 110s: Same-type comparison (§7.3.1) -----------------------------
    write_fixture(
        fixture_id="110-compare-same-type-sev-equal",
        title="Two equal SEV measurements compare equal.",
        spec_refs=["7.3.1"],
        notes="SPEC §7.3.1 same-type: all registers MUST match exactly.",
        source={"type": SEV_URI, "registers": [SNP_MEASUREMENT]},
        target={"type": SEV_URI, "registers": [SNP_MEASUREMENT]},
        expected_accept=True,
    )

    write_fixture(
        fixture_id="111-compare-same-type-tdx-equal",
        title="Two equal TDX measurements compare equal.",
        spec_refs=["7.3.1"],
        notes="SPEC §7.3.1 same-type: all 5 TDX registers MUST match exactly.",
        source={
            "type": TDX_URI,
            "registers": [MRTD_VALUE, RTMR0_VALUE, RTMR1_VALUE, RTMR2_VALUE, RTMR3_ZERO],
        },
        target={
            "type": TDX_URI,
            "registers": [MRTD_VALUE, RTMR0_VALUE, RTMR1_VALUE, RTMR2_VALUE, RTMR3_ZERO],
        },
        expected_accept=True,
    )

    write_fixture(
        fixture_id="112-compare-same-type-mismatch",
        title="Same-type SEV with differing snp_measurement must reject.",
        spec_refs=["7.3.1"],
        notes="SPEC §7.3.1: any register difference → MEASUREMENT_MISMATCH.",
        source={"type": SEV_URI, "registers": [SNP_MEASUREMENT]},
        target={"type": SEV_URI, "registers": [SNP_MEASUREMENT[:-2] + "ff"]},
        expected_accept=False,
        rejection_code="MEASUREMENT_MISMATCH",
    )

    write_fixture(
        fixture_id="113-compare-same-type-lowercase-normalization",
        title="Same-type compare with uppercase target accepts (lowercase-normalized).",
        spec_refs=["7.3"],
        notes=(
            "SPEC §7.3: 'All measurement register values MUST be compared as\n"
            "lowercase hex strings.' Two registers that differ only in case\n"
            "MUST be treated as equal. Catches SDKs that do byte-for-byte\n"
            "compares without normalizing case."
        ),
        source={"type": SEV_URI, "registers": [SNP_MEASUREMENT]},
        target={"type": SEV_URI, "registers": [SNP_MEASUREMENT.upper()]},
        expected_accept=True,
    )

    # ---- 120s: MultiPlatform → TDX comparison (§7.3.2) -------------------
    _MP_TDX_CAP = {"measurement.compare_multiplatform_to_tdx_supported": True}

    write_fixture(
        fixture_id="120-compare-multiplatform-to-tdx-equal",
        title="MP source vs TDX target with matching RTMR1/RTMR2 and zero RTMR3 → accept.",
        spec_refs=["7.3.2"],
        notes=(
            "SPEC §7.3.2: source[1]==target[2], source[2]==target[3],\n"
            "target[4]==RTMR3_ZERO. MRTD and RTMR0 are NOT compared (they are\n"
            "hardware-platform-dependent and verified separately via §6).\n"
            "Gated on measurement.compare_multiplatform_to_tdx_supported —\n"
            "tinfoil-js's compareMeasurements doesn't implement the MP↔TDX\n"
            "path yet and skips honestly."
        ),
        source={
            "type": MP_URI,
            "registers": [SNP_MEASUREMENT, RTMR1_VALUE, RTMR2_VALUE],
        },
        target={
            "type": TDX_URI,
            "registers": [MRTD_VALUE, RTMR0_VALUE, RTMR1_VALUE, RTMR2_VALUE, RTMR3_ZERO],
        },
        expected_accept=True,
        required_capabilities=_MP_TDX_CAP,
    )

    write_fixture(
        fixture_id="121-compare-multiplatform-to-tdx-rtmr3-nonzero",
        title="MP→TDX with TDX RTMR3 != zeros must reject with MEASUREMENT_RTMR3_NONZERO.",
        spec_refs=["7.3.2", "7.3.6"],
        notes=(
            "SPEC §7.3.2 requires target.registers[4] (RTMR3) == RTMR3_ZERO\n"
            "(96 hex zeros). Any other value MUST cause rejection. SPEC §7.3.6\n"
            "fixes the canonical RTMR3_ZERO constant."
        ),
        source={
            "type": MP_URI,
            "registers": [SNP_MEASUREMENT, RTMR1_VALUE, RTMR2_VALUE],
        },
        target={
            "type": TDX_URI,
            "registers": [MRTD_VALUE, RTMR0_VALUE, RTMR1_VALUE, RTMR2_VALUE, "1" + "0" * 95],
        },
        expected_accept=False,
        rejection_code="MEASUREMENT_RTMR3_NONZERO",
        required_capabilities=_MP_TDX_CAP,
    )

    write_fixture(
        fixture_id="122-compare-multiplatform-to-tdx-rtmr1-mismatch",
        title="MP→TDX with RTMR1 mismatch must reject with MEASUREMENT_MISMATCH.",
        spec_refs=["7.3.2"],
        notes=(
            "source[1] != target[2] → mismatch. Catches an SDK that only checks\n"
            "RTMR2 and silently skips RTMR1."
        ),
        source={
            "type": MP_URI,
            "registers": [SNP_MEASUREMENT, RTMR1_VALUE, RTMR2_VALUE],
        },
        target={
            "type": TDX_URI,
            "registers": [
                MRTD_VALUE,
                RTMR0_VALUE,
                RTMR1_VALUE[:-2] + "ff",  # mismatched RTMR1
                RTMR2_VALUE,
                RTMR3_ZERO,
            ],
        },
        expected_accept=False,
        rejection_code="MEASUREMENT_MISMATCH",
        required_capabilities=_MP_TDX_CAP,
    )

    write_fixture(
        fixture_id="123-compare-multiplatform-to-tdx-bad-target-count",
        title="MP→TDX with TDX target having 4 registers (not 5) must reject.",
        spec_refs=["7.3.2"],
        notes=(
            "SPEC §7.3.2 precondition: target MUST have exactly 5 registers\n"
            "(TDX_REGISTER_COUNT). An SDK that lazily accesses target[2]/[3]\n"
            "without checking length first might pass on a short target — the\n"
            "fixture forces them to validate count first."
        ),
        source={
            "type": MP_URI,
            "registers": [SNP_MEASUREMENT, RTMR1_VALUE, RTMR2_VALUE],
        },
        target={
            "type": TDX_URI,
            "registers": [MRTD_VALUE, RTMR0_VALUE, RTMR1_VALUE, RTMR2_VALUE],
        },
        expected_accept=False,
        rejection_code=["MEASUREMENT_REGISTER_COUNT_INVALID", "MEASUREMENT_MISMATCH"],
        required_capabilities=_MP_TDX_CAP,
    )

    # ---- 130s: MultiPlatform → SEV comparison (§7.3.3) -------------------
    write_fixture(
        fixture_id="130-compare-multiplatform-to-sev-equal",
        title="MP source vs SEV target with matching snp_measurement → accept.",
        spec_refs=["7.3.3"],
        notes="SPEC §7.3.3: source[0] (SNP) MUST equal target[0] (SNP).",
        source={
            "type": MP_URI,
            "registers": [SNP_MEASUREMENT, RTMR1_VALUE, RTMR2_VALUE],
        },
        target={"type": SEV_URI, "registers": [SNP_MEASUREMENT]},
        expected_accept=True,
    )

    write_fixture(
        fixture_id="131-compare-multiplatform-to-sev-mismatch",
        title="MP→SEV with SNP measurement mismatch must reject.",
        spec_refs=["7.3.3"],
        notes="source[0] != target[0] → MEASUREMENT_MISMATCH.",
        source={
            "type": MP_URI,
            "registers": [SNP_MEASUREMENT, RTMR1_VALUE, RTMR2_VALUE],
        },
        target={"type": SEV_URI, "registers": [SNP_MEASUREMENT[:-2] + "ff"]},
        expected_accept=False,
        rejection_code="MEASUREMENT_MISMATCH",
    )

    # ---- 140s: Reverse comparisons (§7.3.4) ------------------------------
    write_fixture(
        fixture_id="140-compare-tdx-to-multiplatform-reverse-equal",
        title="TDX source vs MP target (reverse of §7.3.2) → swap and accept.",
        spec_refs=["7.3.4"],
        notes=(
            "SPEC §7.3.4: 'If the source and target types are reversed (e.g.,\n"
            "TDX source vs MultiPlatform target), the comparison is delegated\n"
            "by swapping: target.assert_equal(source).' Catches SDKs that only\n"
            "handle MP-as-source and reject MP-as-target. Gated on the same\n"
            "MP↔TDX capability since the reverse path uses §7.3.2 under the hood."
        ),
        source={
            "type": TDX_URI,
            "registers": [MRTD_VALUE, RTMR0_VALUE, RTMR1_VALUE, RTMR2_VALUE, RTMR3_ZERO],
        },
        target={
            "type": MP_URI,
            "registers": [SNP_MEASUREMENT, RTMR1_VALUE, RTMR2_VALUE],
        },
        expected_accept=True,
        required_capabilities=_MP_TDX_CAP,
    )

    write_fixture(
        fixture_id="141-compare-sev-to-multiplatform-reverse-equal",
        title="SEV source vs MP target (reverse of §7.3.3) → swap and accept.",
        spec_refs=["7.3.4"],
        notes="Reverse of §7.3.3 via §7.3.4 swap rule.",
        source={"type": SEV_URI, "registers": [SNP_MEASUREMENT]},
        target={
            "type": MP_URI,
            "registers": [SNP_MEASUREMENT, RTMR1_VALUE, RTMR2_VALUE],
        },
        expected_accept=True,
    )

    # ---- 150s: Unsupported combinations (§7.3.5) -------------------------
    write_fixture(
        fixture_id="150-compare-tdx-direct-to-sev-unsupported",
        title="TDX directly vs SEV (no MP bridge) must reject as unsupported combination.",
        spec_refs=["7.3.5"],
        notes=(
            "SPEC §7.3.5: 'Any type combination not covered by Sections 7.3.1\n"
            "through 7.3.4 (e.g., TdxGuestV2 vs SevGuestV2 directly) MUST be\n"
            "rejected with an incompatible-types error.' Only MP can bridge\n"
            "TDX↔SEV; direct comparison must fail."
        ),
        source={
            "type": TDX_URI,
            "registers": [MRTD_VALUE, RTMR0_VALUE, RTMR1_VALUE, RTMR2_VALUE, RTMR3_ZERO],
        },
        target={"type": SEV_URI, "registers": [SNP_MEASUREMENT]},
        expected_accept=False,
        rejection_code="MEASUREMENT_TYPE_COMBINATION_UNSUPPORTED",
    )

    print("Wrote measurement fixtures:")
    for d in sorted(VECTORS_DIR.iterdir()):
        if d.is_dir():
            print(f"  {d.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
