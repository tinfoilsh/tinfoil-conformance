#!/usr/bin/env python3
"""Generate Phase 1 verify-full fixtures: SPEC §11 end-to-end orchestration.

Phase 1 chains the existing per-stage fixtures into composite SPEC §11
fixtures that test the full Sigstore → hardware-attestation cross-check
flow. Each composite fixture stacks inputs from passing per-stage
fixtures, so we get end-to-end coverage with no new ground truth.

Sources:
  - Sigstore: vectors/sigstore/001-happy-path-snp-tdx-multiplatform/input.json
    (real production bundle asserting a SnpTdxMultiPlatformV1 measurement
    whose register[0] equals the SEV-SNP measurement in the staged Genoa
    attestation bundle — i.e. the Sigstore-attested truth and the
    hardware-reported truth match).
  - SEV-SNP: vectors/attestation-sev/200-real-sev-snp-happy/input.json
    (the same staged Genoa attestation bundle used as the SEV foundation).
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = REPO_ROOT / "vectors" / "verify-full"
SIG_DIR = REPO_ROOT / "vectors" / "sigstore"
SEV_DIR = REPO_ROOT / "vectors" / "attestation-sev"


def _load_sigstore_input(fixture_id: str) -> dict[str, Any]:
    return json.loads((SIG_DIR / fixture_id / "input.json").read_text())


def _load_sev_input(fixture_id: str) -> dict[str, Any]:
    return json.loads((SEV_DIR / fixture_id / "input.json").read_text())


def write_fixture(
    *,
    fixture_id: str,
    title: str,
    notes: str,
    spec_refs: list[str],
    payload: dict[str, Any],
    accepted: bool,
    rejection_code: str | list[str] | None = None,
    rejection_stage: str | None = None,
    required_caps: dict[str, Any] | None = None,
) -> None:
    dst = VECTORS_DIR / fixture_id
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "input.json").write_text(json.dumps(payload, indent=2))

    if accepted:
        expected: dict[str, Any] = {"stage": "verify-full", "accepted": True}
    else:
        assert rejection_code is not None
        rej: dict[str, Any] = {"code": rejection_code}
        if rejection_stage:
            rej["stage"] = rejection_stage
        expected = {"stage": "verify-full", "accepted": False, "rejection": rej}
    (dst / "expected.json").write_text(json.dumps(expected, indent=2))

    manifest = (
        f"id: {fixture_id}\n"
        f"stage: verify-full\n"
        f"title: |\n  {title}\n"
        f"spec_refs: {json.dumps(spec_refs)}\n"
        f"expects:\n"
        f"  exit_code: {0 if accepted else 10}\n"
    )
    if not accepted:
        manifest += f"  rejection_code: {json.dumps(rejection_code)}\n"
        if rejection_stage:
            manifest += f"  rejection_stage: {json.dumps(rejection_stage)}\n"
    manifest += "required_capabilities:\n"
    default_caps = {
        "attestation_sev.supported": True,
        "attestation_sev.injected_collateral_supported": True,
    }
    for cap, val in (required_caps or default_caps).items():
        manifest += f"  {cap}: {json.dumps(val)}\n"
    manifest += (
        "fixture_kind: composite\n"
        "notes: |\n"
    )
    for line in notes.strip().splitlines():
        manifest += f"  {line}\n"
    (dst / "manifest.yaml").write_text(manifest)


def main() -> None:
    sigstore_in = _load_sigstore_input("001-happy-path-snp-tdx-multiplatform")
    sev_in = _load_sev_input("200-real-sev-snp-happy")

    # 500 — Standard flow happy path (SPEC §11.1)
    standard_payload = {
        "schema_version": "1",
        "mode": "standard",
        "sigstore": {
            "bundle_b64": sigstore_in["bundle_b64"],
            "expected_digest_sha256_hex": sigstore_in["expected_digest_sha256_hex"],
            "repo": sigstore_in["repo"],
            "policy": sigstore_in["policy"],
            "trust_root_b64": sigstore_in["trust_root_b64"],
            "verification_time_unix": sigstore_in.get("verification_time_unix"),
        },
        "attestation_sev": {
            "attestation_doc_b64": sev_in["attestation_doc_b64"],
            "vcek_der_b64": sev_in["vcek_der_b64"],
            "expiration_check_date_unix": sev_in.get("expiration_check_date_unix"),
        },
    }
    write_fixture(
        fixture_id="500-standard-flow-sev-happy",
        title="Standard-flow SEV-SNP: Sigstore MultiPlatform measurement matches SEV report measurement → accepted.",
        spec_refs=["11.1", "7.3.4"],
        payload=standard_payload,
        accepted=True,
        required_caps={
            "attestation_sev.supported": True,
            "attestation_sev.injected_collateral_supported": True,
            "sigstore.trust_root_loading": "configurable",
            "flow_modes_supported": "standard",
        },
        notes=(
            "Phase 1 verify-full happy path — SPEC §11.1 standard flow chained\n"
            "end-to-end on the staged Tinfoil Genoa bundle.\n"
            "\n"
            "Steps:\n"
            "  1. verify-sigstore extracts MultiPlatform measurement\n"
            "     (register[0] = SEV target = 09ef32...eb519).\n"
            "  2. verify-attestation-sev extracts SEV measurement\n"
            "     (same 09ef32...eb519 — they MUST match by construction).\n"
            "  3. verify-measurement compares MultiPlatform → SEV via SPEC §7.3.4\n"
            "     reduction; register[0] equality means the enclave the SDK is\n"
            "     talking to matches the artifact the publisher signed.\n"
            "\n"
            "Any sub-stage divergence (sigstore bundle invalid, SEV report\n"
            "invalid, measurement mismatch) MUST surface as a rejection with\n"
            "the originating stage's SPEC-anchored rejection code.\n"
            "\n"
            "Gates on sigstore.trust_root_loading=configurable (so the staged\n"
            "production trust root is honored) + attestation_sev.supported\n"
            "(SDKs without SEV verification skip the entire chain)."
        ),
    )

    # 501 — Standard flow, Sigstore sub-stage rejects.
    sigstore_reject_payload = deepcopy(standard_payload)
    sigstore_reject_payload["sigstore"]["expected_digest_sha256_hex"] = "0" * 64
    write_fixture(
        fixture_id="501-standard-flow-sigstore-digest-mismatch",
        title="Standard-flow SEV-SNP: Sigstore subject digest mismatch rejects before attestation.",
        spec_refs=["11.1", "5.4"],
        payload=sigstore_reject_payload,
        accepted=False,
        rejection_code="SUBJECT_DIGEST_MISMATCH",
        rejection_stage="verify-sigstore",
        required_caps={
            "sigstore.trust_root_loading": "configurable",
            "flow_modes_supported": "standard",
        },
        notes=(
            "SPEC §11.1 composition must preserve the failing sub-stage.\n"
            "This vector starts from the standard happy path, but pins the\n"
            "caller-supplied expected artifact digest to all-zeroes. The\n"
            "Sigstore bundle itself is otherwise valid, so verify-full MUST\n"
            "reject with SUBJECT_DIGEST_MISMATCH and rejection.stage=\n"
            "'verify-sigstore' before consulting hardware attestation.\n"
            "\n"
            "This is the full-flow counterpart of sigstore/016."
        ),
    )

    # 502 — Standard flow, SEV attestation sub-stage rejects.
    sev_reject_payload = deepcopy(standard_payload)
    sev_reject_payload["attestation_sev"]["policy"] = {
        "expected_measurement_hex": "f" * 96,
    }
    write_fixture(
        fixture_id="502-standard-flow-sev-attestation-pin-mismatch",
        title="Standard-flow SEV-SNP: SEV measurement policy mismatch propagates from attestation stage.",
        spec_refs=["11.1", "3.8"],
        payload=sev_reject_payload,
        accepted=False,
        rejection_code="MEASUREMENT_MISMATCH",
        rejection_stage="verify-attestation-sev",
        required_caps={
            "attestation_sev.supported": True,
            "attestation_sev.injected_collateral_supported": True,
            "attestation_sev.extended_checks_supported": True,
            "sigstore.trust_root_loading": "configurable",
            "flow_modes_supported": "standard",
        },
        notes=(
            "SPEC §11.1 composition must preserve SEV-SNP attestation\n"
            "failures instead of flattening them into a generic verify-full\n"
            "error. The Sigstore stage succeeds, then the nested SEV policy\n"
            "pins expected_measurement_hex to all-0xff. The real report\n"
            "measurement is 09ef32...eb519, so the SEV sub-stage MUST reject\n"
            "with MEASUREMENT_MISMATCH and rejection.stage=\n"
            "'verify-attestation-sev'.\n"
            "\n"
            "This is the full-flow counterpart of attestation-sev/400."
        ),
    )

    # 510 — Pinned-measurement flow (SPEC §11.3)
    pinned_payload = {
        "schema_version": "1",
        "mode": "pinned",
        "pinned_measurement": {
            # The SEV measurement extracted from the staged bundle. Pinned
            # directly with no sigstore involvement — represents the
            # SPEC §11.3 re-verification flow where a previously-verified
            # measurement is re-checked against a fresh attestation.
            "type": "https://tinfoil.sh/predicate/sev-snp-guest/v2",
            "registers": [
                "09ef32acf90fcfeb6206d1a46c13145cef736ebbb83f18eaff680b686232031546ff5fd39c44599699ee8734cbbeb519"
            ],
        },
        "attestation_sev": {
            "attestation_doc_b64": sev_in["attestation_doc_b64"],
            "vcek_der_b64": sev_in["vcek_der_b64"],
            "expiration_check_date_unix": sev_in.get("expiration_check_date_unix"),
        },
    }
    write_fixture(
        fixture_id="510-pinned-flow-sev-happy",
        title="Pinned-measurement flow: caller-pinned SEV measurement matches fresh SEV attestation → accepted.",
        spec_refs=["11.3"],
        payload=pinned_payload,
        accepted=True,
        required_caps={
            "attestation_sev.supported": True,
            "attestation_sev.injected_collateral_supported": True,
            "flow_modes_supported": "pinned",
        },
        notes=(
            "SPEC §11.3 pinned-measurement flow. No Sigstore involvement —\n"
            "the caller supplies the trusted measurement directly (from\n"
            "previous verification, out-of-band trust, or developer intent)\n"
            "and the SDK only needs to verify the fresh hardware attestation\n"
            "matches it. Common case: re-verification on every connection.\n"
            "\n"
            "Skips on SDKs lacking flow_modes_supported='pinned'."
        ),
    )

    # 520 — Pinned mismatch
    pinned_mismatch_payload = {
        "schema_version": "1",
        "mode": "pinned",
        "pinned_measurement": {
            "type": "https://tinfoil.sh/predicate/sev-snp-guest/v2",
            "registers": [
                # All ff's — guaranteed to never match the real attestation.
                "f" * 96
            ],
        },
        "attestation_sev": {
            "attestation_doc_b64": sev_in["attestation_doc_b64"],
            "vcek_der_b64": sev_in["vcek_der_b64"],
            "expiration_check_date_unix": sev_in.get("expiration_check_date_unix"),
        },
    }
    write_fixture(
        fixture_id="520-pinned-flow-measurement-mismatch",
        title="Pinned measurement doesn't match SEV attestation → MEASUREMENT_MISMATCH.",
        spec_refs=["11.3", "7.3"],
        payload=pinned_mismatch_payload,
        accepted=False,
        rejection_code="MEASUREMENT_MISMATCH",
        rejection_stage="verify-measurement",
        required_caps={
            "attestation_sev.supported": True,
            "attestation_sev.injected_collateral_supported": True,
            "flow_modes_supported": "pinned",
        },
        notes=(
            "Negative pinned-flow fixture: pin all-0xff SEV measurement,\n"
            "fresh attestation reports the real Genoa measurement. The\n"
            "verify-measurement sub-stage MUST reject as MEASUREMENT_MISMATCH\n"
            "with rejection.stage='verify-measurement'.\n"
            "\n"
            "Confirms the verify-full chain doesn't short-circuit on sigstore\n"
            "or attestation success — the final cross-check is normative."
        ),
    )

    print("Wrote Phase 1 verify-full fixtures:")
    for fid in (
        "500-standard-flow-sev-happy",
        "501-standard-flow-sigstore-digest-mismatch",
        "502-standard-flow-sev-attestation-pin-mismatch",
        "510-pinned-flow-sev-happy",
        "520-pinned-flow-measurement-mismatch",
    ):
        print(f"  - {VECTORS_DIR / fid}")


if __name__ == "__main__":
    main()
