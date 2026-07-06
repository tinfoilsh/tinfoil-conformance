#!/usr/bin/env python3
"""Happy TDX end-to-end verify-full fixture (SPEC §11.1 / §7.3.2).

The standard flow cross-checks the Sigstore-attested MultiPlatform measurement
against a freshly-verified hardware attestation. All existing verify-full happy
fixtures are SEV; there was no TDX end-to-end coverage (the verify-full TDX
sub-runner was an unwired stub in every SDK).

No consistent sigstore⇄TDX asset existed, so we generate one: take fixture 001's
in-toto payload, overwrite its predicate `tdx_measurement.rtmr1/rtmr2` with the
values from the real TDX quote (fixture 300), and re-sign with a synthetic trust
root (via signed_fixtures / lib.spec). The resulting bundle's MultiPlatform
measurement then matches the 300 quote, so verify-full accepts.

Gated on attestation_tdx.verify_full_supported (go, py) so SDKs without a wired
verify-full TDX path skip.
"""

import base64
import copy
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "fixturegen"))

from lib.spec import FixtureSpec, build_bundle_and_trust_root  # noqa: E402
from signed_fixtures import (  # noqa: E402
    DEFAULT_REPO,
    default_policy,
    seed_digest,
    seed_payload,
    _verification_time,
)

VF_DIR = REPO_ROOT / "vectors" / "verify-full"
TDX_DIR = REPO_ROOT / "vectors" / "attestation-tdx" / "300-tdx-v4-happy"


def main() -> None:
    # 300's TD report registers (SPEC §4.1.3: TD Quote Body, 584 bytes @ 0x30).
    tdx_in = json.loads((TDX_DIR / "input.json").read_text())
    quote = base64.b64decode(tdx_in["quote_b64"])
    body = quote[48 : 48 + 584]
    rtmr1 = body[376:424].hex()
    rtmr2 = body[424:472].hex()

    # Overwrite the seed predicate's TDX rtmr1/rtmr2 with 300's so the
    # MultiPlatform measurement matches the quote (§7.3.2 compares rtmr1/rtmr2).
    p = json.loads(seed_payload().decode())
    pred = copy.deepcopy(p["predicate"])
    pred["tdx_measurement"]["rtmr1"] = rtmr1
    pred["tdx_measurement"]["rtmr2"] = rtmr2
    p["predicate"] = pred
    mutated = json.dumps(p).encode()

    spec = FixtureSpec(payload_bytes=mutated, workflow_repository=DEFAULT_REPO)
    g = build_bundle_and_trust_root(spec)

    payload = {
        "schema_version": "1",
        "mode": "standard",
        "sigstore": {
            "bundle_b64": base64.standard_b64encode(json.dumps(g.bundle).encode()).decode(),
            "expected_digest_sha256_hex": seed_digest(),
            "repo": DEFAULT_REPO,
            "policy": default_policy(DEFAULT_REPO),
            "trust_root_b64": base64.standard_b64encode(json.dumps(g.trust_root).encode()).decode(),
            "verification_time_unix": _verification_time(spec),
        },
        "attestation_tdx": {k: v for k, v in tdx_in.items() if k != "schema_version"},
    }

    dst = VF_DIR / "506-standard-flow-tdx-happy"
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "input.json").write_text(json.dumps(payload, indent=2) + "\n")
    (dst / "expected.json").write_text(
        json.dumps({"stage": "verify-full", "accepted": True}, indent=2) + "\n"
    )
    (dst / "manifest.yaml").write_text(
        "id: 506-standard-flow-tdx-happy\n"
        "stage: verify-full\n"
        "title: |\n"
        "  Standard flow (TDX) happy path: sigstore MultiPlatform measurement matches the verified TDX quote (SPEC §11.1 / §7.3.2).\n"
        'spec_refs: ["11.1", "7.3.2", "4"]\n'
        "expects:\n"
        "  exit_code: 0\n"
        "required_capabilities:\n"
        "  attestation_tdx.verify_full_supported: true\n"
        '  sigstore.trust_root_loading: "configurable"\n'
        "fixture_kind: composite\n"
        "notes: |\n"
        "  End-to-end standard flow on TDX. The Sigstore bundle is a synthetic\n"
        "  re-sign of fixture 001's payload with its predicate tdx_measurement\n"
        "  rtmr1/rtmr2 set to the real TDX quote (fixture 300)'s values, so the\n"
        "  MultiPlatform measurement matches the fully-verified quote (§7.3.2) and\n"
        "  verify-full accepts. Exercises the verify-full TDX path end-to-end\n"
        "  (previously an unwired stub). Gated on attestation_tdx.verify_full_supported\n"
        "  so rs (no native TDX verifier) and js (TDX only in the js-tdx variant) skip.\n"
    )
    print(f"wrote {dst}")


if __name__ == "__main__":
    main()
