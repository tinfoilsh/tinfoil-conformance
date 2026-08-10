#!/usr/bin/env python3
"""Generate v3 ENVELOPE-layer conformance fixtures (SPEC_COVERAGE_V3 E1–E13 + happy).

Envelope rules need no crypto: envelope.Check does strict JSON parsing plus
nonce / endorsed-section-hash / report_data binding, never a signature. So we
build one valid base document (with the correct report_data ladder) and apply a
single-field mutation per rule. Every mutation rejects at the v3-check-envelope
stage; the happy base accepts. Emits the shared fixture format the SDK harnesses
consume: {id, stage, input{document_b64,nonce_hex,repo}, expected{accepted}}.
"""

import base64
import hashlib
import json
import os
import sys

# Format registry — must match verifier/envelope/envelope.go exactly.
ATTESTATION_V3 = "https://tinfoil.sh/predicate/attestation/v3"
REPORT_DATA_V1 = "https://tinfoil.sh/report-data/v1"
CRYPTO_MATERIAL = "https://tinfoil.sh/crypto-material/v1"
DEVICE_EVIDENCE = "https://tinfoil.sh/device-evidence/v1"
SEV_REPORT_V1 = "https://tinfoil.sh/format/sev-snp-report/v1"
KEY_SPKI_FP = "https://tinfoil.sh/key/spki-fp-sha256/v1"
AMD_CRL = "https://tinfoil.sh/collateral/amd-crl/v1"

REPO = "tinfoilsh/confidential-inference-proxy"
NONCE = bytes(range(32))  # fixed; the fixture's nonce_hex must equal doc.challenge.nonce


def canon(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode()


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def base_doc() -> dict:
    """A document that passes envelope.Check: correct section hashes and the
    report_data ladder SHA-256(LABEL || nonce || cm_hash || de_hash)."""
    cm = canon({"format": CRYPTO_MATERIAL, "items": []})
    de = canon({"format": DEVICE_EVIDENCE, "items": []})
    cmh, deh = sha(cm), sha(de)
    report_data = sha(REPORT_DATA_V1.encode() + NONCE + cmh + deh) + b"\x00" * 32
    return {
        "format": ATTESTATION_V3,
        "challenge": {
            "nonce": NONCE.hex(),
            "report_data": report_data.hex(),
            "report_data_algorithm": REPORT_DATA_V1,
        },
        "cpu_evidence": {
            "format": SEV_REPORT_V1,
            "report_base64": b64(b"\x00" * 1184),  # opaque to the envelope stage
            "endorsed": {"crypto_material_hash": cmh.hex(), "device_evidence_hash": deh.hex()},
        },
        "crypto_material": b64(cm),
        "device_evidence": b64(de),
        "collateral": [],
    }


def with_section(cm_obj=None, de_obj=None) -> dict:
    """base_doc with a replaced section. Section-shape rejects happen during
    Parse, before Check's hash comparison, so the endorsed hash need not match."""
    d = base_doc()
    if cm_obj is not None:
        d["crypto_material"] = b64(canon(cm_obj))
    if de_obj is not None:
        d["device_evidence"] = b64(canon(de_obj))
    return d


# One mutation per rule; each returns the raw document bytes.
def e1():  # unknown top-level member (case-sensitive, no unknowns)
    d = base_doc()
    d["extra_field"] = 1
    return canon(d)


def e2():  # duplicate member (dicts can't hold dup keys, so patch the bytes)
    return canon(base_doc()).replace(b'{"format":', b'{"format":"x","format":', 1)


def e3():  # not valid UTF-8 (0xFF inside a string value)
    raw = bytearray(canon(base_doc()))
    i = raw.index(b'"report_base64":"') + len(b'"report_base64":"')
    raw[i:i] = b"\xff"
    return bytes(raw)


def e4():  # non-canonical base64 for an endorsed section (embedded newline)
    d = base_doc()
    cm = d["crypto_material"]
    d["crypto_material"] = cm[:4] + "\n" + cm[4:]
    return canon(d)


def e5():  # hex field not lowercase
    d = base_doc()
    d["challenge"]["report_data"] = d["challenge"]["report_data"].upper()
    return canon(d)


def e6():  # trailing data after the JSON
    return canon(base_doc()) + b" trailing"


def e7():  # document shape: crypto_material section missing
    d = base_doc()
    del d["crypto_material"]
    return canon(d)


def e8():  # challenge shape: unknown report_data_algorithm
    d = base_doc()
    d["challenge"]["report_data_algorithm"] = REPORT_DATA_V1 + "-x"
    return canon(d)


def e9():  # endorsed hash wrong length (31 bytes)
    d = base_doc()
    d["cpu_evidence"]["endorsed"]["crypto_material_hash"] = "aa" * 31
    return canon(d)


def e10():  # crypto_material: duplicate item id
    item = {"id": "tls", "format": KEY_SPKI_FP, "data": "ab" * 32}
    return canon(with_section(cm_obj={"format": CRYPTO_MATERIAL, "items": [item, item]}))


def e11():  # crypto_material: unknown section format
    return canon(with_section(cm_obj={"format": CRYPTO_MATERIAL + "-x", "items": []}))


def e12():  # device_evidence: item with no id.
    # NOTE: Parse validates device items for id/dup only — kind/vendor/format
    # are NOT enforced (see review: device evidence hash-bound but under-appraised).
    # So we exercise the ENFORCED violation here; the missing-kind/vendor gap is
    # tracked as a divergence probe, not asserted as a reject.
    item = {"id": "", "kind": "gpu", "vendor": "nvidia", "format": "x", "evidence": {}}
    return canon(with_section(de_obj={"format": DEVICE_EVIDENCE, "items": [item]}))


def e13():  # collateral: duplicate entry id
    d = base_doc()
    entry = {"id": "c1", "role": "endorsement", "format": AMD_CRL, "data": {}}
    d["collateral"] = [entry, entry]
    return canon(d)


# Binding checks (envelope.Check): well-formed but not consistent. These are the
# freshness/hash-binding rules — distinct from the parse/shape rules above.
def e14():  # challenge.nonce valid but != the verifier's nonce (freshness)
    d = base_doc()
    d["challenge"]["nonce"] = "ff" * 32
    return canon(d)


def e15():  # crypto_material_hash valid but != SHA-256(crypto_material section)
    d = base_doc()
    d["cpu_evidence"]["endorsed"]["crypto_material_hash"] = "bb" * 32
    return canon(d)


def e16():  # device_evidence_hash valid but != SHA-256(device_evidence section)
    d = base_doc()
    d["cpu_evidence"]["endorsed"]["device_evidence_hash"] = "bb" * 32
    return canon(d)


def e17():  # challenge.report_data valid 64 bytes but != recomputed ladder
    d = base_doc()
    d["challenge"]["report_data"] = "cc" * 64
    return canon(d)


MUTATIONS = {f"e{i}": fn for i, fn in enumerate(
    [e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e12, e13, e14, e15, e16, e17], start=1)}


def fixture(fid: str, doc: bytes, accepted: bool) -> dict:
    return {
        "id": fid,
        "stage": "v3-check-envelope",
        "input": {
            "schema_version": "1",
            "document_b64": b64(doc),
            "nonce_hex": NONCE.hex(),
            "repo": REPO,
        },
        "expected": {"accepted": accepted},
    }


def valid_doc(cm_items=None, de_items=None, collateral=None) -> dict:
    """A document that passes Check with populated sections: the endorsed hashes
    and report_data ladder are recomputed over the actual section bytes."""
    d = base_doc()
    cm = canon({"format": CRYPTO_MATERIAL, "items": cm_items or []})
    de = canon({"format": DEVICE_EVIDENCE, "items": de_items or []})
    cmh, deh = sha(cm), sha(de)
    d["challenge"]["report_data"] = (sha(REPORT_DATA_V1.encode() + NONCE + cmh + deh) + b"\x00" * 32).hex()
    d["cpu_evidence"]["endorsed"] = {"crypto_material_hash": cmh.hex(), "device_evidence_hash": deh.hex()}
    d["crypto_material"] = b64(cm)
    d["device_evidence"] = b64(de)
    if collateral is not None:
        d["collateral"] = collateral
    return d


# Positive variations that MUST accept — populated sections and collateral — so a
# port that wrongly rejects non-empty sections is caught.
POSITIVES = {
    "envelope-pos-crypto-items":
        lambda: valid_doc(cm_items=[{"id": "tls", "format": KEY_SPKI_FP, "data": "ab" * 32}]),
    "envelope-pos-device-item":
        lambda: valid_doc(de_items=[{"id": "gpu0", "kind": "gpu", "vendor": "nvidia",
                                     "format": "https://tinfoil.sh/x", "evidence": {}}]),
    "envelope-pos-collateral":
        lambda: valid_doc(collateral=[{"id": "c1", "role": "endorsement",
                                       "format": AMD_CRL, "data": {}}]),
}


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else "vectors/v3/envelope"
    os.makedirs(out, exist_ok=True)
    fixtures = [fixture("envelope-happy", canon(base_doc()), True)]
    for fid, fn in POSITIVES.items():
        fixtures.append(fixture(fid, canon(fn()), True))
    for rid, fn in MUTATIONS.items():
        fixtures.append(fixture(rid, fn(), False))
    for f in fixtures:
        with open(os.path.join(out, f["id"] + ".json"), "w") as fh:
            fh.write(json.dumps(f, indent=2) + "\n")
    print(f"wrote {len(fixtures)} envelope fixtures to {out}/")


if __name__ == "__main__":
    main()
