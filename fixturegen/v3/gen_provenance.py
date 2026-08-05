#!/usr/bin/env python3
"""Generate v3 PROVENANCE-layer conformance fixtures (SPEC_COVERAGE_V3 P-rules).

Each fixture is a full v3 document whose sigstore-code reference-values collateral
carries a synthetic Sigstore bundle (see sigstore_synth), plus the synthetic
trusted root it was produced under. The happy document authenticates through the
`v3-authenticate-provenance` stage; every mutation is a single-field change that
rejects there. Emits the shared fixture format {id, stage, input, expected}.

The stage authenticates the CODE bundle only, so this file covers the code-side
rules P1, P3–P14. The platform-endorsements identity rules (P2, P15) and the
both-entries-present rule (P16) are exercised in the identity slice, which builds
the sigstore-platform bundle.
"""

import base64
import copy
import hashlib
import json
import os

import sigstore_synth as ss
from gen_envelope import base_doc, canon, b64, REPO

CODE_FMT = "https://tinfoil.sh/collateral/sigstore-code/v1"
ROLE_RV = "reference-values"
PRED = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
TAG = "v1.0.0"
IDENTITY = f"https://github.com/{REPO}/.github/workflows/release.yml@refs/tags/{TAG}"
DIGEST = hashlib.sha256(b"code-artifact-v1").hexdigest()


def statement(pred_type=PRED, with_shape=True, digest=DIGEST):
    predicate = {"snp_measurement": "aa" * 48, "tdx_measurement": {"rtmr1": "bb" * 48, "rtmr2": "cc" * 48}}
    if with_shape:
        predicate["vm_shape"] = {"cpus": 8, "memory_mb": 32768, "gpus": 1, "disks": 2}
    return json.dumps({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "cip", "digest": {"sha256": digest}}],
        "predicateType": pred_type,
        "predicate": predicate,
    }, separators=(",", ":")).encode()


def code_entry(bundle, digest=DIGEST, repo=REPO):
    return {"id": "sigstore-code", "role": ROLE_RV, "format": CODE_FMT,
            "data": {"repo": repo, "tag": TAG, "digest": digest, "sigstore_bundle": bundle}}


def doc_with(bundle, digest=DIGEST):
    d = base_doc()
    d["collateral"] = [code_entry(bundle, digest)]
    return d


def _happy_bundle():
    return ss.build_bundle(IDENTITY, statement())


# Each mutation returns (document, trusted_root, accepted).
def happy():
    b, t = _happy_bundle()
    return doc_with(b), t, True


def p1():  # required sigstore-code reference-values entry missing
    _, t = _happy_bundle()
    d = base_doc()
    d["collateral"] = []
    return d, t, False


def p3():  # legacy bundle layout: x509 certificate chain instead of single certificate
    b, t = _happy_bundle()
    leaf = b["verificationMaterial"].pop("certificate")
    b["verificationMaterial"]["x509CertificateChain"] = {"certificates": [leaf]}
    return doc_with(b), t, False


def p4_zero():  # DSSE envelope carries zero signatures
    b, t = _happy_bundle()
    b["dsseEnvelope"]["signatures"] = []
    return doc_with(b), t, False


def p4_two():  # DSSE envelope carries more than one signature
    b, t = _happy_bundle()
    b["dsseEnvelope"]["signatures"].append(dict(b["dsseEnvelope"]["signatures"][0]))
    return doc_with(b), t, False


def p5():  # certificate does not chain to the trusted Fulcio root
    b, t = _happy_bundle()
    t = copy.deepcopy(t)
    t["certificateAuthorities"][0]["certChain"]["certificates"] = ss.rogue_ca_cert_chain()
    return doc_with(b), t, False


def p6():  # no SCT verifiable against a trusted CT log key
    b, t = _happy_bundle()
    t = copy.deepcopy(t)
    t["ctlogs"] = []
    return doc_with(b), t, False


def p7():  # no transparency-log entry
    b, t = _happy_bundle()
    b["verificationMaterial"]["tlogEntries"] = []
    return doc_with(b), t, False


def p8():  # observer timestamp outside the certificate validity window
    b, t = ss.build_bundle(IDENTITY, statement(), integrated_time=ss.INTEGRATED_TIME + 3600 * 24 * 400)
    return doc_with(b), t, False


def p9():  # DSSE signature does not verify under the leaf certificate key
    b, t = ss.build_bundle(IDENTITY, statement(), bad_dsse=True)
    return doc_with(b), t, False


def p10():  # subject[0] digest != the expected artifact digest
    b, t = _happy_bundle()
    other = hashlib.sha256(b"different-artifact").hexdigest()
    return doc_with(b, digest=other), t, False


def p11():  # signing identity SAN is a different repository
    ident = "https://github.com/attacker/evil/.github/workflows/release.yml@refs/tags/v1.0.0"
    b, t = ss.build_bundle(ident, statement())
    return doc_with(b), t, False


def p12():  # two SCTs share a CT log id
    b, t = ss.build_bundle(IDENTITY, statement(), dup_sct=True)
    return doc_with(b), t, False


def p13_type():  # statement predicate type is not the expected code URI
    b, t = ss.build_bundle(IDENTITY, statement(pred_type=PRED + "-wrong"))
    return doc_with(b), t, False


def p13_shape():  # code predicate declares no vm_shape
    b, t = ss.build_bundle(IDENTITY, statement(with_shape=False))
    return doc_with(b), t, False


def p14():  # SAN ref is a branch, not a tag
    ident = f"https://github.com/{REPO}/.github/workflows/release.yml@refs/heads/main"
    b, t = ss.build_bundle(ident, statement())
    return doc_with(b), t, False


MUTATIONS = {
    "provenance-happy": happy,
    "p1": p1, "p3": p3, "p4-zero-sigs": p4_zero, "p4-two-sigs": p4_two,
    "p5": p5, "p6": p6, "p7": p7, "p8": p8, "p9": p9, "p10": p10,
    "p11": p11, "p12": p12, "p13-predicate-type": p13_type,
    "p13-missing-shape": p13_shape, "p14": p14,
}


def fixture(fid, doc, troot, accepted):
    return {
        "id": fid,
        "stage": "v3-authenticate-provenance",
        "input": {
            "schema_version": "1",
            "document_b64": b64(canon(doc)),
            "nonce_hex": "",
            "repo": REPO,
            "sigstore_trusted_root_json_b64": b64(json.dumps(troot).encode()),
        },
        "expected": {"accepted": accepted},
    }


def main():
    out = "vectors/v3/provenance"
    os.makedirs(out, exist_ok=True)
    n = 0
    for fid, fn in MUTATIONS.items():
        doc, troot, accepted = fn()
        with open(os.path.join(out, fid + ".json"), "w") as fh:
            fh.write(json.dumps(fixture(fid, doc, troot, accepted), indent=2) + "\n")
        n += 1
    print(f"wrote {n} provenance fixtures to {out}/")


if __name__ == "__main__":
    main()
