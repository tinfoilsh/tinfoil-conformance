#!/usr/bin/env python3
"""Generate v3 FRESHNESS fixtures (SPEC §10).

Two enforced, fixturable rules:

FR1 — nonce binding: the verifier binds the quote to *its own* nonce, never the
document's. The golden document accepts; supplying a different nonce rejects at
the envelope layer.

FR2 — freshness witness (required since feat/v3 #109): each Sigstore artifact
carries a separately signed freshness proof, verified against a pinned appraisal
time. Both-sided: the golden accepts, and every way the witness can be wrong
(missing, stale, future-dated, wrong signer, mismatched endorsement) rejects at
the provenance layer. `fr2-pos-at-max-age` pins MaxFreshnessAge (7 days).

FR3 (multiple endorsed stacks accepted, no rollback bound) is the ST2 positive
`st2-multi-measurement`.
"""

import base64
import json
import os

import gen_golden as gg
import gen_envelope as env
import gen_provenance as prov
import sigstore_synth as ss

DAY = 86400
APPRAISAL = ss.INTEGRATED_TIME  # golden pins verification_time to the witness time


def _doc_inp():
    """A fresh golden (document dict, input) pair, decoded for mutation."""
    _, inp = gg.golden()
    return json.loads(base64.b64decode(inp["document_b64"])), dict(inp)


def _encode(d, inp, **over):
    inp["document_b64"] = env.b64(env.canon(d))
    inp.update(over)
    return inp


def _set_witness(d, entry_id, bundle):
    for e in d["collateral"]:
        if e.get("id") == entry_id:
            e["data"]["sigstore_bundle"] = bundle
            return
    raise KeyError(entry_id)


def _drop(d, entry_id):
    d["collateral"] = [e for e in d["collateral"] if e.get("id") != entry_id]


def _fx(fid, inp, accepted, code="PROVENANCE_REJECTED"):
    exp = ({"accepted": True, "tls_public_key_fp": env.TLS_FP, "hpke_public_key": env.HPKE_KEY}
           if accepted else {"accepted": False, "code": code})
    return {"id": fid, "stage": "verify-attestation-v3", "input": inp, "expected": exp}


def main():
    out = "vectors/v3/freshness"
    os.makedirs(out, exist_ok=True)
    fixtures = []

    # FR1 nonce binding.
    _, base_inp = gg.golden()
    fixtures.append(_fx("fr1-nonce-fresh", base_inp, True))
    stale_nonce = dict(base_inp)
    stale_nonce["nonce_hex"] = "ff" * 32
    fixtures.append(_fx("fr1-nonce-stale", stale_nonce, False, "ENVELOPE_REJECTED"))

    # FR2 — the witness must be present, timely, correctly signed, and endorse
    # this artifact. Each fault rejects at the provenance layer.
    d, inp = _doc_inp(); _drop(d, "code-freshness")
    fixtures.append(_fx("fr2-missing-code-freshness", _encode(d, inp), False))
    d, inp = _doc_inp(); _drop(d, "platform-freshness")
    fixtures.append(_fx("fr2-missing-platform-freshness", _encode(d, inp), False))

    # Stale / future: the witness is valid, but the appraisal clock is moved past
    # the window / before the witness — isolating the age and skew checks.
    d, inp = _doc_inp()
    fixtures.append(_fx("fr2-stale", _encode(d, inp, verification_time_unix=APPRAISAL + 8 * DAY), False))
    d, inp = _doc_inp()
    fixtures.append(_fx("fr2-future-skew", _encode(d, inp, verification_time_unix=APPRAISAL - 3600), False))

    # Wrong signer: witness signed under the code identity, not the freshness one.
    wrong_id = ss.build_freshness_bundle(prov.SUBJECT, prov.DIGEST, prov.REPO, prov.TAG, prov.COMMIT,
                                         integrated_time=ss.INTEGRATED_TIME, identity=prov.IDENTITY)
    d, inp = _doc_inp(); _set_witness(d, "code-freshness", wrong_id)
    fixtures.append(_fx("fr2-wrong-identity", _encode(d, inp), False))

    # Mismatched endorsement: the witness endorses a different commit.
    mismatch = ss.build_freshness_bundle(prov.SUBJECT, prov.DIGEST, prov.REPO, prov.TAG, "0" * 40,
                                         integrated_time=ss.INTEGRATED_TIME)
    d, inp = _doc_inp(); _set_witness(d, "code-freshness", mismatch)
    fixtures.append(_fx("fr2-mismatched-endorsement", _encode(d, inp), False))

    # Boundary: exactly MaxFreshnessAge (7 days) still accepts — pins the constant.
    d, inp = _doc_inp()
    fixtures.append(_fx("fr2-pos-at-max-age", _encode(d, inp, verification_time_unix=APPRAISAL + 7 * DAY), True))

    for f in fixtures:
        with open(os.path.join(out, f["id"] + ".json"), "w") as fh:
            fh.write(json.dumps(f, indent=2) + "\n")
    print(f"wrote {len(fixtures)} freshness fixtures to {out}/")


if __name__ == "__main__":
    main()
