#!/usr/bin/env python3
"""Generate v3 embedded-root rejection fixtures.

Every other fixture injects a synthetic trust root, which never exercises the
verifier's *embedded* (production) root path. These fixtures leave the anchor
fields empty so the adapter falls back to its embedded AMD / Intel / Sigstore
roots, and pair that with a synthetic document — which must REJECT, because
synthetic material does not chain to the real embedded roots. This both asserts
"the production roots reject untrusted material" and covers the embedded-root
code (getDefaultClient / trustedRoots(nil) / intelRootCertPool) that synthetic
fixtures bypass. A real accepting document needs the deferred real-frozen lane.
"""

import json
import os

import gen_envelope as env
import gen_sev as gs
import gen_tdx as gt
import gen_provenance as gp


def _fx(fid, stage, doc, code):
    return {
        "id": fid, "stage": stage,
        "input": {  # no *_root / *_pem / *_json anchor fields => embedded roots
            "schema_version": "1", "document_b64": env.b64(env.canon(doc)),
            "nonce_hex": "", "repo": env.REPO,
        },
        "expected": {"accepted": False, "code": code},
    }


def main():
    out = "vectors/v3/embedded-roots"
    os.makedirs(out, exist_ok=True)

    fixtures = []
    # SEV quote against the embedded AMD Genoa root (synthetic chain != real ARK).
    art = gs.ss.build_sev()
    fixtures.append(_fx("embedded-sev-rejects-synthetic", "v3-authenticate-quote",
                        gs.sev_document(art), "QUOTE_REJECTED"))
    # TDX quote against the embedded Intel SGX root.
    _, quote, responses = gt.build_tdx()
    fixtures.append(_fx("embedded-tdx-rejects-synthetic", "v3-authenticate-quote",
                        gt.tdx_document(quote, responses), "QUOTE_REJECTED"))
    # Code provenance against the embedded Sigstore trusted root.
    b, _ = gp._happy_bundle()
    fixtures.append(_fx("embedded-sigstore-rejects-synthetic", "v3-authenticate-provenance",
                        gp.doc_with(b), "PROVENANCE_REJECTED"))

    for f in fixtures:
        with open(os.path.join(out, f["id"] + ".json"), "w") as fh:
            fh.write(json.dumps(f, indent=2) + "\n")
    print(f"wrote {len(fixtures)} embedded-root fixtures to {out}/")


if __name__ == "__main__":
    main()
