#!/usr/bin/env python3
"""Generate v3 QUOTE-TDX conformance fixtures.

Reuses the repo's existing synthetic Intel stack (fixturegen/lib/tdx_synth.py:
Intel SGX root -> platform CA -> PCK leaf with SGX extensions, a TDX v4 quote,
and TCB Info / QE Identity / CRL collateral) and wraps it into a v3 document:
the quote as cpu_evidence, the Intel PCS responses as intel-pcs endorsement
collateral, and the synthetic Intel root as the pinned anchor. The happy
document authenticates through `v3-authenticate-quote`; mutations reject there.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # fixturegen/ (for lib)
from lib import tdx_synth as tsx  # noqa: E402
from gen_envelope import base_doc, canon, b64, REPO  # noqa: E402

TDX_FMT = "https://tinfoil.sh/format/tdx-quote/v1"
PCS_FMT = "https://tinfoil.sh/collateral/intel-pcs/v1"
FMSPC = tsx.SYNTH_FMSPC.hex()

TCB_URL = f"https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc={FMSPC}"
QE_URL = "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"
PCKCRL_URL = "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der"
ROOTCRL_URL = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"


def _resp(url, header_name, header_val, body):
    r = {"url": url, "body_base64": b64(body if isinstance(body, bytes) else body.encode())}
    r["headers"] = {header_name: [header_val]} if header_name else {}
    return r


PCE_SVN = 11
# TCB levels consistent with the synth chain's PCK extensions and the default
# TD body's tee_tcb_svn (00 03 05 00): tdxtcbcomponents svn <= tee_tcb_svn
# byte-wise, mirroring the working attestation_tdx_phase3 recipe.
def _tcb_levels(status="UpToDate"):
    return [{
        "tcb": {
            "sgxtcbcomponents": [{"svn": b} for b in [5, 5, 2, 2, 3, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0]],
            "pcesvn": PCE_SVN,
            "tdxtcbcomponents": [{"svn": b} for b in [3, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]],
        },
        "tcbDate": "2023-02-15T00:00:00Z", "tcbStatus": status,
    }]


def build_tdx(body=None, tcb_levels=None, tcb_eval=18):
    chain = tsx.build_synth_chain(pce_svn=PCE_SVN)
    body = body or tsx.TdBodyFields(tee_tcb_svn=b"\x00\x03\x05\x00" + b"\x00" * 12)
    quote, _ = tsx.build_tdx_quote_v4(chain, body=body)
    tcb = tsx.build_tcb_info_response(chain, tcb_levels=tcb_levels or _tcb_levels(),
                                      tcb_evaluation_data_number=tcb_eval)
    qe = tsx.build_qe_identity_response(chain, mrsigner_hex="DC" * 32, isv_prod_id=2,
                                        isv_svn=8, tcb_evaluation_data_number=tcb_eval)
    tcb_chain = tsx.url_encoded_pem_chain(chain.tcb_signer, chain.root_ca)
    pck_chain = tsx.url_encoded_pem_chain(chain.platform_ca, chain.root_ca)
    responses = [
        _resp(TCB_URL, "Tcb-Info-Issuer-Chain", tcb_chain, tcb),
        _resp(QE_URL, "Sgx-Enclave-Identity-Issuer-Chain", tcb_chain, qe),
        _resp(PCKCRL_URL, "Sgx-Pck-Crl-Issuer-Chain", pck_chain, tsx.build_empty_crl(chain.platform_ca)),
        _resp(ROOTCRL_URL, None, None, tsx.build_empty_crl(chain.root_ca)),
    ]
    return chain, quote, responses


def tdx_document(quote, responses):
    d = base_doc()
    d["cpu_evidence"]["format"] = TDX_FMT
    d["cpu_evidence"]["report_base64"] = b64(quote)
    d["collateral"] = [{"id": "pcs", "role": "endorsement", "format": PCS_FMT,
                        "subjects": ["cpu"], "data": {"responses": responses}}]
    return d


def fx(fid, doc, root_pem, accepted):
    return {"id": fid, "stage": "v3-authenticate-quote",
            "input": {"schema_version": "1", "document_b64": b64(canon(doc)), "nonce_hex": "",
                      "repo": REPO, "intel_sgx_root_pem": root_pem},
            "expected": {"accepted": accepted}}


def happy():
    chain, quote, responses = build_tdx()
    return fx("tdx-happy", tdx_document(quote, responses), chain.root_ca.pem, True)


def main():
    out = "vectors/v3/quote-tdx"
    os.makedirs(out, exist_ok=True)
    for f in [happy()]:
        with open(os.path.join(out, f["id"] + ".json"), "w") as fh:
            fh.write(json.dumps(f, indent=2) + "\n")
    print(f"wrote fixtures to {out}/")


if __name__ == "__main__":
    main()
