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
from datetime import datetime, timezone
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


def build_tdx(body=None, tcb_levels=None, tcb_eval=18, qe_mrsigner=None, crl_expired=False):
    chain = tsx.build_synth_chain(pce_svn=PCE_SVN)
    body = body or tsx.TdBodyFields(tee_tcb_svn=b"\x00\x03\x05\x00" + b"\x00" * 12)
    qkw = {"qe_mrsigner": qe_mrsigner} if qe_mrsigner is not None else {}
    quote, _ = tsx.build_tdx_quote_v4(chain, body=body, **qkw)
    tcb = tsx.build_tcb_info_response(chain, tcb_levels=tcb_levels or _tcb_levels(),
                                      tcb_evaluation_data_number=tcb_eval)
    qe = tsx.build_qe_identity_response(chain, mrsigner_hex="DC" * 32, isv_prod_id=2,
                                        isv_svn=8, tcb_evaluation_data_number=tcb_eval)
    tcb_chain = tsx.url_encoded_pem_chain(chain.tcb_signer, chain.root_ca)
    pck_chain = tsx.url_encoded_pem_chain(chain.platform_ca, chain.root_ca)
    crl_kw = {}
    if crl_expired:
        crl_kw = {"not_before": datetime(2023, 1, 1, tzinfo=timezone.utc),
                  "not_after": datetime(2023, 2, 1, tzinfo=timezone.utc)}
    responses = [
        _resp(TCB_URL, "Tcb-Info-Issuer-Chain", tcb_chain, tcb),
        _resp(QE_URL, "Sgx-Enclave-Identity-Issuer-Chain", tcb_chain, qe),
        _resp(PCKCRL_URL, "Sgx-Pck-Crl-Issuer-Chain", pck_chain, tsx.build_empty_crl(chain.platform_ca, **crl_kw)),
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


def _tamper(quote, idx):  # flip one byte
    b = bytearray(quote)
    b[idx] ^= 0xFF
    return bytes(b)


# Authenticate-stage TDX rules (structural / vendor / chain / collateral),
# reachable through v3-authenticate-quote. Each builder returns a fixture.
def happy():
    chain, quote, responses = build_tdx()
    return fx("tdx-happy", tdx_document(quote, responses), chain.root_ca.pem, True)


def t1_version():  # T1/T2: header version must be 4
    chain, quote, responses = build_tdx()
    return fx("t1-quote-version", tdx_document(_tamper(quote, 0), responses), chain.root_ca.pem, False)


def t3_reserved():  # T3: reserved header bytes (QE/PCE SVN, offset 8) must be zero
    chain, quote, responses = build_tdx()
    return fx("t3-reserved-bytes", tdx_document(_tamper(quote, 8), responses), chain.root_ca.pem, False)


def t3_extra_bytes():  # T3: trailing non-zero bytes after the signed data
    chain, quote, responses = build_tdx()
    return fx("t3-extra-bytes", tdx_document(quote + b"\x01", responses), chain.root_ca.pem, False)


def t_signature():  # T2/T21: attestation-key signature over the TD body fails
    chain, quote, responses = build_tdx()
    return fx("t21-signature", tdx_document(_tamper(quote, 100), responses), chain.root_ca.pem, False)


def t21_qe_mismatch():  # T21: QE report MRSIGNER != endorsed QE identity mrsigner
    chain, quote, responses = build_tdx(qe_mrsigner=b"\xEE" * 32)
    return fx("t21-qe-mrsigner", tdx_document(quote, responses), chain.root_ca.pem, False)


def t24_missing_pcs():  # T24: no intel-pcs endorsement collateral
    chain, quote, responses = build_tdx()
    doc = tdx_document(quote, responses)
    doc["collateral"] = []
    return fx("t24-missing-pcs", doc, chain.root_ca.pem, False)


def t24_crl_expired():  # T24: captured PCK CRL outside its validity window
    chain, quote, responses = build_tdx(crl_expired=True)
    return fx("t24-crl-expired", tdx_document(quote, responses), chain.root_ca.pem, False)


def t25_wrong_root():  # T25: quote does not chain to the pinned Intel root
    chain, quote, responses = build_tdx()
    rogue = tsx.build_synth_chain(pce_svn=PCE_SVN)
    return fx("t25-wrong-root", tdx_document(quote, responses), rogue.root_ca.pem, False)


def _body(**kw):
    return tsx.TdBodyFields(tee_tcb_svn=b"\x00\x03\x05\x00" + b"\x00" * 12, **kw)


def t8_mrsignerseam():  # T8: MRSIGNERSEAM != TCB Info TdxModule.mrsigner
    chain, quote, responses = build_tdx(body=_body(mr_signer_seam=b"\xEE" * 48))
    return fx("t8-mr-signer-seam", tdx_document(quote, responses), chain.root_ca.pem, False)


def t9_seamattributes():  # T9: SEAMATTRIBUTES masked comparison against TCB Info
    chain, quote, responses = build_tdx(body=_body(seam_attributes=b"\xFF" * 8))
    return fx("t9-seam-attributes", tdx_document(quote, responses), chain.root_ca.pem, False)


def t22_pcesvn():  # T22: PCK leaf PCESVN below the matched TCB level's pcesvn
    lv = _tcb_levels()
    lv[0]["tcb"]["pcesvn"] = 99                      # PCK carries pcesvn=11 < 99
    chain, quote, responses = build_tdx(tcb_levels=lv)
    return fx("t22-pcesvn", tdx_document(quote, responses), chain.root_ca.pem, False)


BUILDERS = [happy, t1_version, t3_reserved, t3_extra_bytes, t_signature,
            t21_qe_mismatch, t24_missing_pcs, t24_crl_expired, t25_wrong_root,
            t8_mrsignerseam, t9_seamattributes, t22_pcesvn]


def main():
    out = "vectors/v3/quote-tdx"
    os.makedirs(out, exist_ok=True)
    for build in BUILDERS:
        f = build()
        with open(os.path.join(out, f["id"] + ".json"), "w") as fh:
            fh.write(json.dumps(f, indent=2) + "\n")
    print(f"wrote {len(BUILDERS)} TDX authenticate-stage fixtures to {out}/")


if __name__ == "__main__":
    main()
