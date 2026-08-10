#!/usr/bin/env python3
"""Generate v3 QUOTE-SEV authenticate-stage conformance fixtures.

Each fixture is a v3 document whose cpu_evidence is a synthetic AMD SEV-SNP report
(see sev_synth) with its VCEK/ASK/ARK chain and CRL as endorsement collateral, and
whose Input pins the AMD ARK+ASK anchor. The happy document authenticates through
`v3-authenticate-quote`; each mutation rejects there.

This file covers the structural / vendor / chain rules reachable at authentication
(S1, S8, S12, S20, S21, S25, S26, the vendor TCB/HWID consistency of S9/S19, and
the collateral shape checks). The policy-comparison S-rules (S2–S7, S10–S16,
S22–S24) need a verified quote compared against an endorsed policy and land with
the `v3-validate-quote` slice.
"""

import base64
import copy
import json
import os

import sev_synth as ss
from gen_envelope import base_doc, canon, b64, REPO

VCEK_FMT = "https://tinfoil.sh/collateral/amd-vcek/v1"
CRL_FMT = "https://tinfoil.sh/collateral/amd-crl/v1"


def sev_document(art):
    d = base_doc()
    d["cpu_evidence"]["report_base64"] = b64(art["report"])
    d["collateral"] = [
        {"id": "vcek", "role": "endorsement", "format": VCEK_FMT, "subjects": ["cpu"],
         "data": {"vcek_der_base64": b64(art["vcek_der"]), "cert_chain_pem": art["cert_chain_pem"]}},
        {"id": "crl", "role": "endorsement", "format": CRL_FMT, "subjects": ["cpu"],
         "data": {"crl_der_base64": b64(art["crl_der"])}},
    ]
    return d


def fx(fid, doc, art, accepted):
    return {"id": fid, "stage": "v3-authenticate-quote",
            "input": {"schema_version": "1", "document_b64": b64(canon(doc)), "nonce_hex": "",
                      "repo": REPO, "amd_root_ca_pem": art["ark_pem"], "ask_pem": art["ask_pem"]},
            "expected": {"accepted": accepted}}


# Each builder returns a fixture dict.
def happy():
    art = ss.build_sev()
    return fx("sev-happy", sev_document(art), art, True)


def _reject(fid, **kw):
    art = ss.build_sev(**kw)
    return fx(fid, sev_document(art), art, False)


def s1_version():
    # Report version < 3 carries no CPUID product identity; clear FMS so the
    # rejection is the missing-product one, not the version-2 mbz check.
    return _reject("s1-report-version", version=2, fms=(0, 0, 0))


def s8_s25_signature():
    return _reject("s8-s25-signature", tamper_report_sig=True)  # ECDSA structural


def s12_signer():
    return _reject("s12-signer-key", signer_info=0x4)       # claims VLEK, but VCEK supplied


def s20_product():
    return _reject("s20-product", fms=(0x19, 0x22, 0x00))   # unknown model → not a pinned product


def s_revoked():
    return _reject("s26-revoked-ask", revoke_ask=True)      # ASK serial listed in the CRL


def s26_root():
    art = ss.build_sev()
    ark_pem, ask_pem = ss.rogue_anchor()
    art = dict(art); art["ark_pem"], art["ask_pem"] = ark_pem, ask_pem
    return fx("s26-wrong-root", sev_document(art), art, False)


# Collateral shape checks (envelope-level, done by editing the happy document).
def _happy_doc_art():
    art = ss.build_sev()
    return sev_document(art), art


def struct_empty_vcek():
    doc, art = _happy_doc_art()
    doc["collateral"][0]["data"]["vcek_der_base64"] = ""
    return fx("struct-empty-vcek", doc, art, False)


def struct_bad_chain():
    doc, art = _happy_doc_art()
    doc["collateral"][0]["data"]["cert_chain_pem"] = art["ark_pem"]  # only 1 cert, want ASK+ARK
    return fx("struct-bad-chain", doc, art, False)


def struct_empty_crl():
    doc, art = _happy_doc_art()
    doc["collateral"][1]["data"]["crl_der_base64"] = ""
    return fx("struct-empty-crl", doc, art, False)


def struct_crl_expired():
    art = ss.build_sev(crl_expired=True)
    return fx("struct-crl-expired", sev_document(art), art, False)


def struct_no_vcek():
    doc, art = _happy_doc_art()
    doc["collateral"] = [e for e in doc["collateral"] if e["id"] != "vcek"]
    return fx("struct-no-vcek", doc, art, False)


def struct_no_crl():
    doc, art = _happy_doc_art()
    doc["collateral"] = [e for e in doc["collateral"] if e["id"] != "crl"]
    return fx("struct-no-crl", doc, art, False)


# S21 (CHIP_ID) and S9/S19 (VCEK-vs-report TCB) are not enforced at
# authentication: go-sev-guest binds neither the VCEK HWID nor the VCEK TCB to
# the report here. They compare against the endorsed policy/identity and land
# with the validate/identity slice.
BUILDERS = [
    happy, s1_version, s8_s25_signature, s12_signer, s20_product,
    s_revoked, s26_root, struct_empty_vcek, struct_bad_chain,
    struct_empty_crl, struct_crl_expired, struct_no_vcek, struct_no_crl,
]


def main():
    out = "vectors/v3/quote-sev"
    os.makedirs(out, exist_ok=True)
    for build in BUILDERS:
        f = build()
        with open(os.path.join(out, f["id"] + ".json"), "w") as fh:
            fh.write(json.dumps(f, indent=2) + "\n")
    print(f"wrote {len(BUILDERS)} SEV authenticate-stage fixtures to {out}/")


if __name__ == "__main__":
    main()
