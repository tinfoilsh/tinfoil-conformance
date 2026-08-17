#!/usr/bin/env python3
"""Generate the v3 TDX golden document + validate-stage fixtures.

The TDX analogue of gen_golden.py: one fully-consistent v3 document that
verify-attestation-v3 accepts, pairing all generators under both anchors:

  envelope ladder   == TDX quote report_data
  quote MRTD/RTMR0  == the endorsed platform measurement (shape-filtered)
  quote RTMR1/RTMR2 == the code provenance tdx_measurement
  quote mr_seam / td_attributes / xfam / qe_vendor_id == the endorsed tdx policy
  quote CHIP/PPID   -> machines map -> the tdx policy

Single-field mutations reject at the specific check, unlocking TDX validate
rules (T4/T7/T10/T12/T14/T17/T18/T20/T23), shape resolution (ST1/ST2), and
policy comparison (PL7/PL8).
"""

import json
import os

import gen_envelope as env
import gen_provenance as prov
import gen_policy as pol
import gen_tdx as gt
import sigstore_synth as sig

# TdBodyFields defaults the quote is built with (see lib/tdx_synth).
MRTD = "11" * 48
RTMR0 = "22" * 48
RTMR1 = "33" * 48
RTMR2 = "44" * 48
MRSEAM = "aa" * 48
TD_ATTRIBUTES = "0000004000000000"
XFAM = "e71a060000000000"
QE_VENDOR_ID = "939a7233f79c4ca9940a0db3957f0607"
PPID = "55" * 16
SHAPE = {"cpus": 8, "memory_mb": 32768, "gpus": 1, "disks": 2}


def tdx_artifact():
    return {
        "format": pol.ARTIFACT_FMT,
        "measurements": {"m1": {"mrtd": MRTD, "rtmr0": RTMR0, "shape": dict(SHAPE)}},
        "machines": {PPID: "tdx-policy"},
        "policies": {"tdx-policy": {"platform": "tdx", "tdx": {
            "qe_vendor_id": QE_VENDOR_ID, "minimum_tee_tcb_svn": "00" * 16,
            "mr_seam": MRSEAM, "td_attributes": TD_ATTRIBUTES, "xfam": XFAM,
            "minimum_tcb_evaluation_data_number": 0, "platform_measurements": ["m1"],
        }}},
    }


def golden_tdx(artifact=None, code_rtmr1=RTMR1, code_rtmr2=RTMR2, report_data=None,
               body_kwargs=None):
    artifact = artifact or tdx_artifact()
    doc = env.base_doc()
    ladder = bytes.fromhex(doc["challenge"]["report_data"])

    bk = {"tee_tcb_svn": b"\x00\x03\x05\x00" + b"\x00" * 12,
          "report_data": report_data if report_data is not None else ladder}
    bk.update(body_kwargs or {})
    body = gt.tsx.TdBodyFields(**bk)
    chain, quote, responses = gt.build_tdx(body=body)

    code_pred = {"snp_measurement": "ab" * 48,
                 "tdx_measurement": {"rtmr1": code_rtmr1, "rtmr2": code_rtmr2},
                 "vm_shape": dict(SHAPE)}
    code_bundle, sig_troot = prov.code_bundle(stmt=prov.statement(predicate=code_pred))
    plat_bundle, _ = pol._bundle(artifact)

    doc["cpu_evidence"]["format"] = gt.TDX_FMT
    doc["cpu_evidence"]["report_base64"] = env.b64(quote)
    doc["collateral"] = [
        prov.code_entry(code_bundle),
        prov.code_freshness_entry(),
        pol.platform_entry(plat_bundle),
        pol.platform_freshness_entry(),
        {"id": "pcs", "role": "endorsement", "format": gt.PCS_FMT,
         "subjects": ["cpu"], "data": {"responses": responses}},
    ]
    inp = {
        "schema_version": "1", "document_b64": env.b64(env.canon(doc)),
        "nonce_hex": env.NONCE.hex(), "repo": prov.REPO,
        "intel_sgx_root_pem": chain.root_ca.pem,
        "sigstore_trusted_root_json_b64": env.b64(json.dumps(sig_troot).encode()),
        # Pin the appraisal clock to the freshness witness time.
        "verification_time_unix": sig.INTEGRATED_TIME,
    }
    return inp


def fixture(fid, inp, accepted):
    return {"id": fid, "stage": "verify-attestation-v3", "input": inp, "expected": {"accepted": accepted} if accepted else {"accepted": False, "code": "POLICY_REJECTED"}}


def _mut_tdx(**changes):
    a = tdx_artifact()
    a["policies"]["tdx-policy"]["tdx"].update(changes)
    return a


def BUILDERS():
    yield ("tdx-golden-happy", golden_tdx(), True)
    # T18: quote RTMR1/RTMR2 != code provenance tdx_measurement.
    yield ("t18-rtmr1", golden_tdx(code_rtmr1="ff" * 48), False)
    yield ("t18-rtmr2", golden_tdx(code_rtmr2="ff" * 48), False)
    # T14/ST1: quote MRTD does not match any shape-filtered platform measurement.
    a = tdx_artifact(); a["measurements"]["m1"]["mrtd"] = "ee" * 48
    yield ("t14-mrtd", golden_tdx(artifact=a), False)
    # T17: quote RTMR0 does not match the platform measurement.
    a = tdx_artifact(); a["measurements"]["m1"]["rtmr0"] = "ee" * 48
    yield ("t17-rtmr0", golden_tdx(artifact=a), False)
    # ST1: no measurement whose shape satisfies the code's required shape.
    a = tdx_artifact(); a["measurements"]["m1"]["shape"]["cpus"] = 99
    yield ("st1-shape-filter", golden_tdx(artifact=a), False)
    # T7 / PL8: MRSEAM != endorsed policy.
    yield ("t7-mr-seam", golden_tdx(artifact=_mut_tdx(mr_seam="bb" * 48)), False)
    # T4: QE_VENDOR_ID != endorsed policy.
    yield ("t4-qe-vendor-id", golden_tdx(artifact=_mut_tdx(qe_vendor_id="00" * 16)), False)
    # T10/T11: TDATTRIBUTES != endorsed policy.
    yield ("t10-td-attributes", golden_tdx(artifact=_mut_tdx(td_attributes="0000000000000000")), False)
    # T12/T13: XFAM != endorsed policy.
    yield ("t12-xfam", golden_tdx(artifact=_mut_tdx(xfam="0000000000000000")), False)
    # T20: REPORT_DATA != the recomputed envelope ladder.
    yield ("t20-report-data", golden_tdx(report_data=b"\x77" * 64), False)
    # T23: collateral tcbEvaluationDataNumber below the policy floor.
    yield ("t23-tcb-eval", golden_tdx(artifact=_mut_tdx(minimum_tcb_evaluation_data_number=999)), False)
    # T6: quote TEE_TCB_SVN below the endorsed per-byte minimum_tee_tcb_svn floor.
    yield ("t6-tee-tcb-svn", golden_tdx(artifact=_mut_tdx(
        minimum_tee_tcb_svn="00030600" + "00" * 12)), False)
    # T19: RTMR3 must be zero (code provenance never extends it).
    yield ("t19-rtmr3", golden_tdx(body_kwargs={"rtmr3": b"\x99" * 48}), False)
    # T15: MRCONFIGID pinned all-zero.
    yield ("t15-mr-config-id", golden_tdx(body_kwargs={"mr_config_id": b"\x99" * 48}), False)
    # T16: MROWNER / MROWNERCONFIG pinned all-zero.
    yield ("t16-mr-owner", golden_tdx(body_kwargs={"mr_owner": b"\x99" * 48}), False)
    yield ("t16-mr-owner-config", golden_tdx(body_kwargs={"mr_owner_config": b"\x99" * 48}), False)
    # T11: TDATTRIBUTES exact-equality per-bit — DEBUG (bit 0) must be 0.
    yield ("t11-td-debug", golden_tdx(body_kwargs={"td_attributes": b"\x01\x00\x00\x40\x00\x00\x00\x00"}), False)

    # --- Positive tests that MUST accept. ---
    # T5/U3: QE user data (QE_ID) is unchecked; happy accepts regardless (the
    # verifier never reads it). Covered by the happy document.
    # Positive: TCB eval number well above the policy floor still accepts.
    yield ("tdx-pos-tcb-eval-above", golden_tdx(artifact=_mut_tdx(
        minimum_tcb_evaluation_data_number=5)), True)
    # ST2: several measurements survive the shape filter; the matching one resolves.
    a = tdx_artifact()
    a["measurements"]["m2"] = {"mrtd": "ee" * 48, "rtmr0": "dd" * 48, "shape": dict(SHAPE)}
    a["policies"]["tdx-policy"]["tdx"]["platform_measurements"] = ["m2", "m1"]
    yield ("st2-multi-measurement", golden_tdx(artifact=a), True)


def main():
    out = "vectors/v3/golden-tdx"
    os.makedirs(out, exist_ok=True)
    n = 0
    for fid, inp, accepted in BUILDERS():
        with open(os.path.join(out, fid + ".json"), "w") as fh:
            fh.write(json.dumps(fixture(fid, inp, accepted), indent=2) + "\n")
        n += 1
    print(f"wrote {n} TDX golden / verify-attestation-v3 fixtures to {out}/")


if __name__ == "__main__":
    main()
