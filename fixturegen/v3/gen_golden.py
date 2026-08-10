#!/usr/bin/env python3
"""Generate the v3 golden document + end-to-end (verify-attestation-v3) fixtures.

The golden document is one fully-consistent v3 attestation pairing all four
generators under both trust anchors:

  envelope report_data ladder == SEV report.report_data
  code launch measurement     == SEV report.measurement   (sigstore-code bundle)
  SEV report.chip_id          -> platform machines-map -> a sev-snp policy whose
                                 guest_policy / platform_info / host_data /
                                 family_id / image_id / vmpl match the report and
                                 whose TCB / guest_svn / mitigation floors it.

verify-attestation-v3 accepts it; single-field mutations of the quote or policy
reject at the specific policy check (SEV S2-S24, PL6-8, ST, identity lookup) and
mutations of explicitly-unchecked fields still accept (U1-U6). This file builds
the happy document; the mutation fixtures build on it once it is green.
"""

import json
import os

import gen_envelope as env
import sigstore_synth as sig
import sev_synth as sev
import gen_provenance as prov
import gen_policy as pol

MEASUREMENT = bytes([0x11] * 48)   # SEV launch measurement == code snp_measurement
CHIP_ID = bytes([0x22] * 64)       # SEV CHIP_ID; machines-map key

VCEK_FMT = "https://tinfoil.sh/collateral/amd-vcek/v1"
CRL_FMT = "https://tinfoil.sh/collateral/amd-crl/v1"


def golden_artifact():
    """A platform-endorsements artifact whose sev-snp policy exactly matches the
    golden SEV report (policy 0x30000 => SMT only; platform_info 0 => all false;
    zero host/image/family; vmpl 0; TCB floors at 0)."""
    tcb0 = {"bl_spl": 0, "tee_spl": 0, "snp_spl": 0, "ucode_spl": 0}
    sev_policy = {
        "minimum_build": 0, "minimum_api_version": "1.0", "minimum_abi_version": "0.0",
        "minimum_guest_svn": 0, "minimum_tcb": dict(tcb0), "minimum_launch_tcb": dict(tcb0),
        "guest_policy": {"debug": False, "smt": True, "migrate_ma": False, "single_socket": False},
        "platform_info": {"smt_enabled": False, "tsme_enabled": False, "ecc_enabled": False,
                          "rapl_disabled": False, "ciphertext_hiding_dram": False},
        "permit_provisional_firmware": False, "vmpl": 0,
        "host_data": "00" * 32, "image_id": "00" * 16, "family_id": "00" * 16,
        "minimum_launch_mitigation_vector": 0, "minimum_current_mitigation_vector": 0,
    }
    return {
        "format": pol.ARTIFACT_FMT,
        "measurements": {},
        "machines": {CHIP_ID.hex(): "sev-policy"},
        "policies": {"sev-policy": {"platform": "sev-snp", "sev_snp": sev_policy}},
    }


def golden(artifact=None, report_measurement=MEASUREMENT, code_measurement=None,
           chip_id=CHIP_ID, sev_kwargs=None):
    """Assemble (document, input) for verify-attestation-v3. The override points
    let mutation fixtures decouple what the report says from what the code
    provenance / endorsed policy expect."""
    artifact = artifact or golden_artifact()
    code_measurement = code_measurement or report_measurement
    sev_kwargs = dict(sev_kwargs or {})
    sev_kwargs.setdefault("host_data", b"\x00" * 32)

    doc = env.base_doc()
    ladder = bytes.fromhex(doc["challenge"]["report_data"])  # 64-byte REPORT_DATA ladder

    # code provenance: snp_measurement is the expected launch measurement.
    code_pred = {"snp_measurement": code_measurement.hex(),
                 "tdx_measurement": {"rtmr1": "bb" * 48, "rtmr2": "cc" * 48},
                 "vm_shape": {"cpus": 8, "memory_mb": 32768, "gpus": 1, "disks": 2}}
    code_bundle, sig_troot = sig.build_bundle(prov.IDENTITY, prov.statement(predicate=code_pred))

    # platform endorsements: same synthetic Sigstore root (fixed keys).
    plat_bundle, _ = sig.build_bundle(pol.IDENTITY, pol.statement(artifact))

    # SEV quote bound to the ladder + report measurement + chip id.
    art = sev.build_sev(report_data=ladder, measurement=report_measurement, chip_id=chip_id,
                        policy=0x30000, **sev_kwargs)

    doc["cpu_evidence"]["report_base64"] = env.b64(art["report"])
    doc["collateral"] = [
        prov.code_entry(code_bundle),
        pol.platform_entry(plat_bundle),
        {"id": "vcek", "role": "endorsement", "format": VCEK_FMT, "subjects": ["cpu"],
         "data": {"vcek_der_base64": env.b64(art["vcek_der"]), "cert_chain_pem": art["cert_chain_pem"]}},
        {"id": "crl", "role": "endorsement", "format": CRL_FMT, "subjects": ["cpu"],
         "data": {"crl_der_base64": env.b64(art["crl_der"])}},
    ]
    inp = {
        "schema_version": "1", "document_b64": env.b64(env.canon(doc)),
        "nonce_hex": env.NONCE.hex(), "repo": prov.REPO,
        "amd_root_ca_pem": art["ark_pem"], "ask_pem": art["ask_pem"],
        "sigstore_trusted_root_json_b64": env.b64(json.dumps(sig_troot).encode()),
    }
    return doc, inp


def fixture(fid, inp, accepted):
    return {"id": fid, "stage": "verify-attestation-v3", "input": inp, "expected": {"accepted": accepted}}


def _mutate_policy(**changes):
    a = golden_artifact()
    a["policies"]["sev-policy"]["sev_snp"].update(changes)
    return a


# Each builder returns (id, input, accepted). Single-field mutations of the
# golden document, verified end-to-end through verify-attestation-v3.
def BUILDERS():
    yield ("golden-happy", golden()[1], True)
    # S14: report launch measurement != code-provenance measurement.
    yield ("s14-measurement", golden(code_measurement=bytes([0x99] * 48))[1], False)
    # S15: report HOST_DATA != endorsed policy host_data.
    yield ("s15-host-data", golden(sev_kwargs={"host_data": bytes([0x01] * 32)})[1], False)
    # S3/S4: report GUEST_POLICY != endorsed guest_policy (endorsement requires debug).
    yield ("s3-guest-policy", golden(artifact=_mutate_policy(
        guest_policy={"debug": True, "smt": True, "migrate_ma": False, "single_socket": False}))[1], False)
    # S10/S11: report PLATFORM_INFO != endorsed platform_info.
    yield ("s10-platform-info", golden(artifact=_mutate_policy(
        platform_info={"smt_enabled": True, "tsme_enabled": False, "ecc_enabled": False,
                       "rapl_disabled": False, "ciphertext_hiding_dram": False}))[1], False)
    # S7: report VMPL != endorsed vmpl.
    yield ("s7-vmpl", golden(artifact=_mutate_policy(vmpl=1))[1], False)
    # S19/S22: report REPORTED_TCB below the endorsed minimum_tcb floor.
    yield ("s19-tcb-floor", golden(artifact=_mutate_policy(
        minimum_tcb={"bl_spl": 0, "tee_spl": 0, "snp_spl": 99, "ucode_spl": 0}))[1], False)
    # I5: report CHIP_ID is not in the machines map (machine not endorsed).
    yield ("i5-not-endorsed", golden(chip_id=bytes([0x33] * 64))[1], False)


def main():
    out = "vectors/v3/golden"
    os.makedirs(out, exist_ok=True)
    n = 0
    for fid, inp, accepted in BUILDERS():
        with open(os.path.join(out, fid + ".json"), "w") as fh:
            fh.write(json.dumps(fixture(fid, inp, accepted), indent=2) + "\n")
        n += 1
    print(f"wrote {n} golden / verify-attestation-v3 fixtures to {out}/")


if __name__ == "__main__":
    main()
