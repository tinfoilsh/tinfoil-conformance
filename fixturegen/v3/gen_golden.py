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
           chip_id=CHIP_ID, sev_kwargs=None, cm_items=None):
    """Assemble (document, input) for verify-attestation-v3. The override points
    let mutation fixtures decouple what the report says from what the code
    provenance / endorsed policy expect."""
    artifact = artifact or golden_artifact()
    code_measurement = code_measurement or report_measurement
    sev_kwargs = dict(sev_kwargs or {})
    sev_kwargs.setdefault("host_data", b"\x00" * 32)
    sev_kwargs.setdefault("policy", 0x30000)

    doc = env.base_doc(cm_items=cm_items)
    ladder = bytes.fromhex(doc["challenge"]["report_data"])  # 64-byte REPORT_DATA ladder

    # code provenance: snp_measurement is the expected launch measurement.
    code_pred = {"snp_measurement": code_measurement.hex(),
                 "tdx_measurement": {"rtmr1": "bb" * 48, "rtmr2": "cc" * 48},
                 "vm_shape": {"cpus": 8, "memory_mb": 32768, "gpus": 1, "disks": 2}}
    code_bundle, sig_troot = prov.code_bundle(stmt=prov.statement(predicate=code_pred))

    # platform endorsements: same synthetic Sigstore root (fixed keys).
    plat_bundle, _ = pol._bundle(artifact)

    # SEV quote bound to the ladder + report measurement + chip id.
    sev_kwargs.setdefault("report_data", ladder)
    art = sev.build_sev(measurement=report_measurement, chip_id=chip_id, **sev_kwargs)

    doc["cpu_evidence"]["report_base64"] = env.b64(art["report"])
    doc["collateral"] = [
        prov.code_entry(code_bundle),
        prov.code_freshness_entry(),
        pol.platform_entry(plat_bundle),
        pol.platform_freshness_entry(),
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
        # Pin the appraisal clock to the freshness witness time so the frozen
        # document replays inside the freshness window.
        "verification_time_unix": sig.INTEGRATED_TIME,
    }
    return doc, inp


def fixture(fid, inp, accepted, code="POLICY_REJECTED"):
    if accepted:
        # Every accepting golden resolves to the same verified facts (no accept
        # varies the measurement); pin them so a port must reproduce them.
        expected = {
            "accepted": True,
            "code_digest": prov.DIGEST,
            "code_measurement": {"type": env.MEAS_SNP_TDX_MULTI,
                                 "registers": [MEASUREMENT.hex(), "bb" * 48, "cc" * 48]},
            "enclave_measurement": {"type": env.MEAS_SEV_GUEST_V2, "registers": [MEASUREMENT.hex()]},
            "tls_public_key_fp": env.TLS_FP, "hpke_public_key": env.HPKE_KEY,
        }
    else:
        expected = {"accepted": False, "code": code}
    return {"id": fid, "stage": "verify-attestation-v3", "input": inp, "expected": expected}


def _mutate_policy(**changes):
    a = golden_artifact()
    a["policies"]["sev-policy"]["sev_snp"].update(changes)
    return a


def _gp(**over):  # endorsed guest_policy with one bit flipped from the happy report's
    gp = {"debug": False, "smt": True, "migrate_ma": False, "single_socket": False}
    gp.update(over)
    return _mutate_policy(guest_policy=gp)


def _pi(**over):  # endorsed platform_info with one bit flipped from the happy report's (all-false)
    pi = {"smt_enabled": False, "tsme_enabled": False, "ecc_enabled": False,
          "rapl_disabled": False, "ciphertext_hiding_dram": False}
    pi.update(over)
    return _mutate_policy(platform_info=pi)


# Benign document variations that MUST still accept, so an over-strict port
# (fixed collateral order, rejects unknown entries) is caught.
def _variant(mutate):
    doc, inp = golden()
    mutate(doc)
    inp = dict(inp)
    inp["document_b64"] = env.b64(env.canon(doc))
    return inp


def _reorder_collateral(d):
    d["collateral"] = list(reversed(d["collateral"]))


def _add_unknown_collateral(d):
    d["collateral"].append({"id": "future-thing", "role": "endorsement",
                            "format": "https://tinfoil.sh/collateral/unknown/v9",
                            "subjects": ["cpu"], "data": {"x": "y"}})


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
    # S19/S9/S22: report REPORTED_TCB below the endorsed minimum_tcb floor
    # (current/committed TCB share this minimum, so S9/S22 ride this check).
    yield ("s19-tcb-floor", golden(artifact=_mutate_policy(
        minimum_tcb={"bl_spl": 0, "tee_spl": 0, "snp_spl": 99, "ucode_spl": 0}))[1], False)
    # S23: report LAUNCH_TCB below the endorsed minimum_launch_tcb floor.
    yield ("s23-launch-tcb", golden(artifact=_mutate_policy(
        minimum_launch_tcb={"bl_spl": 0, "tee_spl": 0, "snp_spl": 99, "ucode_spl": 0}))[1], False)
    # S9/S19/S22 vendor TCB-consistency checks (go-sev-guest validateTcb),
    # isolated so a regression in any one is caught (audit #11 finding).
    _lo = dict(sev.TCB); _lo["snp"] = 19
    # S9: CURRENT_TCB below the VCEK-certificate TCB (== REPORTED_TCB). Lower
    # committed too so it stays == current and only the current<cert check trips.
    yield ("s9-current-tcb", golden(sev_kwargs={"current_tcb_parts": _lo, "committed_tcb_parts": _lo})[1], False)
    # S19 (vendor): REPORTED_TCB != the VCEK-certificate TCB.
    yield ("s19-vcek-cert-tcb", golden(sev_kwargs={"vcek_tcb_parts": _lo})[1], False)
    # S22: COMMITTED_TCB != CURRENT_TCB (no provisional firmware permitted).
    yield ("s22-committed-tcb", golden(sev_kwargs={"committed_tcb_parts": _lo})[1], False)
    # S4: GUEST_POLICY exact-equality is per-bit (spec: all bits). One fixture
    # per bit so a port that compares only some bits is caught (debug = s3).
    yield ("s4-smt", golden(artifact=_gp(smt=False))[1], False)
    yield ("s4-migrate-ma", golden(artifact=_gp(migrate_ma=True))[1], False)
    yield ("s4-single-socket", golden(artifact=_gp(single_socket=True))[1], False)
    # S11: PLATFORM_INFO exact-equality per-bit (smt_enabled = s10).
    yield ("s11-tsme", golden(artifact=_pi(tsme_enabled=True))[1], False)
    yield ("s11-ecc", golden(artifact=_pi(ecc_enabled=True))[1], False)
    yield ("s11-rapl", golden(artifact=_pi(rapl_disabled=True))[1], False)
    yield ("s11-ciphertext", golden(artifact=_pi(ciphertext_hiding_dram=True))[1], False)
    # S2: report GUEST_SVN below the endorsed minimum_guest_svn floor.
    yield ("s2-guest-svn", golden(artifact=_mutate_policy(minimum_guest_svn=5))[1], False)
    # S5: report FAMILY_ID != endorsed family_id.
    yield ("s5-family-id", golden(sev_kwargs={"family_id": bytes([0x01] * 16)})[1], False)
    # S6: report IMAGE_ID != endorsed image_id.
    yield ("s6-image-id", golden(sev_kwargs={"image_id": bytes([0x01] * 16)})[1], False)
    # S13: report REPORT_DATA != the recomputed envelope ladder.
    yield ("s13-report-data", golden(sev_kwargs={"report_data": bytes([0xFF] * 64)})[1], False)
    # S16: report carries a non-zero ID_KEY_DIGEST (ID-block launches unsupported).
    yield ("s16-id-key-digest", golden(sev_kwargs={"id_key_digest": bytes([0x01] * 48)})[1], False)
    # S24: report LAUNCH_MIT_VECTOR missing a bit the policy floor requires.
    yield ("s24-mitigation", golden(artifact=_mutate_policy(
        minimum_launch_mitigation_vector=1))[1], False)
    # I5: report CHIP_ID is not in the machines map (machine not endorsed).
    yield ("i5-not-endorsed", golden(chip_id=bytes([0x33] * 64))[1], False)

    # --- Positive tests: valid variations and explicitly-unchecked fields that
    # MUST still accept (catch a port that is wrongly too strict). ---
    # U1: REPORT_ID is a random per-guest id, not checked.
    yield ("u1-report-id", golden(sev_kwargs={"report_id": bytes([0x77] * 32)})[1], True)
    # U2: REPORT_ID_MA is unchecked when migrate_ma is disallowed.
    yield ("u2-report-id-ma", golden(sev_kwargs={"report_id_ma": bytes([0x77] * 32)})[1], True)
    # Positive variation: debug launches accept when the endorsed policy permits.
    yield ("pos-debug", golden(
        sev_kwargs={"policy": 0x30000 | (1 << 19)},
        artifact=_mutate_policy(guest_policy={"debug": True, "smt": True,
                                              "migrate_ma": False, "single_socket": False}))[1], True)
    # Positive variation: REPORTED_TCB well above the policy floor accepts.
    hi = {"bl": 7, "tee": 0, "snp": 25, "spl4": 0, "spl5": 0, "spl6": 0, "spl7": 0, "ucode": 90}
    yield ("pos-tcb-above-floor", golden(
        sev_kwargs={"tcb_parts": hi},
        artifact=_mutate_policy(minimum_tcb={"bl_spl": 0, "tee_spl": 0, "snp_spl": 10, "ucode_spl": 0}))[1], True)
    # Boundary: exactly-at-floor accepts (catches an off-by-one > vs >= regression).
    yield ("pos-tcb-at-floor", golden(
        artifact=_mutate_policy(minimum_tcb={"bl_spl": 7, "tee_spl": 0, "snp_spl": 20, "ucode_spl": 72}))[1], True)
    yield ("pos-guest-svn-at-floor", golden(
        sev_kwargs={"guest_svn": 7}, artifact=_mutate_policy(minimum_guest_svn=7))[1], True)
    yield ("pos-collateral-reordered", _variant(_reorder_collateral), True)
    yield ("pos-extra-collateral", _variant(_add_unknown_collateral), True)
    # The full stage requires both endorsed channel keys: a document that
    # verifies but binds no usable key is useless to every real client.
    yield ("e-missing-tls-key", golden(cm_items=[
        {"id": "hpke", "format": env.KEY_X25519_HPKE, "data": env.HPKE_KEY}])[1],
        False, "ENVELOPE_REJECTED")
    # PLATFORM_INFO bit 6 (Turin iommu_write_safe): the member parses so
    # artifacts carrying Turin policies stay readable, but a selected policy
    # requiring it cannot be enforced and must fail closed at assembly.
    yield ("pos-iommu-false-present", golden(artifact=_pi(iommu_write_safe=False))[1], True)
    yield ("pl-iommu-required", golden(artifact=_pi(iommu_write_safe=True))[1], False)
    yield ("e-hpke-wrong-format", golden(cm_items=[
        {"id": "tls", "format": env.KEY_SPKI_FP, "data": env.TLS_FP},
        {"id": "hpke", "format": env.KEY_SPKI_FP, "data": env.HPKE_KEY}])[1],
        False, "ENVELOPE_REJECTED")


def main():
    out = "vectors/v3/golden"
    os.makedirs(out, exist_ok=True)
    n = 0
    for entry in BUILDERS():
        fid, inp, accepted = entry[0], entry[1], entry[2]
        code = entry[3] if len(entry) > 3 else "POLICY_REJECTED"
        with open(os.path.join(out, fid + ".json"), "w") as fh:
            fh.write(json.dumps(fixture(fid, inp, accepted, code), indent=2) + "\n")
        n += 1
    print(f"wrote {n} golden / verify-attestation-v3 fixtures to {out}/")


if __name__ == "__main__":
    main()
