#!/usr/bin/env python3
"""Generate v3 IDENTITY + POLICY conformance fixtures (SPEC_COVERAGE_V3 I/PL rules,
plus provenance P2/P15/P16).

Each fixture is a v3 document whose sigstore-platform reference-values collateral
carries a synthetic Sigstore bundle (platform-endorsements identity) signing an
in-toto statement whose predicate is a policy artifact. The `v3-assemble-policy`
stage authenticates the bundle and parses the artifact fail-closed, so mutations
exercise both the platform-bundle identity rules (P2/P15/P16) and the artifact
machines-map / policy validation (I / PL rules) reached through policy.Parse.

Shape-resolution rules (ST1–ST4) and the not-endorsed / platform-mismatch lookup
rules need a verified quote and land with the quote-validation slice.
"""

import copy
import hashlib
import json
import os

import sigstore_synth as ss
from gen_envelope import base_doc, canon, b64, REPO

PLAT_FMT_COLL = "https://tinfoil.sh/collateral/sigstore-platform/v1"
ARTIFACT_FMT = "https://tinfoil.sh/predicate/platform-endorsements/v1"
ROLE_RV = "reference-values"
PLAT_REPO = "tinfoilsh/platform-endorsements"
TAG = "v1.0.0"
IDENTITY = f"https://github.com/{PLAT_REPO}/.github/workflows/build.yml@refs/tags/{TAG}"
DIGEST = hashlib.sha256(b"platform-endorsements-v1").hexdigest()
COMMIT = hashlib.sha1(b"platform-commit-v1").hexdigest()  # 40-hex source commit
FRESH_FMT = "https://tinfoil.sh/collateral/sigstore-freshness/v1"
SUBJECT = "platform"

SEV_CHIP = "ab" * 64   # 128 hex chars = 64-byte CHIP_ID
TDX_PPID = "cd" * 16   # 32 hex chars = 16-byte PPID


def sev_policy():
    tcb = {"bl_spl": 0, "tee_spl": 0, "snp_spl": 0, "ucode_spl": 0}
    return {
        "minimum_build": 0, "minimum_api_version": "1.0", "minimum_abi_version": "1.0",
        "minimum_guest_svn": 0, "minimum_tcb": dict(tcb), "minimum_launch_tcb": dict(tcb),
        "guest_policy": {"debug": False, "smt": True, "migrate_ma": False, "single_socket": False},
        "platform_info": {"smt_enabled": True, "tsme_enabled": True, "ecc_enabled": True,
                          "rapl_disabled": False, "ciphertext_hiding_dram": False},
        "permit_provisional_firmware": False, "vmpl": 0,
        "host_data": "00" * 32, "image_id": "00" * 16, "family_id": "00" * 16,
        "minimum_launch_mitigation_vector": 0, "minimum_current_mitigation_vector": 0,
    }


def tdx_policy():
    return {
        "qe_vendor_id": "939a7233f79c4ca9940a0db3957f0607", "minimum_tee_tcb_svn": "00" * 16,
        "mr_seam": "00" * 48, "td_attributes": "00" * 8, "xfam": "00" * 8,
        "minimum_tcb_evaluation_data_number": 0, "platform_measurements": ["m1"],
    }


def base_artifact():
    return {
        "format": ARTIFACT_FMT,
        "measurements": {"m1": {"mrtd": "dd" * 48, "rtmr0": "ee" * 48,
                                "shape": {"cpus": 8, "memory_mb": 32768, "gpus": 1, "disks": 2}}},
        "machines": {SEV_CHIP: "sev-policy", TDX_PPID: "tdx-policy"},
        "policies": {
            "sev-policy": {"platform": "sev-snp", "sev_snp": sev_policy()},
            "tdx-policy": {"platform": "tdx", "tdx": tdx_policy()},
        },
    }


def statement(artifact):
    return json.dumps({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "platform", "digest": {"sha256": DIGEST}}],
        "predicateType": ARTIFACT_FMT,
        "predicate": artifact,
    }, separators=(",", ":")).encode()


def platform_entry(bundle, digest=DIGEST):
    return {"id": "sigstore-platform", "role": ROLE_RV, "format": PLAT_FMT_COLL,
            "data": {"repo": PLAT_REPO, "tag": TAG, "digest": digest, "sigstore_bundle": bundle}}


def doc_with(bundle, digest=DIGEST):
    d = base_doc()
    d["collateral"] = [platform_entry(bundle, digest)]
    return d


def _bundle(artifact, identity=IDENTITY, **kw):
    kw.setdefault("source_ref", "refs/tags/" + TAG)
    kw.setdefault("source_digest", COMMIT)
    return ss.build_bundle(identity, statement(artifact), **kw)


def platform_freshness_entry():
    """The platform artifact's freshness witness collateral entry."""
    bundle = ss.build_freshness_bundle(SUBJECT, DIGEST, PLAT_REPO, TAG, COMMIT,
                                       integrated_time=ss.INTEGRATED_TIME)
    return {"id": "platform-freshness", "role": ROLE_RV, "format": FRESH_FMT,
            "data": {"sigstore_bundle": bundle}}


def _artifact(mutate):
    a = base_artifact()
    mutate(a)
    return a


# --- fixtures: each returns (document, trusted_root, accepted) ---
def happy():
    b, t = _bundle(base_artifact())
    return doc_with(b), t, True


# Provenance platform-side rules (P2/P15/P16).
def p2():  # required sigstore-platform entry missing
    _, t = _bundle(base_artifact())
    d = base_doc(); d["collateral"] = []
    return d, t, False


def p15():  # platform-endorsements identity is the wrong workflow file
    ident = f"https://github.com/{PLAT_REPO}/.github/workflows/other.yml@refs/tags/{TAG}"
    b, t = _bundle(base_artifact(), identity=ident)
    return doc_with(b), t, False


def p15_tag():  # platform identity tag lacks the required v<digit> prefix
    ident = f"https://github.com/{PLAT_REPO}/.github/workflows/build.yml@refs/tags/release"
    b, t = _bundle(base_artifact(), identity=ident)
    return doc_with(b), t, False


def p16():  # platform bundle observer timestamp outside the certificate window
    b, t = _bundle(base_artifact(), integrated_time=ss.INTEGRATED_TIME + 3600 * 24 * 400)
    return doc_with(b), t, False


# Identity rules (I): machines map.
def i_unknown_policy():
    b, t = _bundle(_artifact(lambda a: a["machines"].update({SEV_CHIP: "nonexistent"})))
    return doc_with(b), t, False


def i_sev_len():
    def m(a):
        del a["machines"][SEV_CHIP]
        a["machines"]["abab"] = "sev-policy"  # too short for a CHIP_ID
    b, t = _bundle(_artifact(m))
    return doc_with(b), t, False


def i_tdx_len():
    def m(a):
        del a["machines"][TDX_PPID]
        a["machines"]["cd" * 32] = "tdx-policy"  # too long for a PPID
    b, t = _bundle(_artifact(m))
    return doc_with(b), t, False


def i_not_hex():
    def m(a):
        del a["machines"][SEV_CHIP]
        a["machines"]["zz" * 64] = "sev-policy"
    b, t = _bundle(_artifact(m))
    return doc_with(b), t, False


# Policy rules (PL): named policies, fail-closed.
def pl_block_mismatch():  # platform sev-snp but the sev_snp block is absent
    def m(a):
        a["policies"]["sev-policy"] = {"platform": "sev-snp", "tdx": tdx_policy()}
    b, t = _bundle(_artifact(m))
    return doc_with(b), t, False


def pl_unsupported_platform():
    def m(a):
        a["policies"]["sev-policy"] = {"platform": "nitro", "sev_snp": sev_policy()}
    b, t = _bundle(_artifact(m))
    return doc_with(b), t, False


def pl_missing_required():  # SEV policy missing a required member (vmpl)
    def m(a):
        del a["policies"]["sev-policy"]["sev_snp"]["vmpl"]
    b, t = _bundle(_artifact(m))
    return doc_with(b), t, False


def pl_bad_tcb():  # SEV minimum_tcb missing ucode_spl
    def m(a):
        del a["policies"]["sev-policy"]["sev_snp"]["minimum_tcb"]["ucode_spl"]
    b, t = _bundle(_artifact(m))
    return doc_with(b), t, False


def pl_dangling_measurement():  # TDX platform_measurements ref not in measurements
    def m(a):
        a["policies"]["tdx-policy"]["tdx"]["platform_measurements"] = ["missing"]
    b, t = _bundle(_artifact(m))
    return doc_with(b), t, False


def pl_measurement_no_shape():  # measurement lacks the required shape
    def m(a):
        del a["measurements"]["m1"]["shape"]
    b, t = _bundle(_artifact(m))
    return doc_with(b), t, False


def pl_unknown_member():  # fail-closed: unknown member anywhere in the artifact
    def m(a):
        a["policies"]["sev-policy"]["sev_snp"]["extra_field"] = 1
    b, t = _bundle(_artifact(m))
    return doc_with(b), t, False


def pl_bad_format():  # artifact format URI is wrong
    def m(a):
        a["format"] = ARTIFACT_FMT + "-wrong"
    b, t = _bundle(_artifact(m))
    return doc_with(b), t, False


def pl_require_author_key():  # unsupported require_author_key must reject
    def m(a):
        a["policies"]["sev-policy"]["sev_snp"]["require_author_key"] = True
    b, t = _bundle(_artifact(m))
    return doc_with(b), t, False


def pl_negative_tcb_eval():  # TDX minimum_tcb_evaluation_data_number negative
    def m(a):
        a["policies"]["tdx-policy"]["tdx"]["minimum_tcb_evaluation_data_number"] = -1
    b, t = _bundle(_artifact(m))
    return doc_with(b), t, False


def pl_vmpl_range():  # vmpl present but outside 0..3 (range check, not presence)
    def m(a):
        a["policies"]["sev-policy"]["sev_snp"]["vmpl"] = 7
    b, t = _bundle(_artifact(m))
    return doc_with(b), t, False


def pl_bad_launch_tcb():  # the second TCB instance (minimum_launch_tcb) is validated too
    def m(a):
        del a["policies"]["sev-policy"]["sev_snp"]["minimum_launch_tcb"]["bl_spl"]
    b, t = _bundle(_artifact(m))
    return doc_with(b), t, False


def pl_tdx_block_mismatch():  # platform tdx but the tdx block is absent
    def m(a):
        a["policies"]["tdx-policy"] = {"platform": "tdx", "sev_snp": sev_policy()}
    b, t = _bundle(_artifact(m))
    return doc_with(b), t, False


def pl_tdx_missing_required():  # TDX policy missing a required member (qe_vendor_id)
    def m(a):
        del a["policies"]["tdx-policy"]["tdx"]["qe_vendor_id"]
    b, t = _bundle(_artifact(m))
    return doc_with(b), t, False


def pl_tdx_empty_measurements():  # TDX platform_measurements must not be empty
    def m(a):
        a["policies"]["tdx-policy"]["tdx"]["platform_measurements"] = []
    b, t = _bundle(_artifact(m))
    return doc_with(b), t, False


# Positive variations that MUST accept.
def pos_fmc_spl():  # optional fmc_spl present in the TCB is valid
    def m(a):
        a["policies"]["sev-policy"]["sev_snp"]["minimum_tcb"]["fmc_spl"] = 0
    b, t = _bundle(_artifact(m))
    return doc_with(b), t, True


def pos_multi_machine():  # several machines mapping into the policy set
    def m(a):
        a["machines"]["ef" * 64] = "sev-policy"
    b, t = _bundle(_artifact(m))
    return doc_with(b), t, True


def i_plat_ref_not_tag():  # platform cert SourceRepositoryRef is a branch, not a tag
    b, t = _bundle(base_artifact(), source_ref="refs/heads/main")
    return doc_with(b), t, False


def i_plat_bad_commit():  # platform cert SourceRepositoryDigest is not a 40-hex commit
    b, t = _bundle(base_artifact(), source_digest="not-a-commit")
    return doc_with(b), t, False


def i_plat_wrong_repo():  # collateral claims a repo other than the pinned platform repo
    b, t = _bundle(base_artifact())  # signed under the pinned platform identity
    e = platform_entry(b)
    e["data"]["repo"] = "tinfoilsh/not-platform-endorsements"
    d = base_doc()
    d["collateral"] = [e]
    return d, t, False


MUTATIONS = {
    "i-plat-ref-not-tag": i_plat_ref_not_tag, "i-plat-bad-commit": i_plat_bad_commit,
    "i-plat-wrong-repo": i_plat_wrong_repo,
    "policy-happy": happy,
    "policy-pos-fmc-spl": pos_fmc_spl,
    "policy-pos-multi-machine": pos_multi_machine,
    "p2": p2, "p15-workflow": p15, "p15-tag": p15_tag, "p16": p16,
    "i-unknown-policy": i_unknown_policy, "i-sev-len": i_sev_len,
    "i-tdx-len": i_tdx_len, "i-not-hex": i_not_hex,
    "pl-block-mismatch": pl_block_mismatch, "pl-unsupported-platform": pl_unsupported_platform,
    "pl-missing-required": pl_missing_required, "pl-bad-tcb": pl_bad_tcb,
    "pl-dangling-measurement": pl_dangling_measurement, "pl-measurement-no-shape": pl_measurement_no_shape,
    "pl-unknown-member": pl_unknown_member, "pl-bad-format": pl_bad_format,
    "pl-require-author-key": pl_require_author_key, "pl-negative-tcb-eval": pl_negative_tcb_eval,
    "pl-vmpl-range": pl_vmpl_range, "pl-bad-launch-tcb": pl_bad_launch_tcb,
    "pl-tdx-block-mismatch": pl_tdx_block_mismatch, "pl-tdx-missing-required": pl_tdx_missing_required,
    "pl-tdx-empty-measurements": pl_tdx_empty_measurements,
}


def fixture(fid, doc, troot, accepted):
    return {
        "id": fid,
        "stage": "v3-assemble-policy",
        "input": {
            "schema_version": "1",
            "document_b64": b64(canon(doc)),
            "nonce_hex": "",
            "repo": REPO,
            "sigstore_trusted_root_json_b64": b64(json.dumps(troot).encode()),
        },
        "expected": {"accepted": accepted} if accepted else {"accepted": False, "code": "PROVENANCE_REJECTED"},
    }


def main():
    out = "vectors/v3/policy"
    os.makedirs(out, exist_ok=True)
    for fid, fn in MUTATIONS.items():
        doc, troot, accepted = fn()
        with open(os.path.join(out, fid + ".json"), "w") as fh:
            fh.write(json.dumps(fixture(fid, doc, troot, accepted), indent=2) + "\n")
    print(f"wrote {len(MUTATIONS)} policy fixtures to {out}/")


if __name__ == "__main__":
    main()
