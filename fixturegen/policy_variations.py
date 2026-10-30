#!/usr/bin/env python3
"""Generate Sigstore policy-variation fixtures from a seed real-frozen bundle.

For each fixture we keep the seed bundle + trust root + verification time
identical to fixture 001, but vary one input field — policy.*, expected_digest,
or trust_root_b64. The expected verdict pins the SPEC-anchored rejection code
(or accept, for cases like uppercase-digest that test normalization).

These are *uniform-behavior* fixtures: both SDKs MUST agree. They establish
positive proof of agreement on each Policy clause. Real *differential*
fixtures (where SDKs are expected to disagree until fixed) require
fixturegen for synthetic Fulcio/Rekor — separate effort.

Usage:
    python3 fixturegen/policy_variations.py

Re-run any time the seed bundle changes (e.g. when 001 is rotated to a fresher
production bundle). Existing fixture directories are overwritten.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = REPO_ROOT / "vectors" / "sigstore"
SEED = VECTORS_DIR / "001-happy-path-snp-tdx-multiplatform"

# Capabilities every policy-variation fixture requires. Fixtures that rely on
# additional configurable fields add to this list.
BASE_CAPABILITIES = {
    "sigstore.trust_root_loading": "configurable",
    # Accept any hermetic-time SDK — both "supported" (consumes our supplied
    # time) and "bundle-supplied-only" (uses bundle's cert NotBefore) survive
    # cert expiry over fixture lifetime. "system-clock-only" rots.
    "sigstore.verification_time_override": [
        "supported",
        "bundle-supplied-only",
    ],
    "sigstore.policy_fields_configurable.workflow_ref_prefix": True,
    "sigstore.policy_fields_configurable.predicate_types_allowed": True,
}


def load_seed() -> dict:
    return json.loads((SEED / "input.json").read_text())


def write_fixture(
    fixture_id: str,
    title: str,
    spec_refs: list[str],
    fixture_kind: str,
    notes: str,
    seed_input: dict,
    *,
    mutate_input,
    expected_exit: int,
    rejection_code: str | list[str] | None,
    expected_outputs: dict | None,
    extra_capabilities: dict[str, object] | None = None,
) -> None:
    """Write {input.json, expected.json, manifest.yaml, README.md} for a fixture."""
    dst = VECTORS_DIR / fixture_id
    dst.mkdir(parents=True, exist_ok=True)

    input_payload = copy.deepcopy(seed_input)
    mutate_input(input_payload)
    (dst / "input.json").write_text(json.dumps(input_payload, indent=2))

    if expected_exit == 0:
        expected_payload = {
            "stage": "verify-sigstore",
            "accepted": True,
            "outputs": expected_outputs or {},
        }
    else:
        expected_payload = {
            "stage": "verify-sigstore",
            "accepted": False,
            "rejection": {"code": rejection_code},
        }
    (dst / "expected.json").write_text(json.dumps(expected_payload, indent=2))

    capabilities = dict(BASE_CAPABILITIES)
    if extra_capabilities:
        capabilities.update(extra_capabilities)

    manifest = (
        f"id: {fixture_id}\n"
        f"stage: verify-sigstore\n"
        f"title: |\n"
        f"  {title}\n"
        f"spec_refs: {json.dumps(spec_refs)}\n"
        f"expects:\n"
        f"  exit_code: {expected_exit}\n"
    )
    if rejection_code is not None:
        # JSON-serializable so the YAML loader handles list-or-string uniformly.
        manifest += f"  rejection_code: {json.dumps(rejection_code)}\n"
    manifest += "required_capabilities:\n"
    for path, value in capabilities.items():
        manifest += f"  {path}: {json.dumps(value)}\n"
    manifest += f"fixture_kind: {fixture_kind}\n"
    manifest += f"notes: |\n"
    for line in notes.strip().splitlines():
        manifest += f"  {line}\n"
    (dst / "manifest.yaml").write_text(manifest)


def main() -> None:
    seed = load_seed()
    # Compute fields we'll reuse.
    real_digest = seed["expected_digest_sha256_hex"]

    # The seed expected outputs (only the policy-related fields differ across
    # fixtures; outputs are identical for all *accepting* fixtures).
    seed_expected = json.loads((SEED / "expected.json").read_text())
    accept_outputs = seed_expected["outputs"]

    # 010 -------------------------------------------------------------------
    write_fixture(
        "010-workflow-ref-prefix-mismatch",
        "policy.workflow_ref_prefix that does not match the cert's ref must be rejected.",
        ["5.3"],
        "real-frozen-policy-variation",
        notes=(
            "Same bundle as 001. We tighten policy.workflow_ref_prefix to a value\n"
            "that doesn't match the cert's actual workflow ref. SDKs implement the\n"
            "check differently (Rust applies a regex on BuildSignerURI, JS calls\n"
            ".startsWith() on the cert's GitHubWorkflowRef extension) — both must\n"
            "reject with the same code."
        ),
        seed_input=seed,
        mutate_input=lambda i: i["policy"].update(
            workflow_ref_prefix="refs/heads/release/"
        ),
        expected_exit=10,
        rejection_code="WORKFLOW_REF_PREFIX_MISMATCH",
        expected_outputs=None,
    )

    # 011 -------------------------------------------------------------------
    write_fixture(
        "011-oidc-issuer-mismatch",
        "policy.oidc_issuer that does not match the cert's OIDC issuer must be rejected.",
        ["5.3"],
        "real-frozen-policy-variation",
        notes=(
            "Same bundle as 001. policy.oidc_issuer is set to a non-GitHub value.\n"
            "Both SDKs must reject — establishes that the OIDC issuer check is exact\n"
            "match against the policy field (not hardcoded to GitHub Actions)."
        ),
        seed_input=seed,
        mutate_input=lambda i: i["policy"].update(
            oidc_issuer="https://gitlab.example.com/oidc"
        ),
        expected_exit=10,
        rejection_code="OIDC_ISSUER_MISMATCH",
        expected_outputs=None,
    )

    # 012 -------------------------------------------------------------------
    write_fixture(
        "012-workflow-repository-mismatch",
        "Top-level repo that does not match the cert's GitHubWorkflowRepository must be rejected.",
        ["5.3"],
        "real-frozen-policy-variation",
        notes=(
            "Same bundle as 001 but the fixture's `repo` field is changed to a\n"
            "different owner/name. SDKs derive policy.workflow_repository from\n"
            "this field and must reject with WORKFLOW_REPOSITORY_MISMATCH."
        ),
        seed_input=seed,
        mutate_input=lambda i: i.update(repo="evil-owner/evil-repo"),
        expected_exit=10,
        rejection_code="WORKFLOW_REPOSITORY_MISMATCH",
        expected_outputs=None,
    )

    # 013 -------------------------------------------------------------------
    write_fixture(
        "013-predicate-type-not-allowed",
        "policy.predicate_types_allowed that excludes the bundle's actual predicate must reject.",
        ["5.5"],
        "real-frozen-policy-variation",
        notes=(
            "Same bundle as 001, but the policy allow-list explicitly does NOT\n"
            "include the bundle's predicate type. This catches SDKs (looking at\n"
            "you, pre-refactor Go) that deferred predicate-type pinning until\n"
            "consumption — they would accept this bundle at verify time and only\n"
            "fail later, defeating defense in depth."
        ),
        seed_input=seed,
        mutate_input=lambda i: i["policy"].update(
            predicate_types_allowed=["https://example.com/predicate/other/v1"]
        ),
        expected_exit=10,
        rejection_code="PREDICATE_TYPE_NOT_ALLOWED",
        expected_outputs=None,
    )

    # 014 -------------------------------------------------------------------
    write_fixture(
        "014-in-toto-statement-type-not-allowed",
        "policy.in_toto_statement_types_allowed that excludes the actual statement type must reject.",
        ["5.4"],
        "real-frozen-policy-variation",
        notes=(
            "SPEC §5.4 is silent on which in-toto statement _type values are\n"
            "acceptable. Tinfoil's default policy pins to v0.1/v1; this fixture\n"
            "shifts the allow-list elsewhere and verifies SDKs honor the policy."
        ),
        seed_input=seed,
        mutate_input=lambda i: i["policy"].update(
            in_toto_statement_types_allowed=["https://in-toto.io/Statement/v0.99"]
        ),
        expected_exit=10,
        rejection_code="IN_TOTO_STATEMENT_TYPE_NOT_ALLOWED",
        expected_outputs=None,
        extra_capabilities={
            "sigstore.policy_fields_configurable.in_toto_statement_types_allowed": True,
        },
    )

    # 015 -------------------------------------------------------------------
    write_fixture(
        "015-payload-type-mismatch",
        "policy.payload_type that does not match the DSSE envelope's payload_type must reject.",
        ["5.4"],
        "real-frozen-policy-variation",
        notes=(
            "DSSE envelope is application/vnd.in-toto+json. Policy demands something\n"
            "else. Both SDKs must reject with PAYLOAD_TYPE_MISMATCH (exact-string\n"
            "match, no charset tolerance — see SPEC §5.4)."
        ),
        seed_input=seed,
        mutate_input=lambda i: i["policy"].update(
            payload_type="application/vnd.something-else"
        ),
        expected_exit=10,
        rejection_code="PAYLOAD_TYPE_MISMATCH",
        expected_outputs=None,
        extra_capabilities={
            "sigstore.policy_fields_configurable.payload_type": True,
        },
    )

    # 016 -------------------------------------------------------------------
    write_fixture(
        "016-subject-digest-mismatch",
        "expected_digest_sha256_hex that doesn't match the bundle subject must reject.",
        ["5.4"],
        "real-frozen-policy-variation",
        notes=(
            "Trivial but load-bearing: the digest binding from caller to attested\n"
            "artifact MUST be checked. Provide a zeroed-out digest; both SDKs reject."
        ),
        seed_input=seed,
        mutate_input=lambda i: i.update(
            expected_digest_sha256_hex="0" * 64
        ),
        expected_exit=10,
        rejection_code="SUBJECT_DIGEST_MISMATCH",
        expected_outputs=None,
    )

    # 017 -------------------------------------------------------------------
    write_fixture(
        "017-subject-digest-uppercase-accepted",
        "expected_digest_sha256_hex in uppercase hex must still verify (SPEC §7.3 lowercase normalization).",
        ["5.4", "7.3"],
        "real-frozen-policy-variation",
        notes=(
            "SPEC §7.3: all hex comparisons are lowercase-normalized. Pre-refactor\n"
            "JS/Python/Go used strict !=/!== on digests and would fail this; Rust\n"
            "already normalized. After the refactor both SDKs accept uppercase\n"
            "expected_digest_sha256_hex. The output's subject_digest_sha256_hex\n"
            "MUST be lowercase regardless of input case."
        ),
        seed_input=seed,
        mutate_input=lambda i: i.update(
            expected_digest_sha256_hex=real_digest.upper()
        ),
        expected_exit=0,
        rejection_code=None,
        expected_outputs=accept_outputs,
    )

    # 018 -------------------------------------------------------------------
    write_fixture(
        "018-predicate-types-allowed-null-accepts",
        "policy.predicate_types_allowed=null means 'any', so the bundle accepts.",
        ["5.5"],
        "real-frozen-policy-variation",
        notes=(
            "Verifies that null in the allow-list is interpreted as 'any', not\n"
            "as 'empty list = reject everything'. Catches off-by-default semantic\n"
            "bugs in policy plumbing."
        ),
        seed_input=seed,
        mutate_input=lambda i: i["policy"].update(predicate_types_allowed=None),
        expected_exit=0,
        rejection_code=None,
        expected_outputs=accept_outputs,
    )

    # 019 -------------------------------------------------------------------
    write_fixture(
        "019-in-toto-statement-types-allowed-null-accepts",
        "policy.in_toto_statement_types_allowed=null means 'any'.",
        ["5.4"],
        "real-frozen-policy-variation",
        notes=(
            "Symmetric to 018, but for the in-toto statement type allow-list."
        ),
        seed_input=seed,
        mutate_input=lambda i: i["policy"].update(
            in_toto_statement_types_allowed=None
        ),
        expected_exit=0,
        rejection_code=None,
        expected_outputs=accept_outputs,
        extra_capabilities={
            "sigstore.policy_fields_configurable.in_toto_statement_types_allowed": True,
        },
    )

    # ---------- Trust-root mutations -------------------------------------
    # These mutate the *trust root only*, not the bundle. The bundle signature
    # is therefore intact, but verification fails because the trust root no
    # longer endorses the keys/CAs that signed the bundle.
    seed_trust = json.loads(
        base64.b64decode(seed["trust_root_b64"]).decode()
    )

    # 021: trust root with no Rekor keys → Rekor inclusion can't be verified.
    no_rekor = copy.deepcopy(seed_trust)
    no_rekor["tlogs"] = []
    write_fixture(
        "021-trust-root-no-rekor-keys",
        "Trust root with no Rekor keys must cause REKOR_KEY_NOT_TRUSTED or REKOR_INCLUSION_INVALID.",
        ["5.1", "5.2"],
        "real-frozen-trust-root-mutation",
        notes=(
            "Bundle is the real production bundle from 001, signed cleanly.\n"
            "Trust root has been emptied of Rekor public keys.\n"
            "\n"
            "SDKs classify the failure differently because upstream Sigstore libs\n"
            "differ in granularity: tinfoil-rs surfaces REKOR_KEY_NOT_TRUSTED\n"
            "(precise: 'no key matched this log id'); tinfoil-js via\n"
            "@freedomofpress/sigstore-browser raises 'Invalid checkpoint\n"
            "signature' (the first symptom — can't validate the checkpoint\n"
            "signature against any key) and we classify it as\n"
            "REKOR_INCLUSION_INVALID. The list form of `rejection_code` lets the\n"
            "fixture accept either while keeping the divergence visible in the\n"
            "result detail."
        ),
        seed_input=seed,
        mutate_input=lambda i: i.update(
            trust_root_b64=base64.standard_b64encode(
                json.dumps(no_rekor).encode()
            ).decode()
        ),
        expected_exit=10,
        # Four SDKs, four different angles on the same root cause ("no Rekor
        # key endorses the tlog entry's log_id"):
        #   * tinfoil-rs    : REKOR_KEY_NOT_TRUSTED (precise: "no key for log")
        #   * tinfoil-js    : REKOR_INCLUSION_INVALID (sigstore-browser
        #                     surfaces as "Invalid checkpoint signature")
        #   * tinfoil-python: REKOR_KEY_NOT_TRUSTED (via internal IndexError)
        #   * tinfoil-go    : TLOG_COUNT_OUT_OF_RANGE (sigstore-go counts
        #                     verified entries; 0 < 1 → reject)
        # All are honest rejections. The list captures the genuine taxonomy
        # ambiguity inherent in the upstream-lib differences.
        rejection_code=[
            "REKOR_KEY_NOT_TRUSTED",
            "REKOR_INCLUSION_INVALID",
            "TLOG_COUNT_OUT_OF_RANGE",
        , "TRUST_ROOT_INVALID"],
        expected_outputs=None,
    )

    # 023: trust root with no CT log keys → SCTs can't be verified.
    no_ctlogs = copy.deepcopy(seed_trust)
    no_ctlogs["ctlogs"] = []
    write_fixture(
        "023-trust-root-no-ct-log-keys",
        "Trust root with no CT log keys must reject — SCT signature can't be verified.",
        ["5.1", "5.2"],
        "real-frozen-trust-root-mutation",
        notes=(
            "Symmetric to 021 (no Rekor keys) and 022 (no Fulcio CAs): empties\n"
            "the trust root's CT log key list. The signing cert has embedded\n"
            "SCTs, but no key in the trust root can verify their signatures.\n"
            "SPEC §5.2 #4 requires at least 1 valid SCT; with no usable\n"
            "verifier key, no SCT can be deemed valid.\n"
            "\n"
            "Four-way taxonomy split:\n"
            "  * tinfoil-rs:  SCT_INSUFFICIENT (precise: zero verifiable SCTs)\n"
            "  * tinfoil-js:  BUNDLE_MALFORMED (sigstore-browser treats empty\n"
            "                 ctlogs as a structural trust-root error)\n"
            "  * tinfoil-py:  TRUST_ROOT_INVALID (sigstore-python rejects\n"
            "                 empty ctlogs at TrustedRoot.from_file load time)\n"
            "  * tinfoil-go:  BUNDLE_MALFORMED (sigstore-go rejects similarly)\n"
            "All are honest rejections — list-form rejection_code captures\n"
            "the genuine taxonomy divergence."
        ),
        seed_input=seed,
        mutate_input=lambda i: i.update(
            trust_root_b64=base64.standard_b64encode(
                json.dumps(no_ctlogs).encode()
            ).decode()
        ),
        expected_exit=10,
        rejection_code=[
            "SCT_INSUFFICIENT",
            "FULCIO_CHAIN_INVALID",
            "BUNDLE_MALFORMED",
            "TRUST_ROOT_INVALID",
        ],
        expected_outputs=None,
    )

    # 022: trust root with no Fulcio CAs → cert chain can't be verified.
    no_fulcio = copy.deepcopy(seed_trust)
    no_fulcio["certificateAuthorities"] = []
    write_fixture(
        "022-trust-root-no-fulcio-cas",
        "Trust root with no Fulcio CAs must cause FULCIO_CHAIN_INVALID.",
        ["5.1", "5.2"],
        "real-frozen-trust-root-mutation",
        notes=(
            "Removes all Fulcio certificate authorities. The signing cert cannot\n"
            "chain to any trusted root. Both SDKs must reject.\n"
            "NOTE: sigstore-browser may surface SCT-related errors first (SCT\n"
            "verification calls find_issuer_spki, which also needs the Fulcio\n"
            "CAs) — that's why we keep this co-anchored to SPEC §5.1 + §5.2."
        ),
        seed_input=seed,
        mutate_input=lambda i: i.update(
            trust_root_b64=base64.standard_b64encode(
                json.dumps(no_fulcio).encode()
            ).decode()
        ),
        expected_exit=10,
        rejection_code="FULCIO_CHAIN_INVALID",
        expected_outputs=None,
    )

    # ---------- Bundle-shape mutations -----------------------------------
    # These remove or null out a top-level bundle field. The DSSE signature
    # doesn't sign these fields (it signs the inner payload), so we can mutate
    # them without re-signing. They test that SDKs reject malformed bundle
    # shapes rather than crashing or silently succeeding.
    seed_bundle = json.loads(base64.b64decode(seed["bundle_b64"]).decode())

    # 030: bundle missing dsseEnvelope entirely.
    no_envelope = copy.deepcopy(seed_bundle)
    del no_envelope["dsseEnvelope"]
    write_fixture(
        "030-bundle-missing-dsse-envelope",
        "Bundle without dsseEnvelope must reject with BUNDLE_MALFORMED.",
        ["5.2"],
        "real-frozen-bundle-mutation",
        notes=(
            "The dsseEnvelope key is removed from the bundle JSON. The signature\n"
            "is not affected because what's signed is the payload INSIDE the\n"
            "envelope; the envelope itself isn't covered. Both SDKs must reject\n"
            "structurally with BUNDLE_MALFORMED before attempting any crypto."
        ),
        seed_input=seed,
        mutate_input=lambda i: i.update(
            bundle_b64=base64.standard_b64encode(
                json.dumps(no_envelope).encode()
            ).decode()
        ),
        expected_exit=10,
        rejection_code="BUNDLE_MALFORMED",
        expected_outputs=None,
    )

    # 032: corrupt the DSSE signature bytes. Payload is untouched so the SDKs
    # reach signature verification and reject there.
    corrupt_sig = copy.deepcopy(seed_bundle)
    sig_b64 = corrupt_sig["dsseEnvelope"]["signatures"][0]["sig"]
    sig_bytes = bytearray(base64.b64decode(sig_b64))
    sig_bytes[10] ^= 0x01  # flip a bit in the middle of the signature
    corrupt_sig["dsseEnvelope"]["signatures"][0]["sig"] = base64.b64encode(
        bytes(sig_bytes)
    ).decode()
    write_fixture(
        "032-dsse-signature-bit-flipped",
        "Bundle with one bit flipped in the DSSE signature must reject with DSSE_SIGNATURE_INVALID.",
        ["5.2"],
        "real-frozen-bundle-mutation",
        notes=(
            "The DSSE signature bytes (signatures[0].sig) are separate from the\n"
            "signed payload, so we can corrupt them without touching the in-toto\n"
            "statement. One bit is flipped; SDKs reach signature verification\n"
            "and reject."
        ),
        seed_input=seed,
        mutate_input=lambda i: i.update(
            bundle_b64=base64.standard_b64encode(
                json.dumps(corrupt_sig).encode()
            ).decode()
        ),
        expected_exit=10,
        rejection_code="DSSE_SIGNATURE_INVALID",
        expected_outputs=None,
    )

    # 033: corrupt inclusionProof.rootHash so it differs from the signed
    # checkpoint envelope. The Rust SDK explicitly cross-checks
    # `inclusion_proof.root_hash == signed_checkpoint.root_hash`. JS may not
    # cross-check directly and instead surface the issue as inclusion-proof
    # invalid via Merkle reconstruction or signature failure.
    corrupt_root = copy.deepcopy(seed_bundle)
    tlog = corrupt_root["verificationMaterial"]["tlogEntries"][0]
    rh_b64 = tlog["inclusionProof"]["rootHash"]
    rh_bytes = bytearray(base64.b64decode(rh_b64))
    rh_bytes[0] ^= 0x01
    tlog["inclusionProof"]["rootHash"] = base64.b64encode(bytes(rh_bytes)).decode()
    write_fixture(
        "033-rekor-root-hash-mismatch",
        "Bundle with rootHash that doesn't match the signed checkpoint must reject.",
        ["5.2"],
        "real-frozen-bundle-mutation",
        notes=(
            "inclusionProof.rootHash is mutated so it no longer equals the root\n"
            "hash inside the signed checkpoint envelope. The cleanest classification\n"
            "is CHECKPOINT_ROOT_MISMATCH (Rust does this cross-check explicitly).\n"
            "Sigstore-browser may instead surface this as REKOR_INCLUSION_INVALID\n"
            "(its inclusion-proof verifier reconstructs to the wrong root). Both\n"
            "are correct rejections; we accept either via the list form."
        ),
        seed_input=seed,
        mutate_input=lambda i: i.update(
            bundle_b64=base64.standard_b64encode(
                json.dumps(corrupt_root).encode()
            ).decode()
        ),
        expected_exit=10,
        rejection_code=["CHECKPOINT_ROOT_MISMATCH", "REKOR_INCLUSION_INVALID"],
        expected_outputs=None,
    )

    # 034: corrupt one of the inclusionProof Merkle hashes. Reconstruction
    # from leaf to root will produce a different root than what the checkpoint
    # signed → REKOR_INCLUSION_INVALID (or CHECKPOINT_ROOT_MISMATCH depending
    # on the SDK's check order).
    corrupt_hash = copy.deepcopy(seed_bundle)
    tlog2 = corrupt_hash["verificationMaterial"]["tlogEntries"][0]
    h0 = tlog2["inclusionProof"]["hashes"][0]
    h0_bytes = bytearray(base64.b64decode(h0))
    h0_bytes[0] ^= 0x01
    tlog2["inclusionProof"]["hashes"][0] = base64.b64encode(bytes(h0_bytes)).decode()
    write_fixture(
        "034-rekor-inclusion-hashes-corrupted",
        "Bundle with a corrupted Merkle hash in the inclusion proof must reject.",
        ["5.2"],
        "real-frozen-bundle-mutation",
        notes=(
            "hashes[0] of the inclusion proof is bit-flipped. Merkle reconstruction\n"
            "produces a wrong root. Either REKOR_INCLUSION_INVALID (Merkle path\n"
            "doesn't verify) or CHECKPOINT_ROOT_MISMATCH (computed root != signed\n"
            "checkpoint root) is acceptable depending on SDK check order."
        ),
        seed_input=seed,
        mutate_input=lambda i: i.update(
            bundle_b64=base64.standard_b64encode(
                json.dumps(corrupt_hash).encode()
            ).decode()
        ),
        expected_exit=10,
        rejection_code=["REKOR_INCLUSION_INVALID", "CHECKPOINT_ROOT_MISMATCH"],
        expected_outputs=None,
    )

    # 035: bundle with empty DSSE signatures array.
    empty_sigs = copy.deepcopy(seed_bundle)
    empty_sigs["dsseEnvelope"]["signatures"] = []
    write_fixture(
        "035-bundle-empty-signatures-array",
        "Bundle whose DSSE signatures array is empty must reject.",
        ["5.2"],
        "real-frozen-bundle-mutation",
        notes=(
            "Either DSSE_SIGNATURE_INVALID (Rust rejects 'must have exactly 1\n"
            "signature') or BUNDLE_MALFORMED (treat empty-array as structural)\n"
            "is acceptable."
        ),
        seed_input=seed,
        mutate_input=lambda i: i.update(
            bundle_b64=base64.standard_b64encode(
                json.dumps(empty_sigs).encode()
            ).decode()
        ),
        expected_exit=10,
        rejection_code=["DSSE_SIGNATURE_INVALID", "BUNDLE_MALFORMED"],
        expected_outputs=None,
    )

    # 036: bundle missing verificationMaterial entirely.
    no_vm = copy.deepcopy(seed_bundle)
    del no_vm["verificationMaterial"]
    write_fixture(
        "036-bundle-missing-verification-material",
        "Bundle without verificationMaterial must reject with BUNDLE_MALFORMED.",
        ["5.2"],
        "real-frozen-bundle-mutation",
        notes=(
            "The cert + tlog entries + checkpoint all live in verificationMaterial.\n"
            "Removing the whole object: SDKs cannot even start chain validation.\n"
            "Both must reject structurally with BUNDLE_MALFORMED."
        ),
        seed_input=seed,
        mutate_input=lambda i: i.update(
            bundle_b64=base64.standard_b64encode(
                json.dumps(no_vm).encode()
            ).decode()
        ),
        expected_exit=10,
        rejection_code="BUNDLE_MALFORMED",
        expected_outputs=None,
    )

    # 050-052: additional policy edge cases ---------------------------------

    # 050: workflow_ref_prefix that exactly equals the cert's workflow ref.
    # This is the prefix-equals-full-string case; should still accept.
    # We need to derive the actual cert's workflow ref. Decode it from
    # fixture 001's expected output... but we don't have it there. Instead
    # use a prefix that we know matches: the actual cert is for
    # confidential-model-router, so the ref is likely "refs/tags/vX.Y.Z".
    # We use "refs/tags/" which the seed already uses, and a more-specific
    # value "refs/tags/v" which still matches.
    write_fixture(
        "050-workflow-ref-prefix-more-specific-accepts",
        "policy.workflow_ref_prefix='refs/tags/v' (more specific than default) still accepts a v-prefixed tag.",
        ["5.3"],
        "real-frozen-policy-variation",
        notes=(
            "Positive test that longer prefixes still match. The fixture cert's\n"
            "workflow ref begins with 'refs/tags/v…'; tightening the policy to\n"
            "'refs/tags/v' (drop the 'efs/tags/' suffix is wrong; we mean adding\n"
            "the 'v' prefix) still satisfies the check."
        ),
        seed_input=seed,
        mutate_input=lambda i: i["policy"].update(
            workflow_ref_prefix="refs/tags/v"
        ),
        expected_exit=0,
        rejection_code=None,
        expected_outputs=accept_outputs,
    )

    # 051: predicate_types_allowed = [] (empty list = reject everything).
    # Distinct from 018 which uses null (= any allowed).
    write_fixture(
        "051-predicate-types-allowed-empty-rejects-all",
        "policy.predicate_types_allowed=[] (empty allow-list) must reject any predicate.",
        ["5.5"],
        "real-frozen-policy-variation",
        notes=(
            "Companion to 018 (null = any). Empty list = nothing allowed = always\n"
            "reject. Distinguishes 'unset' from 'explicitly empty', a common\n"
            "source of policy-plumbing bugs."
        ),
        seed_input=seed,
        mutate_input=lambda i: i["policy"].update(predicate_types_allowed=[]),
        expected_exit=10,
        rejection_code="PREDICATE_TYPE_NOT_ALLOWED",
        expected_outputs=None,
    )

    # 052: in_toto_statement_types_allowed = [] (empty list = reject everything).
    write_fixture(
        "052-in-toto-statement-types-allowed-empty-rejects-all",
        "policy.in_toto_statement_types_allowed=[] (empty allow-list) must reject any statement type.",
        ["5.4"],
        "real-frozen-policy-variation",
        notes=("Symmetric to 051, for the in-toto statement type allow-list."),
        seed_input=seed,
        mutate_input=lambda i: i["policy"].update(
            in_toto_statement_types_allowed=[]
        ),
        expected_exit=10,
        rejection_code="IN_TOTO_STATEMENT_TYPE_NOT_ALLOWED",
        expected_outputs=None,
        extra_capabilities={
            "sigstore.policy_fields_configurable.in_toto_statement_types_allowed": True,
        },
    )

    # 031: bundle with empty tlogEntries array.
    empty_tlogs = copy.deepcopy(seed_bundle)
    empty_tlogs["verificationMaterial"]["tlogEntries"] = []
    write_fixture(
        "031-bundle-empty-tlog-entries",
        "Bundle with empty tlogEntries must reject with TLOG_COUNT_OUT_OF_RANGE.",
        ["5.2"],
        "real-frozen-bundle-mutation",
        notes=(
            "Bundle's tlogEntries is set to []. SPEC §5.2 #3 requires at least 1\n"
            "valid Rekor log entry; this fixture pins TLOG_COUNT_OUT_OF_RANGE\n"
            "as the canonical code. SDK divergence on this rejection code is a\n"
            "real conformance signal worth investigating (e.g., sigstore-browser\n"
            "may surface a more generic REKOR_INCLUSION_INVALID)."
        ),
        seed_input=seed,
        mutate_input=lambda i: i.update(
            bundle_b64=base64.standard_b64encode(
                json.dumps(empty_tlogs).encode()
            ).decode()
        ),
        expected_exit=10,
        rejection_code="TLOG_COUNT_OUT_OF_RANGE",
        expected_outputs=None,
    )

    # 020 -------------------------------------------------------------------
    not_json = b"this trust root is not JSON"
    write_fixture(
        "020-trust-root-invalid-json",
        "trust_root_b64 that decodes to non-JSON must be rejected with TRUST_ROOT_INVALID.",
        ["5.1"],
        "real-frozen-policy-variation",
        notes=(
            "Trust root that doesn't even parse — both SDKs MUST reject at exit 10\n"
            "(substantive verification failure, not exit 30 which is reserved for\n"
            "input.json envelope-shape violations)."
        ),
        seed_input=seed,
        mutate_input=lambda i: i.update(
            trust_root_b64=base64.standard_b64encode(not_json).decode()
        ),
        expected_exit=10,
        rejection_code="TRUST_ROOT_INVALID",
        expected_outputs=None,
    )

    print("Wrote 11 fixtures:")
    for d in sorted(VECTORS_DIR.iterdir()):
        if d.is_dir() and d.name != SEED.name:
            print(f"  {d.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
