#!/usr/bin/env python3
"""Generate Sigstore fixtures that require fresh signatures.

Anything that mutates signed material — the cert's Fulcio extensions
(workflow ref, OIDC issuer, repo), the cert's validity window, the SCT list,
or the DSSE-signed in-toto payload — can only be tested with a synthetic
trust root + freshly signed bundle. This module drives `fixturegen.lib` to
produce those.

Fixtures emitted:

    060 workflow-ref-heads-trojan         — cert ext workflow_ref =
                                             "refs/heads/main@refs/tags/v1"
                                             (the recon-found Go-style trojan)
    061 workflow-ref-bare-heads-branch    — cert ext workflow_ref = "refs/heads/main"
    062 predicate-missing-tdx-rtmr2       — DSSE payload mutated (re-signed)
    063 subject-missing                   — DSSE payload with empty subject
    064 cert-expired                      — cert NotAfter < verification_time

Each fixture's payload is otherwise identical to fixture 001's so the SDK's
binding checks line up.
"""

from __future__ import annotations

import base64
import copy
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "fixturegen"))

from lib.spec import FixtureSpec, build_bundle_and_trust_root  # noqa: E402

VECTORS_DIR = REPO_ROOT / "vectors" / "sigstore"
SEED = VECTORS_DIR / "001-happy-path-snp-tdx-multiplatform"

DEFAULT_REPO = "tinfoilsh/test-repo"


def seed_payload() -> bytes:
    """Pull the in-toto payload bytes out of fixture 001's DSSE envelope.

    Reused across synthetic fixtures so the subject digest binding, predicate
    shape, etc. all line up with the harness's defaults."""
    seed_input = json.loads((SEED / "input.json").read_text())
    seed_bundle = json.loads(base64.b64decode(seed_input["bundle_b64"]))
    return base64.b64decode(seed_bundle["dsseEnvelope"]["payload"])


def seed_digest() -> str:
    return json.loads((SEED / "input.json").read_text())["expected_digest_sha256_hex"]


def default_policy(repo: str) -> dict[str, Any]:
    return {
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "workflow_ref_prefix": "refs/tags/",
        "predicate_types_allowed": [
            "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
        ],
        "in_toto_statement_types_allowed": None,
        "payload_type": "application/vnd.in-toto+json",
    }


BASE_CAPS: dict[str, Any] = {
    "sigstore.trust_root_loading": "configurable",
    "sigstore.verification_time_override": "supported",
    "sigstore.policy_fields_configurable.workflow_ref_prefix": True,
    "sigstore.policy_fields_configurable.predicate_types_allowed": True,
}


def _verification_time(spec: FixtureSpec) -> int:
    """Pick a verification time strictly inside the leaf cert's validity window."""
    half = (
        (spec.leaf_valid_from.timestamp() + spec.leaf_valid_until.timestamp()) / 2
    )
    return int(half)


def write_fixture(
    *,
    fixture_id: str,
    title: str,
    spec_refs: list[str],
    notes: str,
    spec: FixtureSpec,
    repo: str,
    policy_override: dict[str, Any] | None,
    expected_exit: int,
    rejection_code: str | list[str] | None,
    expected_outputs: dict[str, Any] | None = None,
    extra_capabilities: dict[str, Any] | None = None,
) -> None:
    g = build_bundle_and_trust_root(spec)
    policy = default_policy(repo)
    if policy_override:
        policy.update(policy_override)

    input_payload = {
        "schema_version": "1",
        "bundle_b64": base64.standard_b64encode(json.dumps(g.bundle).encode()).decode(),
        "expected_digest_sha256_hex": seed_digest(),
        "repo": repo,
        "policy": policy,
        "trust_root_b64": base64.standard_b64encode(
            json.dumps(g.trust_root).encode()
        ).decode(),
        "verification_time_unix": _verification_time(spec),
    }

    dst = VECTORS_DIR / fixture_id
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "input.json").write_text(json.dumps(input_payload, indent=2))

    if expected_exit == 0:
        expected_payload: dict[str, Any] = {
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

    capabilities = dict(BASE_CAPS)
    if extra_capabilities:
        capabilities.update(extra_capabilities)

    manifest = (
        f"id: {fixture_id}\n"
        f"stage: verify-sigstore\n"
        f"title: |\n  {title}\n"
        f"spec_refs: {json.dumps(spec_refs)}\n"
        f"expects:\n"
        f"  exit_code: {expected_exit}\n"
    )
    if rejection_code is not None:
        manifest += f"  rejection_code: {json.dumps(rejection_code)}\n"
    manifest += "required_capabilities:\n"
    for path, value in capabilities.items():
        manifest += f"  {path}: {json.dumps(value)}\n"
    manifest += "fixture_kind: synthetic\n"
    manifest += "notes: |\n"
    for line in notes.strip().splitlines():
        manifest += f"  {line}\n"
    (dst / "manifest.yaml").write_text(manifest)


def mutate_payload_remove_rtmr2(payload: bytes) -> bytes:
    """Strip rtmr2 from the predicate. The signature breaks; we re-sign."""
    p = json.loads(payload.decode())
    pred = copy.deepcopy(p["predicate"])
    if "tdx_measurement" in pred and "rtmr2" in pred["tdx_measurement"]:
        del pred["tdx_measurement"]["rtmr2"]
    p["predicate"] = pred
    return json.dumps(p, separators=(",", ":"), sort_keys=True).encode()


def mutate_payload_empty_subject(payload: bytes) -> bytes:
    p = json.loads(payload.decode())
    p["subject"] = []
    return json.dumps(p, separators=(",", ":"), sort_keys=True).encode()


def main() -> None:
    payload = seed_payload()

    # 060: workflow-ref-heads-trojan ----------------------------------------
    write_fixture(
        fixture_id="060-workflow-ref-heads-trojan",
        title=(
            "Cert workflow ref 'refs/heads/main@refs/tags/v1' (trojan) must be rejected."
        ),
        spec_refs=["5.3"],
        notes=(
            "The recon's marquee differential vector. A cert with workflow ref\n"
            "'refs/heads/main@refs/tags/v1' embeds the substring 'refs/tags/'\n"
            "but does NOT start with it. SDKs doing loose substring/regex checks\n"
            "would accept; correct prefix-semantics implementations reject.\n"
            "\n"
            "Both Rust and JS use proper prefix matching today (we built it\n"
            "deliberately, see SPEC §5.3); this fixture is a regression guard\n"
            "that any future relaxation gets caught."
        ),
        spec=FixtureSpec(
            payload_bytes=payload,
            workflow_repository=DEFAULT_REPO,
            workflow_ref="refs/heads/main@refs/tags/v1",
            build_signer_uri=(
                f"https://github.com/{DEFAULT_REPO}/.github/workflows/release.yml"
                "@refs/heads/main@refs/tags/v1"
            ),
        ),
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=10,
        rejection_code="WORKFLOW_REF_PREFIX_MISMATCH",
    )

    # 061: workflow-ref-bare-heads-branch -----------------------------------
    write_fixture(
        fixture_id="061-workflow-ref-bare-heads-branch",
        title="Cert workflow ref 'refs/heads/main' (no trojan) must be rejected.",
        spec_refs=["5.3"],
        notes=(
            "The plain branch-build case: cert is for a build that wasn't\n"
            "triggered by a tag. SDKs must reject because policy requires\n"
            "tag-triggered builds (workflow_ref_prefix='refs/tags/')."
        ),
        spec=FixtureSpec(
            payload_bytes=payload,
            workflow_repository=DEFAULT_REPO,
            workflow_ref="refs/heads/main",
            build_signer_uri=(
                f"https://github.com/{DEFAULT_REPO}/.github/workflows/release.yml"
                "@refs/heads/main"
            ),
        ),
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=10,
        rejection_code="WORKFLOW_REF_PREFIX_MISMATCH",
    )

    # 062: predicate-missing-tdx-rtmr2 --------------------------------------
    write_fixture(
        fixture_id="062-predicate-missing-tdx-rtmr2",
        title=(
            "DSSE-signed in-toto statement whose SnpTdxMultiPlatformV1 predicate "
            "lacks tdx_measurement.rtmr2 must reject with PREDICATE_MEASUREMENT_INVALID."
        ),
        spec_refs=["5.5"],
        notes=(
            "The recon-found JS bug was extracting ONLY snp_measurement, silently\n"
            "dropping rtmr1 and rtmr2. After the verifier fix, both SDKs must\n"
            "reject if rtmr2 is missing rather than producing a 1- or 2-register\n"
            "measurement. The payload is re-signed by fixturegen so the DSSE\n"
            "signature is valid and the failure is genuinely at predicate parsing."
        ),
        spec=FixtureSpec(
            payload_bytes=mutate_payload_remove_rtmr2(payload),
            workflow_repository=DEFAULT_REPO,
        ),
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=10,
        rejection_code="PREDICATE_MEASUREMENT_INVALID",
    )

    # 063: subject-missing ---------------------------------------------------
    write_fixture(
        fixture_id="063-subject-missing",
        title="DSSE-signed in-toto statement with empty subject must reject.",
        spec_refs=["5.4"],
        notes=(
            "Subject is empty after re-signing. The release-artifact binding\n"
            "cannot be checked. SDKs reject with SUBJECT_MISSING (or some\n"
            "equivalent — list-form acceptable since wording differs)."
        ),
        spec=FixtureSpec(
            payload_bytes=mutate_payload_empty_subject(payload),
            workflow_repository=DEFAULT_REPO,
        ),
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=10,
        rejection_code="SUBJECT_MISSING",
    )

    # 064: integrated-time outside cert validity ----------------------------
    # The leaf cert is short-lived in early 2020. SCT is timestamped inside
    # the cert window. The trust root's CA / CT-log / Rekor key all have
    # valid_from in 2019 so chain + SCT verify successfully. The Rekor
    # integratedTime is 2026, well past cert.NotAfter — that's the check
    # the fixture targets.
    expired_spec = FixtureSpec(
        payload_bytes=payload,
        workflow_repository=DEFAULT_REPO,
        root_valid_from=datetime(2019, 1, 1, tzinfo=timezone.utc),
        root_valid_until=datetime(2030, 1, 1, tzinfo=timezone.utc),
        leaf_valid_from=datetime(2020, 1, 1, tzinfo=timezone.utc),
        leaf_valid_until=datetime(2020, 1, 1, 0, 10, tzinfo=timezone.utc),
        sct_timestamp=datetime(2020, 1, 1, 0, 1, tzinfo=timezone.utc),
        integrated_time=datetime(2026, 1, 1, 0, 2, tzinfo=timezone.utc),
        rekor_valid_from=datetime(2019, 1, 1, tzinfo=timezone.utc),
        ctlog_valid_from=datetime(2019, 1, 1, tzinfo=timezone.utc),
    )
    write_fixture(
        fixture_id="064-rekor-integrated-time-outside-cert-validity",
        title=(
            "Rekor integratedTime outside the leaf cert's validity window must reject."
        ),
        spec_refs=["5.2"],
        notes=(
            "Leaf cert is valid 2020-01-01T00:00:00Z to 2020-01-01T00:10:00Z.\n"
            "The Rekor entry's integratedTime is 2026-01-01T00:02:00Z — well past\n"
            "the cert's NotAfter. Rust explicitly checks integratedTime against\n"
            "the cert window. JS may surface this as REKOR_INCLUSION_INVALID or\n"
            "as CERT_EXPIRED depending on internal check order; list-form accepts."
        ),
        spec=expired_spec,
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=10,
        rejection_code="CERT_EXPIRED",
    )

    # 065: SCT_INSUFFICIENT — leaf cert has zero SCTs ------------------------
    write_fixture(
        fixture_id="065-cert-no-scts",
        title="Leaf cert with zero embedded SCTs must reject with SCT_INSUFFICIENT.",
        spec_refs=["5.2"],
        notes=(
            "SPEC §5.2 #4 requires at least 1 valid SCT. fixturegen embeds an\n"
            "empty SCT list extension; both SDKs must reject."
        ),
        spec=FixtureSpec(
            payload_bytes=payload,
            workflow_repository=DEFAULT_REPO,
            num_scts=0,
        ),
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=10,
        rejection_code="SCT_INSUFFICIENT",
    )

    # 066: SCT_DUPLICATE_LOG — leaf cert has 2 SCTs from same log -----------
    write_fixture(
        fixture_id="066-cert-duplicate-sct-log",
        title=(
            "Leaf cert with two SCTs from the same CT log must reject — replay-amplification guard."
        ),
        spec_refs=["5.2"],
        notes=(
            "Both SCTs are signed by the same fixturegen CT log key (same log_id).\n"
            "Rust's verifier explicitly rejects duplicate log ids before counting\n"
            "SCTs (so threshold > 1 can't be trivially inflated). JS / sigstore-\n"
            "browser may or may not do this check; if it accepts duplicates this\n"
            "is a real divergence to fix in JS, not a fixture bug."
        ),
        spec=FixtureSpec(
            payload_bytes=payload,
            workflow_repository=DEFAULT_REPO,
            num_scts=2,
        ),
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=10,
        rejection_code="SCT_DUPLICATE_LOG",
    )

    print("Wrote synthetic fixtures:")
    for d in sorted(VECTORS_DIR.iterdir()):
        if d.is_dir() and d.name.startswith(("06",)):
            print(f"  {d.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
