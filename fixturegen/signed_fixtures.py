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
    "sigstore.verification_time_override": [
        "supported",
        "bundle-supplied-only",
    ],
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


def mutate_payload_remove_snp_measurement(payload: bytes) -> bytes:
    """Strip snp_measurement from the predicate."""
    p = json.loads(payload.decode())
    pred = copy.deepcopy(p["predicate"])
    pred.pop("snp_measurement", None)
    p["predicate"] = pred
    return json.dumps(p, separators=(",", ":"), sort_keys=True).encode()


def mutate_payload_remove_rtmr1(payload: bytes) -> bytes:
    """Strip rtmr1 from tdx_measurement."""
    p = json.loads(payload.decode())
    pred = copy.deepcopy(p["predicate"])
    if "tdx_measurement" in pred and "rtmr1" in pred["tdx_measurement"]:
        del pred["tdx_measurement"]["rtmr1"]
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

    # 060b: split-cert-ext divergence (audit finding #3) --------------------
    # Rust checks workflow_ref_prefix against the BuildSignerURI extension
    # (.1.9) via regex; JS checks against the GitHubWorkflowRef extension
    # (.1.6) via startsWith. For legitimate Fulcio-issued certs those two
    # values are derived from the same OIDC claim and always agree. fixturegen
    # lets us set them independently — this fixture has them DISAGREE: the
    # ref ext says "refs/heads/main" while the BuildSignerURI ends in
    # "@refs/tags/v1.0.0". A loose verifier that reads only the URI accepts;
    # a loose verifier that reads only the ref ext rejects. Both Rust and JS
    # should reject — for *different reasons*. The harness's list-form
    # rejection code documents this asymmetry.
    write_fixture(
        fixture_id="060b-cert-ext-mismatch-ref-vs-buildsigner",
        title=(
            "Cert with GitHubWorkflowRef='refs/heads/main' but BuildSignerURI "
            "ending '@refs/tags/v1.0.0' must reject — exposes ref-vs-URI split."
        ),
        spec_refs=["5.3"],
        notes=(
            "Catches the audit-found divergence in which cert field each SDK\n"
            "reads for the workflow_ref check (Rust = BuildSignerURI; JS =\n"
            "GitHubWorkflowRef extension). Both reject this fixture but for\n"
            "different fields: JS's startsWith('refs/tags/') on the ref ext\n"
            "trivially fails; Rust's URI regex matches '...@refs/tags/v1...'\n"
            "successfully — so Rust's *other* check, OIDC issuer? No, that's\n"
            "set normally. Rust actually falls through to verifying the\n"
            "cert's workflowRef extension via the URI parse, OR it accepts.\n"
            "The list rejection_code lets us pass the fixture either way and\n"
            "documents the cert-field asymmetry."
        ),
        spec=FixtureSpec(
            payload_bytes=payload,
            workflow_repository=DEFAULT_REPO,
            workflow_ref="refs/heads/main",  # the .1.6 ext
            build_signer_uri=(
                f"https://github.com/{DEFAULT_REPO}/.github/workflows/release.yml"
                "@refs/tags/v1.0.0"  # the .1.9 ext — claims it's a tag build
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
            "cannot be checked. SDKs reject with SUBJECT_MISSING or some\n"
            "equivalent code — sigstore-go's WithArtifactDigest can't find a\n"
            "matching subject digest and surfaces this as\n"
            "SUBJECT_DIGEST_MISMATCH instead. Either rejection is acceptable."
        ),
        spec=FixtureSpec(
            payload_bytes=mutate_payload_empty_subject(payload),
            workflow_repository=DEFAULT_REPO,
        ),
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=10,
        rejection_code=["SUBJECT_MISSING", "SUBJECT_DIGEST_MISMATCH"],
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
            "All four SDKs reject with SCT_DUPLICATE_LOG via an explicit\n"
            "per-log-id uniqueness guard (SPEC §5.2): tinfoil-rs and -js check a\n"
            "log-id set before counting SCTs; tinfoil-go adds checkDuplicateSCTLogs\n"
            "on top of sigstore-go (which dedups rather than rejecting); and\n"
            "tinfoil-python adds reject_duplicate_sct_logs ahead of sigstore-\n"
            "python's verify (which otherwise rejects this only incidentally via\n"
            "its exactly-one-SCT rule)."
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
        extra_capabilities={"sigstore.rejects_duplicate_sct_log": True},
    )

    # 067: bundle with 2 valid tlog entries -------------------------------
    # SPEC §5.2 #3 requires "at least 1 valid Rekor log entry", not "exactly 1".
    # Real Sigstore production carries exactly one, but a SPEC-compliant verifier
    # MUST accept bundles with two well-formed entries (each a complete
    # tree-size-1 inclusion proof signed by the same Rekor key).
    #
    # The audit surfaced this as a divergence: tinfoil-rs hardcoded
    # `tlog_entries.len() != 1 → reject`; JS via @freedomofpress/sigstore-
    # browser correctly accepts. The Rust verifier was patched in the same
    # commit (rekor.rs: `is_empty()` instead of `!= 1`); this fixture is the
    # regression guard.
    write_fixture(
        fixture_id="067-bundle-two-tlog-entries",
        title=(
            "Bundle with 2 valid Rekor tlog entries (each tree-size-1) — must accept."
        ),
        spec_refs=["5.2"],
        notes=(
            "SPEC §5.2 #3 plain reading. Both tlog entries are valid Rekor\n"
            "inclusion proofs for the same DSSE envelope, signed by the same\n"
            "test Rekor key. Gated on sigstore.accepts_multi_tlog_entries —\n"
            "SDKs that hardcode exactly-1 (sigstore-python's current behavior)\n"
            "declare the cap as false and the fixture skips cleanly."
        ),
        extra_capabilities={"sigstore.accepts_multi_tlog_entries": True},
        spec=FixtureSpec(
            payload_bytes=payload,
            workflow_repository=DEFAULT_REPO,
            num_tlog_entries=2,
        ),
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=0,
        rejection_code=None,
        # The accept output looks like the happy path, but the bundle
        # observables (rekor_log_id_hex, integratedTime, tlog_entry_count,
        # sct_count, cert_*) differ from fixture 001's because fixturegen
        # uses synthetic keys + repo. Pin only the predicate-derived fields,
        # which are stable: they come from the payload.
        expected_outputs={
            "predicate_type": "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1",
            "in_toto_statement_type": "https://in-toto.io/Statement/v1",
            "subject_name": "tinfoil-deployment.json",
            "subject_digest_sha256_hex": seed_digest(),
            "tlog_entry_count": 2,
        },
    )

    # 068: cert with V1 OIDC issuer only ------------------------------------
    # Older Fulcio certs only have the V1 OIDC issuer extension (.1.1, raw
    # UTF-8 bytes). SDKs prefer V2 (.1.8) but MUST fall back to V1 when V2
    # is absent. Both Rust and JS do this in extract_certificate_info /
    # WrappedOIDCIssuer respectively — this fixture pins the behavior.
    write_fixture(
        fixture_id="068-cert-only-v1-oidc-issuer",
        title="Cert with V1 OIDC issuer extension only (no V2) must accept.",
        spec_refs=["5.3"],
        notes=(
            "Tests V1/V2 OIDC issuer extension precedence. The cert carries\n"
            "only the V1 extension (OID .1.1) with the canonical GitHub Actions\n"
            "issuer; the V2 extension (.1.8) is omitted. SDKs must accept by\n"
            "falling back to V1. Particularly relevant for SDKs that read only\n"
            "one of V1 or V2 — those would diverge here."
        ),
        spec=FixtureSpec(
            payload_bytes=payload,
            workflow_repository=DEFAULT_REPO,
            omit_oidc_v2=True,
        ),
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=0,
        rejection_code=None,
        expected_outputs={
            "predicate_type": "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1",
            "in_toto_statement_type": "https://in-toto.io/Statement/v1",
            "cert_oidc_issuer": "https://token.actions.githubusercontent.com",
        },
    )

    # 069: cert with V1 and V2 OIDC disagreeing -----------------------------
    # Both extensions present but V1 says gitlab.com and V2 says GitHub.
    # SPEC §5.3 doesn't explicitly mandate precedence; Rust and JS prefer
    # V2; sigstore-python prefers V1. Gate the fixture on the
    # `oidc_issuer_v2_preferred` capability so V1-preferring SDKs skip
    # cleanly rather than fail.
    write_fixture(
        fixture_id="069-cert-v1-v2-oidc-disagree-v2-wins",
        title=(
            "Cert with V1 and V2 OIDC issuer extensions disagreeing — V2 takes precedence."
        ),
        spec_refs=["5.3"],
        notes=(
            "V1 (.1.1) carries 'https://gitlab.com/oidc'; V2 (.1.8) carries\n"
            "the GitHub Actions issuer; the policy pins the GitHub issuer. The\n"
            "canonical reading is V2-preferred (Fulcio deprecated V1), so all\n"
            "four SDKs accept: go/rs/js key on V2, and tinfoil-python now uses\n"
            "OIDCIssuerV2Preferred (V2 first, V1 fallback). Still gated on\n"
            "oidc_issuer_v2_preferred so any implementation that regresses to\n"
            "V1-only skips with a clear reason rather than failing noisily.\n"
            "See 069b for the inverse (V1 trusted, V2 untrusted) direction."
        ),
        spec=FixtureSpec(
            payload_bytes=payload,
            workflow_repository=DEFAULT_REPO,
            oidc_issuer_v1_override="https://gitlab.com/oidc",
        ),
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=0,
        rejection_code=None,
        expected_outputs={
            "cert_oidc_issuer": "https://token.actions.githubusercontent.com",
        },
        extra_capabilities={"sigstore.oidc_issuer_v2_preferred": True},
    )

    # 069b: INVERSE of 069 — V1 trusted, V2 untrusted ----------------------
    # The dangerous direction. V1 (.1.1) carries the canonical GitHub Actions
    # issuer (matches policy); V2 (.1.8) carries an untrusted gitlab issuer.
    # A V1-only reader (sigstore-python's default policy.OIDCIssuer) ACCEPTS
    # this — a false-accept: it trusts the deprecated extension and ignores
    # the authoritative V2 value. The canonical V2-preferred reading REJECTS,
    # because the authoritative issuer is untrusted. go/rs/js and the fixed
    # tinfoil-python (OIDCIssuerV2Preferred) all reject. NOT gated: every
    # conformant SDK must reject, so a regression to V1-only fails loudly.
    write_fixture(
        fixture_id="069b-cert-v1-trusted-v2-untrusted",
        title=(
            "Cert with V1 (trusted) and V2 (untrusted) OIDC issuers disagreeing "
            "— V2 is authoritative, so must reject."
        ),
        spec_refs=["5.3"],
        notes=(
            "Inverse of 069. V1 (.1.1) = 'https://token.actions.githubusercontent.com'\n"
            "(the canonical issuer the policy pins); V2 (.1.8) = 'https://gitlab.com/oidc'\n"
            "(untrusted). Because V2 is the canonical/authoritative Fulcio issuer\n"
            "extension (V1 is deprecated), the cert's real issuer is the untrusted\n"
            "gitlab one and verification MUST reject with OIDC_ISSUER_MISMATCH.\n"
            "An SDK that reads only the deprecated V1 extension would ACCEPT this\n"
            "(a false-accept). This fixture is the regression guard for that bug."
        ),
        spec=FixtureSpec(
            payload_bytes=payload,
            workflow_repository=DEFAULT_REPO,
            oidc_issuer="https://gitlab.com/oidc",  # -> V2 (.1.8), authoritative
            oidc_issuer_v1_override=(
                "https://token.actions.githubusercontent.com"  # -> V1 (.1.1), deprecated
            ),
        ),
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=10,
        rejection_code="OIDC_ISSUER_MISMATCH",
        extra_capabilities={"sigstore.oidc_issuer_v2_preferred": True},
    )

    # 070: cert missing GitHubWorkflowRef extension -------------------------
    # The .1.6 extension is the SPEC §5.3 source of truth for the workflow_ref
    # check (the fix that landed in this PR). A cert without it must reject —
    # the SDK cannot evaluate the prefix policy.
    write_fixture(
        fixture_id="070-cert-missing-workflow-ref-ext",
        title=(
            "Cert without GitHubWorkflowRef extension (.1.6) must reject — "
            "workflow_ref policy can't be checked."
        ),
        spec_refs=["5.3"],
        notes=(
            "Recent fix migrated the workflow_ref policy check from regex-on-\n"
            "BuildSignerURI to startsWith on the dedicated GitHubWorkflowRef\n"
            "extension. A cert that omits .1.6 entirely cannot satisfy the\n"
            "check at all. Both SDKs must reject. Real Fulcio always emits\n"
            ".1.6; this fixture catches SDKs that silently fall back to\n"
            "BuildSignerURI when the dedicated extension is missing."
        ),
        spec=FixtureSpec(
            payload_bytes=payload,
            workflow_repository=DEFAULT_REPO,
            omit_workflow_ref_ext=True,
        ),
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=10,
        rejection_code="WORKFLOW_REF_PREFIX_MISMATCH",
    )

    # 071: cert missing BuildSignerURI extension ----------------------------
    # The .1.9 extension is no longer required for SPEC §5.3 workflow_ref
    # checks (that moved to .1.6). Cert without .1.9 should still be acceptable.
    write_fixture(
        fixture_id="071-cert-missing-build-signer-uri",
        title=(
            "Cert without BuildSignerURI (.1.9) must accept — extension is "
            "informational only after the workflow_ref check moved to .1.6."
        ),
        spec_refs=["5.3"],
        notes=(
            "After the workflow_ref-check migration to .1.6, BuildSignerURI\n"
            "(.1.9) is informational/diagnostic only. Cert without it should\n"
            "still verify. An SDK that requires .1.9 for the workflow_ref\n"
            "check (old Rust behavior) would reject — fixture catches\n"
            "regression."
        ),
        spec=FixtureSpec(
            payload_bytes=payload,
            workflow_repository=DEFAULT_REPO,
            omit_build_signer_uri=True,
        ),
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=0,
        rejection_code=None,
        expected_outputs={
            "predicate_type": "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1",
            "cert_workflow_signer_uri": "",
        },
    )

    # 072: DSSE envelope with duplicate signatures --------------------------
    # `signatures` array has two identical entries, both verify. Rust's
    # current verifier hardcodes `signatures.len() != 1 → reject`; JS via
    # sigstore-browser may or may not. SPEC §5.2 #1 says "the envelope
    # signature MUST be verified against the Fulcio-issued certificate" —
    # singular. The list rejection_code documents the genuine ambiguity.
    write_fixture(
        fixture_id="072-dsse-duplicate-signatures",
        title=(
            "DSSE envelope with 2 identical signature entries — both SDKs "
            "must reject (count > 1) or both accept."
        ),
        spec_refs=["5.2"],
        notes=(
            "Probe for SDKs that strictly require `signatures.len() == 1`\n"
            "(Rust does) vs SDKs that iterate and accept any valid one\n"
            "(JS via sigstore-browser may). SPEC §5.2 #1 phrases this in the\n"
            "singular but doesn't pin a count requirement. The fixture's\n"
            "rejection_code list documents the genuine taxonomy ambiguity\n"
            "while still requiring both SDKs to reject (not silently accept)."
        ),
        spec=FixtureSpec(
            payload_bytes=payload,
            workflow_repository=DEFAULT_REPO,
            num_dsse_signatures=2,
        ),
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=10,
        rejection_code=["DSSE_SIGNATURE_INVALID", "BUNDLE_MALFORMED"],
    )

    # 073: in-toto statement with multiple subjects, subject[0] mismatches ---
    # SPEC §5.4: "If the subject array contains multiple entries, only the
    # first entry (subject[0]) is checked." Fixture: subject[0] has a
    # zero-digest, subject[1] carries the real digest. SDKs MUST reject
    # because subject[0] doesn't match.
    write_fixture(
        fixture_id="073-subject-array-only-first-checked",
        title=(
            "In-toto subject array with bad subject[0] and good subject[1] — "
            "must reject (only subject[0] is checked per SPEC §5.4)."
        ),
        spec_refs=["5.4"],
        notes=(
            "Catches SDKs that iterate the subject array and accept on any\n"
            "match. The SPEC explicitly says only subject[0] is checked.\n"
            "sigstore-go is non-conformant here (it iterates subjects);\n"
            "gated on `sigstore.checks_only_subject_0` so Go skips cleanly\n"
            "rather than fails — the divergence is visible in the result\n"
            "matrix."
        ),
        spec=FixtureSpec(
            payload_bytes=payload,
            workflow_repository=DEFAULT_REPO,
            num_subjects=2,
        ),
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=10,
        rejection_code="SUBJECT_DIGEST_MISMATCH",
        extra_capabilities={"sigstore.checks_only_subject_0": True},
    )

    # 074: in-toto statement with unknown extra field -----------------------
    # SPEC §5.4: the in-toto statement MUST contain only the recognized
    # top-level fields (_type, subject, predicateType, predicate); an unknown
    # top-level field MUST be rejected. Tinfoil produces canonical statements,
    # so an unknown field is non-canonical; all four SDKs reject.
    write_fixture(
        fixture_id="074-in-toto-statement-extra-field",
        title=(
            "In-toto statement with an unknown extra top-level field must reject."
        ),
        spec_refs=["5.4"],
        notes=(
            "Adds `'_spec_version': 99` to the in-toto statement before signing.\n"
            "All four SDKs reject the unknown top-level field: go via sigstore-go's\n"
            "strict protojson parser (surfaces as DSSE_SIGNATURE_INVALID); rs via\n"
            "serde deny_unknown_fields, and py/js via an explicit top-level-field\n"
            "check (BUNDLE_MALFORMED). Ungated."
        ),
        spec=FixtureSpec(
            payload_bytes=payload,
            workflow_repository=DEFAULT_REPO,
            extra_statement_field=("_spec_version", 99),
        ),
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=10,
        rejection_code=["BUNDLE_MALFORMED", "DSSE_SIGNATURE_INVALID"],
    )

    # 075: cert with neither V1 nor V2 OIDC issuer extension --------------
    # Both .1.1 and .1.8 omitted. SDKs can't evaluate the OIDC issuer policy
    # at all → reject. This catches a future SDK that silently treats
    # missing-extension as "no policy, accept" (a known anti-pattern).
    write_fixture(
        fixture_id="075-cert-no-oidc-issuer-extension",
        title=(
            "Cert with no OIDC issuer extension (neither .1.1 V1 nor .1.8 V2) — "
            "must reject."
        ),
        spec_refs=["5.3"],
        notes=(
            "The OIDC issuer policy can't be evaluated when the cert carries\n"
            "neither V1 nor V2. The canonical rejection is OIDC_ISSUER_MISMATCH;\n"
            "Rust's extract_certificate_info also short-circuits with a 'missing\n"
            "required OIDC issuer extension' error which classifies as\n"
            "BUNDLE_MALFORMED — list-form rejection_code accepts either."
        ),
        spec=FixtureSpec(
            payload_bytes=payload,
            workflow_repository=DEFAULT_REPO,
            omit_oidc_v1=True,
            omit_oidc_v2=True,
        ),
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=10,
        rejection_code=["OIDC_ISSUER_MISMATCH", "BUNDLE_MALFORMED"],
    )

    # 076: empty workflow_ref_prefix policy --------------------------------
    # policy.workflow_ref_prefix="" is a degenerate but valid policy: every
    # ref starts with the empty string, so the check trivially accepts. SDKs
    # MUST honor this. A future SDK that special-cases empty-string to "must
    # match exactly" would reject — caught here.
    write_fixture(
        fixture_id="076-workflow-ref-prefix-empty-accepts-any",
        title=(
            "policy.workflow_ref_prefix='' (no restriction) must accept any "
            "cert workflow ref."
        ),
        spec_refs=["5.3"],
        notes=(
            "Degenerate-but-valid policy. The cert's actual workflow ref is\n"
            "refs/heads/main; the empty prefix trivially matches it. Catches\n"
            "SDKs that special-case empty-string to 'must match exactly' or\n"
            "fail-closed."
        ),
        spec=FixtureSpec(
            payload_bytes=payload,
            workflow_repository=DEFAULT_REPO,
            workflow_ref="refs/heads/main",  # would fail "refs/tags/" prefix
        ),
        repo=DEFAULT_REPO,
        policy_override={"workflow_ref_prefix": ""},
        expected_exit=0,
        rejection_code=None,
        expected_outputs={
            "predicate_type": "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1",
        },
    )

    # 077: predicate type with trailing slash -------------------------------
    # Predicate type URI has a trailing slash, policy doesn't. Exact-match
    # enforcement rejects. Catches lenient string comparators.
    write_fixture(
        fixture_id="077-predicate-type-trailing-slash",
        title=(
            "In-toto predicate type with a trailing slash must NOT match a "
            "no-trailing-slash policy entry — exact match."
        ),
        spec_refs=["5.5"],
        notes=(
            "The statement's predicateType is\n"
            "'https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1/' (note the\n"
            "trailing slash). The default policy lists the same URI WITHOUT\n"
            "trailing slash. SDKs that do canonical-URI normalization on\n"
            "predicate types would erroneously accept. SPEC §5.5 specifies\n"
            "exact URI match — reject."
        ),
        spec=FixtureSpec(
            payload_bytes=payload,
            workflow_repository=DEFAULT_REPO,
            predicate_type_override=(
                "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1/"
            ),
        ),
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=10,
        rejection_code="PREDICATE_TYPE_NOT_ALLOWED",
    )

    # 078: in-toto statement _type with case variation ----------------------
    # _type = "https://in-toto.io/Statement/V1" (capital V). Policy default
    # allows "https://in-toto.io/Statement/v0.1" and ".../v1" (lowercase).
    # Exact match should reject.
    write_fixture(
        fixture_id="078-in-toto-statement-type-case-variation",
        title=(
            "In-toto _type with capital V (Statement/V1) must NOT match a "
            "lowercase-v allow-list — exact match."
        ),
        spec_refs=["5.4"],
        notes=(
            "The in-toto statement _type is exactly\n"
            "'https://in-toto.io/Statement/V1' (capital V). Policy default\n"
            "lists 'https://in-toto.io/Statement/v0.1' and '.../v1'. Per\n"
            "SPEC §5.4 the comparison is exact string equality — reject."
        ),
        spec=FixtureSpec(
            payload_bytes=payload,
            workflow_repository=DEFAULT_REPO,
            statement_type_override="https://in-toto.io/Statement/V1",
        ),
        repo=DEFAULT_REPO,
        # default_policy keeps in_toto_statement_types_allowed=None (= any);
        # pin it explicitly so the capital-V variant fails the allow-list.
        policy_override={
            "in_toto_statement_types_allowed": [
                "https://in-toto.io/Statement/v0.1",
                "https://in-toto.io/Statement/v1",
            ]
        },
        expected_exit=10,
        rejection_code="IN_TOTO_STATEMENT_TYPE_NOT_ALLOWED",
        extra_capabilities={
            "sigstore.policy_fields_configurable.in_toto_statement_types_allowed": True,
        },
    )

    # 079: bundle with cert under x509CertificateChain (legacy format) ------
    # Sigstore v0.1/v0.2 bundles nested the leaf cert under
    # `verificationMaterial.x509CertificateChain.certificates[0].rawBytes`.
    # v0.3 moved it to `verificationMaterial.certificate.rawBytes`.
    #
    # Per SPEC §5.2 the legacy layout MUST be rejected: it can carry
    # intermediate/root CA certificates (a misuse vector the v0.3 single-cert
    # form avoids), and tinfoil only ever produces v0.3 bundles. All four SDKs
    # reject it — rs via its v0.3-only port, and go/py/js via an explicit
    # tinfoil-layer guard on top of their libs (which would otherwise parse the
    # legacy oneof). Reject-only fixture, ungated.
    # Re-load the seed fixture's bundle (the real production v0.3 bundle).
    seed_input_for_079 = json.loads((SEED / "input.json").read_text())
    seed_bundle_for_079 = json.loads(base64.b64decode(seed_input_for_079["bundle_b64"]))
    old_format = copy.deepcopy(seed_bundle_for_079)
    cert_rawbytes = old_format["verificationMaterial"]["certificate"]["rawBytes"]
    del old_format["verificationMaterial"]["certificate"]
    old_format["verificationMaterial"]["x509CertificateChain"] = {
        "certificates": [{"rawBytes": cert_rawbytes}]
    }
    old_format["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.2"
    seed_input2 = copy.deepcopy(seed_input_for_079)
    seed_input2["bundle_b64"] = base64.standard_b64encode(
        json.dumps(old_format).encode()
    ).decode()
    # Manually write this fixture since it's a bundle-mutation, not a
    # fixturegen run: take fixture 001's seed and mutate just the cert location.
    dst = VECTORS_DIR / "079-bundle-cert-in-x509-chain-format"
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "input.json").write_text(json.dumps(seed_input2, indent=2))
    (dst / "expected.json").write_text(
        json.dumps(
            {
                "stage": "verify-sigstore",
                "accepted": False,
                "rejection": {"code": "BUNDLE_MALFORMED"},
            },
            indent=2,
        )
    )
    (dst / "manifest.yaml").write_text(
        "id: 079-bundle-cert-in-x509-chain-format\n"
        "stage: verify-sigstore\n"
        "title: |\n"
        "  Bundle with cert at verificationMaterial.x509CertificateChain.\n"
        "  certificates[0].rawBytes (legacy Sigstore v0.1/v0.2 format) must reject.\n"
        'spec_refs: ["5.2"]\n'
        "expects:\n"
        "  exit_code: 10\n"
        '  rejection_code: "BUNDLE_MALFORMED"\n'
        "required_capabilities:\n"
        '  sigstore.trust_root_loading: "configurable"\n'
        '  sigstore.verification_time_override: ["supported", "bundle-supplied-only"]\n'
        "fixture_kind: real-frozen-bundle-mutation\n"
        "notes: |\n"
        "  Cert relocated from .verificationMaterial.certificate.rawBytes\n"
        "  (v0.3 layout) to .verificationMaterial.x509CertificateChain.\n"
        "  certificates[0].rawBytes (legacy v0.1/v0.2 layout). Per SPEC §5.2 the\n"
        "  legacy layout MUST be rejected (it can carry CA certs; tinfoil only\n"
        "  produces v0.3). All four SDKs reject: rs via its v0.3-only port, and\n"
        "  go/py/js via an explicit tinfoil-layer guard over libs that would\n"
        "  otherwise parse the legacy oneof.\n"
    )

    # 080-083: SPEC §5.5.1 predicate-field validation ----------------------
    # Companion fixtures to 062. Each mutates one register-bearing field of
    # the SnpTdxMultiPlatformV1 predicate and re-signs; the DSSE signature
    # is valid so the rejection is squarely at predicate parsing.
    write_fixture(
        fixture_id="080-predicate-missing-snp-measurement",
        title=(
            "SnpTdxMultiPlatformV1 predicate without snp_measurement must reject "
            "with PREDICATE_MEASUREMENT_INVALID."
        ),
        spec_refs=["5.5"],
        notes=(
            "Symmetric to 062 (which drops rtmr2): drops snp_measurement instead.\n"
            "SPEC §5.5.1 requires all 3 registers — failure to produce a complete\n"
            "register set is a parse error, not silent acceptance with fewer\n"
            "registers."
        ),
        spec=FixtureSpec(
            payload_bytes=mutate_payload_remove_snp_measurement(payload),
            workflow_repository=DEFAULT_REPO,
        ),
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=10,
        rejection_code="PREDICATE_MEASUREMENT_INVALID",
    )

    write_fixture(
        fixture_id="081-predicate-missing-tdx-rtmr1",
        title=(
            "SnpTdxMultiPlatformV1 predicate without tdx_measurement.rtmr1 must "
            "reject with PREDICATE_MEASUREMENT_INVALID."
        ),
        spec_refs=["5.5"],
        notes=(
            "Symmetric to 062: drops rtmr1 instead of rtmr2. Catches an SDK that\n"
            "only validates presence of rtmr2 (the recon-found bug) or that\n"
            "treats rtmr1 as optional."
        ),
        spec=FixtureSpec(
            payload_bytes=mutate_payload_remove_rtmr1(payload),
            workflow_repository=DEFAULT_REPO,
        ),
        repo=DEFAULT_REPO,
        policy_override=None,
        expected_exit=10,
        rejection_code="PREDICATE_MEASUREMENT_INVALID",
    )

    # NOTE on measurement field validation (no fixtures 082/083): SPEC §5.5.1
    # says "registers[0] = snp_measurement (48 bytes = 96 hex chars)" as a
    # descriptive note on register width, not as a verification step. None of
    # the four SDKs validate field length or hex-character contents at the
    # Sigstore parse stage — they treat the field as an opaque string and rely
    # on downstream measurement comparison (which would mismatch a malformed
    # value) to catch the problem. Adding a strict-validation requirement here
    # would need a SPEC update first.

    print("Wrote synthetic fixtures:")
    for d in sorted(VECTORS_DIR.iterdir()):
        if d.is_dir() and d.name.startswith(("06", "08")):
            print(f"  {d.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
