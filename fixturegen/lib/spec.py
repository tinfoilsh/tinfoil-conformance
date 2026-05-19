"""High-level orchestrator: spec dataclass + build_bundle_and_trust_root entry."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from . import fulcio, rekor, trust_root
from .bundle import build_bundle
from .dsse import SignedEnvelope, sign_envelope
from .fulcio import LeafCertSpec, build_leaf_final, build_leaf_pre_sct, build_root_ca
from .keys import P256KeyPair
from .sct import make_sct


@dataclass
class FixtureSpec:
    """Inputs for one synthetic Sigstore bundle.

    The shape is deliberately small — every field has either a meaningful
    default or is required.
    """

    # in-toto payload to sign in the DSSE envelope. Caller-supplied so the
    # same fixturegen run can produce fixtures whose only delta is the cert
    # ID extensions while sharing the payload (typical case for crafted-cert
    # fixtures).
    payload_bytes: bytes
    payload_type: str = "application/vnd.in-toto+json"

    # Fulcio leaf cert identity fields. These drive SDK policy checks.
    oidc_issuer: str = "https://token.actions.githubusercontent.com"
    workflow_repository: str = "tinfoilsh/test-repo"
    workflow_ref: str = "refs/tags/v1.0.0"
    build_signer_uri: str = ""  # auto-derived from repo+ref if empty

    # Validity windows. Defaults give a comfortable past+future range so the
    # synthetic bundle doesn't drift out of validity over fixture lifetime.
    root_valid_from: datetime = field(
        default_factory=lambda: datetime(2024, 1, 1, tzinfo=timezone.utc)
    )
    root_valid_until: datetime = field(
        default_factory=lambda: datetime(2034, 1, 1, tzinfo=timezone.utc)
    )
    leaf_valid_from: datetime = field(
        default_factory=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)
    )
    leaf_valid_until: datetime = field(
        default_factory=lambda: datetime(2026, 1, 1, 0, 10, tzinfo=timezone.utc)
    )
    sct_timestamp: datetime = field(
        default_factory=lambda: datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc)
    )
    # Number of SCTs to embed in the leaf cert. All signed by the same test
    # CT log key (we only have one). 0 → SCT_INSUFFICIENT; 2+ → SCT_DUPLICATE_LOG.
    num_scts: int = 1
    # Number of tlog entries to include in verificationMaterial.tlogEntries.
    # Each is generated in its own tree-size-1 Merkle log, all signed by the
    # same Rekor key. Used to test SDKs that hardcode `exactly 1 tlog entry`
    # vs SDKs that accept `>= 1`.
    num_tlog_entries: int = 1

    # Per-extension knobs for the leaf cert. Defaults emit a full Fulcio-style
    # cert (V1 + V2 OIDC issuer, workflow repo + ref, BuildSignerURI). Setting
    # the omit_* flags to True or the *_override values to non-None lets us
    # construct certs that exercise SDK quirks around which extensions are
    # required, V1-vs-V2 precedence, etc.
    omit_oidc_v1: bool = False
    omit_oidc_v2: bool = False
    omit_workflow_ref_ext: bool = False
    omit_build_signer_uri: bool = False
    # When set, the V1 OIDC issuer carries this value while V2 carries
    # `oidc_issuer`. Used to test SDK V1-vs-V2 precedence.
    oidc_issuer_v1_override: str | None = None
    # Number of DSSE signature entries to emit. Default 1 (real Sigstore
    # always emits one). Setting >1 duplicates the same signature across
    # entries — tests SDKs that hardcode `signatures.len() == 1`.
    num_dsse_signatures: int = 1
    # Number of subject entries in the in-toto payload. Default 1. When >1,
    # the first subject's digest is set to all-zeros (so it mismatches the
    # caller's expected_digest_sha256_hex) while later subjects carry the
    # real digest — SPEC §5.4 says only subject[0] is checked, so SDKs must
    # reject with SUBJECT_DIGEST_MISMATCH.
    num_subjects: int = 1
    # When set, an extra unknown field is added to the in-toto statement
    # before signing. SDKs should tolerate (forward compat).
    extra_statement_field: tuple[str, object] | None = None
    # When set, override the in-toto statement's `_type` field. Lets fixtures
    # probe case-sensitivity / trailing-slash strictness.
    statement_type_override: str | None = None
    # When set, override the in-toto statement's `predicateType` field. The
    # actual predicate content stays the same — fixtures use this to test
    # exact-match enforcement on the type string.
    predicate_type_override: str | None = None
    integrated_time: datetime = field(
        default_factory=lambda: datetime(2026, 1, 1, 0, 2, tzinfo=timezone.utc)
    )

    # Trust-root validity windows. start <= sct_timestamp and start <=
    # integrated_time, so the SDK's key-validity-window checks pass.
    rekor_valid_from: datetime = field(
        default_factory=lambda: datetime(2024, 1, 1, tzinfo=timezone.utc)
    )
    ctlog_valid_from: datetime = field(
        default_factory=lambda: datetime(2024, 1, 1, tzinfo=timezone.utc)
    )

    def derived_build_signer_uri(self) -> str:
        if self.build_signer_uri:
            return self.build_signer_uri
        return (
            f"https://github.com/{self.workflow_repository}"
            f"/.github/workflows/release.yml@{self.workflow_ref}"
        )


@dataclass
class GeneratedFixture:
    bundle: dict[str, Any]
    trust_root: dict[str, Any]


def build_bundle_and_trust_root(spec: FixtureSpec) -> GeneratedFixture:
    # 1. Generate three keypairs: Fulcio root, leaf signer, CT log, Rekor.
    root_key = P256KeyPair.generate()
    leaf_key = P256KeyPair.generate()
    ct_log_key = P256KeyPair.generate()
    rekor_key = P256KeyPair.generate()

    # 2. Issue the Fulcio root CA.
    root = build_root_ca(
        key=root_key,
        not_before=spec.root_valid_from,
        not_after=spec.root_valid_until,
    )

    # 3. Build the leaf without SCT extension to get its TBS bytes.
    # The serial is shared between pre-SCT and final builds so the verifier,
    # which re-encodes the final cert's TBS with the SCT extension stripped,
    # reconstructs the SAME bytes the SCT was signed over.
    import secrets
    leaf_serial = secrets.randbits(159) + 1  # X.509 requires positive, max 20 bytes
    leaf_spec = LeafCertSpec(
        oidc_issuer=spec.oidc_issuer,
        workflow_repository=spec.workflow_repository,
        workflow_ref=spec.workflow_ref,
        build_signer_uri=spec.derived_build_signer_uri(),
        omit_oidc_v1=spec.omit_oidc_v1,
        omit_oidc_v2=spec.omit_oidc_v2,
        omit_workflow_ref_ext=spec.omit_workflow_ref_ext,
        omit_build_signer_uri=spec.omit_build_signer_uri,
        oidc_issuer_v1_override=spec.oidc_issuer_v1_override,
    )
    pre_sct = build_leaf_pre_sct(
        leaf_key=leaf_key,
        root=root,
        spec=leaf_spec,
        not_before=spec.leaf_valid_from,
        not_after=spec.leaf_valid_until,
        serial=leaf_serial,
    )
    issuer_spki = fulcio.issuer_spki_der(root)

    # 4. Compute the SCT(s) over those TBS bytes, signed by the CT log key.
    # Multiple SCTs all come from the same CT log key (we only run one log
    # in fixturegen); that's exactly what triggers SCT_DUPLICATE_LOG in
    # downstream verifiers.
    from datetime import timedelta
    scts = [
        make_sct(
            ct_log_key=ct_log_key,
            issuer_spki_der=issuer_spki,
            tbs_pre_sct_bytes=pre_sct.tbs_certificate_bytes,
            timestamp=spec.sct_timestamp + timedelta(seconds=i),
        )
        for i in range(spec.num_scts)
    ]

    # 5. Build the final leaf cert with the SCT extension included.
    leaf = build_leaf_final(
        leaf_key=leaf_key,
        root=root,
        spec=leaf_spec,
        not_before=spec.leaf_valid_from,
        not_after=spec.leaf_valid_until,
        serial=leaf_serial,
        scts=scts,
    )

    # 6. Optionally mutate the in-toto payload (subjects, extra fields) before
    # signing. The mutation is applied to the JSON-canonical form of the
    # statement, then re-encoded so the DSSE signature covers the final bytes.
    payload_to_sign = _maybe_mutate_payload(spec)

    # Sign the DSSE envelope with the leaf key.
    envelope = sign_envelope(
        signing_key=leaf_key,
        payload_type=spec.payload_type,
        payload=payload_to_sign,
    )

    # 7. Build N Rekor tree-size-1 entries (default 1). Each is a complete
    # tree-size-1 inclusion proof signed by the same Rekor key; they differ
    # only in integratedTime + logIndex so the cert/sig/payload bindings all
    # still match the bundle's DSSE envelope.
    entries = [
        rekor.build_size_1_rekor_entry(
            envelope=envelope,
            leaf_cert_pem=leaf.cert_pem,
            rekor_key=rekor_key,
            integrated_time=spec.integrated_time
            + __import__("datetime").timedelta(seconds=i),
            log_index=i,
        )
        for i in range(spec.num_tlog_entries)
    ]

    # 8. Assemble bundle + matching trust root. `num_dsse_signatures > 1`
    # duplicates the same signature in the envelope's signatures array — tests
    # SDKs that hardcode `signatures.len() == 1`.
    bundle = build_bundle(
        leaf_cert_der=leaf.cert_der,
        envelope=envelope,
        rekor_entries=entries,
        num_dsse_signatures=spec.num_dsse_signatures,
    )
    tr = trust_root.build_trust_root(
        fulcio_root=root,
        ct_log_key=ct_log_key,
        ct_log_valid_from=spec.ctlog_valid_from,
        rekor_key=rekor_key,
        rekor_valid_from=spec.rekor_valid_from,
    )
    return GeneratedFixture(bundle=bundle, trust_root=tr)


def _maybe_mutate_payload(spec: "FixtureSpec") -> bytes:
    """Apply subject-array and extra-field mutations to the in-toto payload
    before signing. Returns the payload bytes to feed into DSSE PAE.
    Re-encodes via JSON.dumps with sorted keys + compact separators so the
    bytes are canonical and stable across regenerations."""
    import json as _json

    if (
        spec.num_subjects == 1
        and spec.extra_statement_field is None
        and spec.statement_type_override is None
        and spec.predicate_type_override is None
    ):
        return spec.payload_bytes

    statement = _json.loads(spec.payload_bytes.decode())
    if spec.statement_type_override is not None:
        statement["_type"] = spec.statement_type_override
    if spec.predicate_type_override is not None:
        statement["predicateType"] = spec.predicate_type_override
    if spec.num_subjects > 1:
        # First subject's digest is zeroed → mismatches caller's expected_digest.
        # Real subject is kept at index 1+ so SPEC §5.4 "check subject[0] only"
        # is the divergence under test.
        canonical = statement["subject"][0]
        zero_subject = _json.loads(_json.dumps(canonical))
        zero_subject["digest"]["sha256"] = "0" * 64
        zero_subject["name"] = canonical["name"] + "-spoof"
        statement["subject"] = [zero_subject] + [
            canonical for _ in range(spec.num_subjects - 1)
        ]
    if spec.extra_statement_field is not None:
        key, value = spec.extra_statement_field
        statement[key] = value
    return _json.dumps(statement, separators=(",", ":"), sort_keys=True).encode()
