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

    # 6. Sign the DSSE envelope with the leaf key.
    envelope = sign_envelope(
        signing_key=leaf_key,
        payload_type=spec.payload_type,
        payload=spec.payload_bytes,
    )

    # 7. Build the Rekor tree-size-1 entry.
    entry = rekor.build_size_1_rekor_entry(
        envelope=envelope,
        leaf_cert_pem=leaf.cert_pem,
        rekor_key=rekor_key,
        integrated_time=spec.integrated_time,
    )

    # 8. Assemble bundle + matching trust root.
    bundle = build_bundle(
        leaf_cert_der=leaf.cert_der, envelope=envelope, rekor_entry=entry
    )
    tr = trust_root.build_trust_root(
        fulcio_root=root,
        ct_log_key=ct_log_key,
        ct_log_valid_from=spec.ctlog_valid_from,
        rekor_key=rekor_key,
        rekor_valid_from=spec.rekor_valid_from,
    )
    return GeneratedFixture(bundle=bundle, trust_root=tr)
