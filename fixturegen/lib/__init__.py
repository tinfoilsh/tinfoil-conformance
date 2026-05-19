"""Synthetic Sigstore bundle generator for cross-SDK conformance fixtures.

Builds a full Sigstore v0.3 bundle and matching trust_root.json from a fixture
spec — test Fulcio root, test CT log, test Rekor instance, all under our
control. Used to construct fixtures that require signed material (crafted
workflow ref, wrong OIDC issuer, duplicate SCT log, etc.) which can't be
produced by mutating real production bundles.

Tree-size-1 Rekor entries only — that keeps Merkle proofs trivial (empty
hashes list, root == leaf) and unlocks every recon-found fixture without
needing a multi-entry log simulation.
"""

from .spec import FixtureSpec, build_bundle_and_trust_root  # noqa: F401
