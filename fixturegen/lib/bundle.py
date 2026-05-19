"""Sigstore v0.3 bundle assembly."""

from __future__ import annotations

import base64

from .dsse import SignedEnvelope
from .rekor import RekorEntry


def build_bundle(
    *,
    leaf_cert_der: bytes,
    envelope: SignedEnvelope,
    rekor_entries: list[RekorEntry],
    num_dsse_signatures: int = 1,
) -> dict:
    """Build a Sigstore v0.3 bundle dict ready to JSON-serialize.

    Accepts a list of Rekor entries. Real Sigstore bundles always carry
    exactly one; supplying >1 lets the conformance suite expose SDKs that
    differ on multi-entry handling (Rust hardcodes exactly-1; JS via
    sigstore-browser accepts >=1).
    """
    cert_b64 = base64.standard_b64encode(leaf_cert_der).decode()
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": cert_b64},
            "tlogEntries": [
                {
                    "logIndex": str(entry.log_index),
                    "logId": {"keyId": entry.log_id_b64},
                    "kindVersion": {"kind": "dsse", "version": "0.0.1"},
                    "integratedTime": str(entry.integrated_time),
                    "inclusionPromise": {
                        "signedEntryTimestamp": entry.signed_entry_timestamp_b64
                    },
                    "inclusionProof": {
                        "logIndex": str(entry.inclusion_proof_log_index),
                        "rootHash": entry.inclusion_proof_root_hash_b64,
                        "treeSize": str(entry.inclusion_proof_tree_size),
                        "hashes": entry.inclusion_proof_hashes,
                        "checkpoint": {"envelope": entry.checkpoint_envelope},
                    },
                    "canonicalizedBody": entry.canonicalized_body_b64,
                }
                for entry in rekor_entries
            ],
        },
        "dsseEnvelope": {
            "payloadType": envelope.payload_type,
            "payload": envelope.payload_b64,
            # When num_dsse_signatures > 1 we emit identical-signature
            # duplicates. All verify against the same payload + key, but
            # SDKs that hardcode `signatures.len() == 1` will reject.
            "signatures": [
                {"sig": envelope.signature_b64}
                for _ in range(max(num_dsse_signatures, 1))
            ],
        },
    }
