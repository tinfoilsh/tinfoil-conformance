"""Sigstore v0.3 bundle assembly."""

from __future__ import annotations

import base64

from .dsse import SignedEnvelope
from .rekor import RekorEntry


def build_bundle(
    *,
    leaf_cert_der: bytes,
    envelope: SignedEnvelope,
    rekor_entry: RekorEntry,
) -> dict:
    """Build a Sigstore v0.3 bundle dict ready to JSON-serialize.

    Layout matches the production bundle shape consumed by both SDKs:
    `verificationMaterial.certificate.rawBytes`, `tlogEntries[]`,
    `dsseEnvelope.{payloadType, payload, signatures}`.
    """
    cert_b64 = base64.standard_b64encode(leaf_cert_der).decode()
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": cert_b64},
            "tlogEntries": [
                {
                    "logIndex": str(rekor_entry.log_index),
                    "logId": {"keyId": rekor_entry.log_id_b64},
                    "kindVersion": {"kind": "dsse", "version": "0.0.1"},
                    "integratedTime": str(rekor_entry.integrated_time),
                    "inclusionPromise": {
                        "signedEntryTimestamp": rekor_entry.signed_entry_timestamp_b64
                    },
                    "inclusionProof": {
                        "logIndex": str(rekor_entry.inclusion_proof_log_index),
                        "rootHash": rekor_entry.inclusion_proof_root_hash_b64,
                        "treeSize": str(rekor_entry.inclusion_proof_tree_size),
                        "hashes": rekor_entry.inclusion_proof_hashes,
                        "checkpoint": {"envelope": rekor_entry.checkpoint_envelope},
                    },
                    "canonicalizedBody": rekor_entry.canonicalized_body_b64,
                }
            ],
        },
        "dsseEnvelope": {
            "payloadType": envelope.payload_type,
            "payload": envelope.payload_b64,
            "signatures": [{"sig": envelope.signature_b64}],
        },
    }
