"""Sigstore v0.3 bundle assembly."""

from __future__ import annotations

import base64
from collections.abc import Sequence

from .dsse import SignedEnvelope
from .rekor import RekorEntry


def _tlog_entry(entry: RekorEntry) -> dict:
    e: dict = {
        "logIndex": str(entry.log_index),
        "logId": {"keyId": entry.log_id_b64},
        "kindVersion": {"kind": entry.kind, "version": entry.version},
    }
    if entry.integrated_time is not None:
        e["integratedTime"] = str(entry.integrated_time)
    if entry.signed_entry_timestamp_b64 is not None:
        e["inclusionPromise"] = {"signedEntryTimestamp": entry.signed_entry_timestamp_b64}
    e["inclusionProof"] = {
        "logIndex": str(entry.inclusion_proof_log_index),
        "rootHash": entry.inclusion_proof_root_hash_b64,
        "treeSize": str(entry.inclusion_proof_tree_size),
        "hashes": entry.inclusion_proof_hashes,
        "checkpoint": {"envelope": entry.checkpoint_envelope},
    }
    e["canonicalizedBody"] = entry.canonicalized_body_b64
    return e


def build_bundle(
    *,
    leaf_cert_der: bytes,
    envelope: SignedEnvelope,
    rekor_entries: list[RekorEntry],
    num_dsse_signatures: int = 1,
    rfc3161_timestamps: Sequence[bytes] = (),
) -> dict:
    """Build a Sigstore v0.3 bundle dict ready to JSON-serialize.

    Accepts a list of Rekor entries. Real Sigstore bundles always carry
    exactly one; supplying >1 lets the conformance suite expose SDKs that
    differ on multi-entry handling (Rust hardcodes exactly-1; JS via
    sigstore-browser accepts >=1). `rfc3161_timestamps` are DER TimeStampResp
    tokens over the DSSE signature (required for Rekor v2 entries).
    """
    cert_b64 = base64.standard_b64encode(leaf_cert_der).decode()
    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": cert_b64},
            "tlogEntries": [_tlog_entry(entry) for entry in rekor_entries],
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
    if rfc3161_timestamps:
        bundle["verificationMaterial"]["timestampVerificationData"] = {
            "rfc3161Timestamps": [
                {"signedTimestamp": base64.standard_b64encode(t).decode()}
                for t in rfc3161_timestamps
            ]
        }
    return bundle
