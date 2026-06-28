"""Rekor entry assembly for a tree-size-1 log.

For a tree of size 1 the inclusion proof is trivial (no sibling hashes; root
hash equals the leaf hash), which lets us produce a fully-verifiable entry
without any multi-entry log simulation.

References used while implementing:
  * tinfoil-rs/src/verifier/sigstore/rekor.rs (verify side)
  * tinfoil-rs/src/verifier/sigstore/checkpoint.rs (sumdb-note format)
  * RFC 6962 §2.1 (leaf hash = sha256(0x00 || data))
  * Rekor dsse v0.0.1 schema (canonicalizedBody shape)
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .dsse import SignedEnvelope
from .keys import P256KeyPair


@dataclass
class RekorEntry:
    """Everything needed to populate one `verificationMaterial.tlogEntries` entry."""

    log_index: int
    log_id_b64: str
    integrated_time: int
    canonicalized_body_b64: str
    signed_entry_timestamp_b64: str   # may be a placeholder; Rust doesn't verify
    inclusion_proof_root_hash_b64: str
    inclusion_proof_tree_size: int
    inclusion_proof_log_index: int
    inclusion_proof_hashes: list[str] = field(default_factory=list)
    checkpoint_envelope: str = ""


def build_dsse_canonicalized_body(
    *,
    envelope: SignedEnvelope,
    cert_pem: str,
) -> bytes:
    """Build the canonicalizedBody bytes for a Rekor dsse v0.0.1 entry.

    The body is a Rekor-canonical JSON document describing the DSSE envelope
    (envelopeHash, payloadHash, signatures + verifier-cert). Whitespace
    matters because the leaf hash is sha256(0x00 || body_bytes); the SDK
    re-computes it from these exact bytes.
    """
    # envelopeHash: sha256 of the canonical JSON form of {payload, payloadType, signatures}
    # Rekor uses a specific canonicalization. From inspecting real bundles, the
    # envelope JSON is keys-sorted, no whitespace, with `signatures[].sig` and
    # `payload` (base64) and `payloadType` strings.
    envelope_json = json.dumps(
        {
            "payload": envelope.payload_b64,
            "payloadType": envelope.payload_type,
            "signatures": [{"sig": envelope.signature_b64}],
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    envelope_hash = hashlib.sha256(envelope_json).hexdigest()
    payload_hash = hashlib.sha256(envelope.payload_bytes).hexdigest()

    body = {
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "envelopeHash": {"algorithm": "sha256", "value": envelope_hash},
            "payloadHash": {"algorithm": "sha256", "value": payload_hash},
            "signatures": [
                {
                    "signature": envelope.signature_b64,
                    "verifier": base64.standard_b64encode(cert_pem.encode()).decode(),
                }
            ],
        },
    }
    # Sort keys, no whitespace — Rekor's canonical form.
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode()


def rfc6962_leaf_hash(canonicalized_body: bytes) -> bytes:
    """RFC 6962 leaf hash: sha256(0x00 || data)."""
    return hashlib.sha256(b"\x00" + canonicalized_body).digest()


def build_checkpoint_envelope(
    *,
    origin: str,
    name: str,
    tree_size: int,
    root_hash: bytes,
    rekor_key: P256KeyPair,
) -> str:
    """Build a sumdb-note style signed checkpoint envelope.

    Body format:    "<origin>\\n<tree_size>\\n<root_hash_b64>\\n"
    Signature:      ECDSA P-256 DER over the body bytes (SHA-256 internal).
    Envelope:       "<body>\\n— <name> <base64(4_byte_hint || DER_sig)>\\n"

    Rust's SignedCheckpoint::decode splits on the first "\\n\\n", and verifies
    against marshal() (which reproduces the body exactly). The 4-byte key-hint
    prefix is parsed but not checked, so any 4 bytes work — we use the first
    4 bytes of the Rekor key's log id for cleanliness.
    """
    body = f"{origin}\n{tree_size}\n{base64.standard_b64encode(root_hash).decode()}\n"
    sig_der = rekor_key.sign_prehashed_sha256(body.encode())
    hint = rekor_key.log_id[:4]
    sig_b64 = base64.standard_b64encode(hint + sig_der).decode()
    return f"{body}\n— {name} {sig_b64}\n"


def build_signed_entry_timestamp(
    *,
    rekor_key: P256KeyPair,
    canonicalized_body: bytes,
    integrated_time: int,
    log_index: int,
) -> str:
    """SET (signedEntryTimestamp) signature over the JSON-canonical form of
    {body, integratedTime, logID, logIndex}, sorted keys, no whitespace.

    logID is hex (lowercase) of the Rekor key id. logIndex/integratedTime are
    JSON integers. body is the base64 of canonicalizedBody.

    Note: tinfoil-rs doesn't currently verify the SET (only the checkpoint
    signature + Merkle inclusion). JS via @freedomofpress/sigstore-browser
    may; we produce a real one to be safe."""
    payload = json.dumps(
        {
            "body": base64.standard_b64encode(canonicalized_body).decode(),
            "integratedTime": int(integrated_time),
            "logID": rekor_key.log_id.hex(),
            "logIndex": int(log_index),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    sig = rekor_key.sign_prehashed_sha256(payload)
    return base64.standard_b64encode(sig).decode()


def build_size_1_rekor_entry(
    *,
    envelope: SignedEnvelope,
    leaf_cert_pem: str,
    rekor_key: P256KeyPair,
    # The checkpoint signer NAME must match the hostname of the trust root's
    # tlog baseUrl — sigstore-go's NewNoteVerifier derives the expected signer
    # name from baseUrl.Hostname() and rejects mismatches.
    #
    # The checkpoint ORIGIN (note line 0) must additionally carry a numeric
    # tree-ID suffix in the real-Rekor "<host> - <treeID>" form. sigstore-go
    # classifies a tlog entry as Rekor v1 (STH inclusion proof) vs Rekor v2
    # (rekor-tiles) via treeIDSuffixRegex = `.* - [0-9]+$` on the origin line
    # (pkg/verify/tlog.go: hasRekorV1STH). Our entries are v1 tree-size-1
    # inclusion proofs, so the origin MUST match that regex or v1.2.x routes
    # them through the v2 rekor-tiles hash reconstruction and rejects them with
    # REKOR_INCLUSION_INVALID. The treeID value itself is cosmetic (it is not
    # the tree SIZE — that is the checkpoint body's second line).
    rekor_origin: str = "tinfoil-conformance.test - 1",
    rekor_signer_name: str = "tinfoil-conformance.test",
    log_index: int = 0,
    integrated_time: datetime,
) -> RekorEntry:
    """Build a Rekor tlog entry for a single-leaf tree (root_hash == leaf_hash)."""
    body = build_dsse_canonicalized_body(envelope=envelope, cert_pem=leaf_cert_pem)
    leaf = rfc6962_leaf_hash(body)
    body_b64 = base64.standard_b64encode(body).decode()
    int_time = int(integrated_time.replace(tzinfo=timezone.utc).timestamp()) \
        if integrated_time.tzinfo is None else int(integrated_time.timestamp())

    checkpoint = build_checkpoint_envelope(
        origin=rekor_origin,
        name=rekor_signer_name,
        tree_size=1,
        root_hash=leaf,
        rekor_key=rekor_key,
    )
    set_b64 = build_signed_entry_timestamp(
        rekor_key=rekor_key,
        canonicalized_body=body,
        integrated_time=int_time,
        log_index=log_index,
    )

    return RekorEntry(
        log_index=log_index,
        log_id_b64=base64.standard_b64encode(rekor_key.log_id).decode(),
        integrated_time=int_time,
        canonicalized_body_b64=body_b64,
        signed_entry_timestamp_b64=set_b64,
        inclusion_proof_root_hash_b64=base64.standard_b64encode(leaf).decode(),
        inclusion_proof_tree_size=1,
        # For a tree-size-1 Merkle log there's exactly one leaf at index 0;
        # the bundle-level `log_index` is just metadata.
        inclusion_proof_log_index=0,
        inclusion_proof_hashes=[],
        checkpoint_envelope=checkpoint,
    )
