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


# ---------------------------------------------------------------------------
# Rekor v2 (rekor-tiles) hashedrekord 0.0.2 entries.
#
# A key-signed approval bundle carries hashedrekord 0.0.2 entries whose body
# is the protojson form of the rekor-tiles `Entry` message in RFC 8785
# canonical JSON, and whose checkpoint is a signed note (C2SP tlog-checkpoint)
# whose origin and signer name are the hostname of the log's base URL. The
# verifier rebuilds the body from the bundle (digest of the signed PAE bytes,
# the DSSE signature, the pinned key's SPKI) and checks the inclusion proof
# against the checkpoint root, so the body bytes must be exactly canonical.
#
# References used while implementing:
#   * sigstore-go pkg/verify/tlog.go (reconstructV2EntryHash, hasRekorV1STH)
#   * rekor-tiles pkg/note/note.go (key hashes: ECDSA = sha256(SPKI)[:4],
#     Ed25519 = sha256(origin || "\n" || 0x01 || raw_key)[:4])
#   * RFC 6962 §2.1 (Merkle tree hash and inclusion proof path)

HASHEDREKORD_KIND = "hashedrekord"
HASHEDREKORD_VERSION = "0.0.2"


def build_hashedrekord_v002_body(
    *,
    digest: bytes,
    signature_der: bytes,
    verifier_spki_der: bytes,
    hash_algorithm: str = "SHA2_256",
    key_details: str = "PKIX_ECDSA_P256_SHA_256",
) -> bytes:
    """The canonicalizedBody bytes of a hashedrekord 0.0.2 entry: protojson
    of the rekor-tiles Entry in RFC 8785 canonical form (sorted keys, no
    whitespace — identical for these ASCII-only members)."""
    body = {
        "apiVersion": HASHEDREKORD_VERSION,
        "kind": HASHEDREKORD_KIND,
        "spec": {
            "hashedRekordV002": {
                "data": {
                    "algorithm": hash_algorithm,
                    "digest": base64.standard_b64encode(digest).decode(),
                },
                "signature": {
                    "content": base64.standard_b64encode(signature_der).decode(),
                    "verifier": {
                        "keyDetails": key_details,
                        "publicKey": {
                            "rawBytes": base64.standard_b64encode(verifier_spki_der).decode()
                        },
                    },
                },
            }
        },
    }
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode()


def rfc6962_hash_children(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior node hash: sha256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaf_hashes: list[bytes]) -> bytes:
    """RFC 6962 §2.1 Merkle tree hash over already-hashed leaves."""
    n = len(leaf_hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hashes[0]
    k = _largest_power_of_two_below(n)
    return rfc6962_hash_children(merkle_root(leaf_hashes[:k]), merkle_root(leaf_hashes[k:]))


def merkle_inclusion_proof(leaf_hashes: list[bytes], index: int) -> list[bytes]:
    """RFC 6962 §2.1.1 audit path for leaf `index`, leaf-to-root order (the
    order sigstore-go / transparency-dev `proof.VerifyInclusion` expect)."""
    n = len(leaf_hashes)
    if not 0 <= index < n:
        raise ValueError(f"leaf index {index} outside a tree of {n} leaves")
    if n == 1:
        return []
    k = _largest_power_of_two_below(n)
    if index < k:
        return merkle_inclusion_proof(leaf_hashes[:k], index) + [merkle_root(leaf_hashes[k:])]
    return merkle_inclusion_proof(leaf_hashes[k:], index - k) + [merkle_root(leaf_hashes[:k])]


def _largest_power_of_two_below(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def note_key_hint(log_key, origin: str) -> bytes:
    """The 4-byte key hint a checkpoint signature line carries for `log_key`.

    ECDSA keys hash their SPKI DER; Ed25519 keys follow the signed-note
    standard: sha256(origin || "\\n" || 0x01 || raw 32-byte key)."""
    if hasattr(log_key, "public_raw"):
        return hashlib.sha256(origin.encode() + b"\n\x01" + log_key.public_raw).digest()[:4]
    return hashlib.sha256(log_key.public_der).digest()[:4]


def build_v2_checkpoint_envelope(
    *,
    origin: str,
    tree_size: int,
    root_hash: bytes,
    log_key,
    signer_name: str | None = None,
) -> str:
    """A Rekor v2 signed checkpoint: "<origin>\\n<size>\\n<root_b64>\\n" signed
    as a note by the log key. The origin must NOT carry a " - <treeID>"
    suffix (that marks a Rekor v1 STH) and must equal the hostname of the
    log's trusted-root base URL, which is also the signature line's name."""
    text = f"{origin}\n{tree_size}\n{base64.standard_b64encode(root_hash).decode()}\n"
    if hasattr(log_key, "public_raw"):
        sig = log_key.sign(text.encode())
    else:
        sig = log_key.sign_prehashed_sha256(text.encode())
    hint = note_key_hint(log_key, origin)
    line = f"— {signer_name or origin} {base64.standard_b64encode(hint + sig).decode()}"
    return f"{text}\n{line}\n"


def filler_leaf_hash(origin: str, index: int) -> bytes:
    """A deterministic leaf hash for the other positions of a synthetic tree."""
    return rfc6962_leaf_hash(f"{origin} filler leaf {index}".encode())


def build_rekor_v2_entry(
    *,
    body: bytes,
    log_key,
    log_id: bytes,
    origin: str,
    log_index: int,
    tree_size: int,
    kind: str = HASHEDREKORD_KIND,
    version: str = HASHEDREKORD_VERSION,
) -> dict:
    """One `verificationMaterial.tlogEntries` element (protojson shape) for a
    Rekor v2 entry sitting at `log_index` of a `tree_size`-leaf tree whose
    other leaves are deterministic filler, with a real inclusion proof and a
    checkpoint signed by `log_key`. No integratedTime, no inclusionPromise."""
    leaves = [filler_leaf_hash(origin, i) for i in range(tree_size)]
    leaves[log_index] = rfc6962_leaf_hash(body)
    root = merkle_root(leaves)
    proof = merkle_inclusion_proof(leaves, log_index)
    return {
        "logIndex": str(log_index),
        "logId": {"keyId": base64.standard_b64encode(log_id).decode()},
        "kindVersion": {"kind": kind, "version": version},
        "inclusionProof": {
            "logIndex": str(log_index),
            "rootHash": base64.standard_b64encode(root).decode(),
            "treeSize": str(tree_size),
            "hashes": [base64.standard_b64encode(h).decode() for h in proof],
            "checkpoint": {
                "envelope": build_v2_checkpoint_envelope(
                    origin=origin, tree_size=tree_size, root_hash=root, log_key=log_key
                )
            },
        },
        "canonicalizedBody": base64.standard_b64encode(body).decode(),
    }
