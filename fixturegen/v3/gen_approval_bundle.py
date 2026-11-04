#!/usr/bin/env python3
"""Generate the key-signed approval-bundle fixtures (vectors/v3/approval-bundle/)
for the `v3-authenticate-approval` stage (CONFORMANCE_ADAPTER_SPEC §2.1).

A key-signed approval is a Sigstore v0.3 DSSE bundle whose verification
material is a public-key *hint* (no certificate) naming one of a verifier's
pinned signing keys, witnessed by one to eight Rekor v2 hashedrekord 0.0.2
inclusion proofs. Nothing in it states a time, so there are no integrated
times, no inclusion promises and no RFC 3161 timestamps inside the bundle.

Every fixture pairs a bundle with the trusted root (transparency logs only)
and the pinned signing keys the adapter must use, and the artifact digest the
statement's subjects must name. The happy bundle verifies; every rejection is
a single-field change away from it and attributes to PROVENANCE_REJECTED.
Emits the shared fixture format {id, stage, input, expected}; each vector
function's docstring says what it exercises.

Deterministic: fixed key secrets, RFC 6979 ECDSA nonces, fixed times, so
re-running changes nothing.

Run from the repo root:  uv run --with cryptography fixturegen/v3/gen_approval_bundle.py
"""

import base64
import copy
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "fixturegen"))

from lib import rekor, trust_root, tsa  # noqa: E402
from lib.dsse import compute_pae  # noqa: E402
from lib.keys import Ed25519KeyPair, P256KeyPair  # noqa: E402

STAGE = "v3-authenticate-approval"
OUT_DIR = REPO_ROOT / "vectors" / "v3" / "approval-bundle"

BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://tinfoil.sh/predicate/approval-layer-vector/v1"

# Fixed secrets -> reproducible keys. Distinct, nonzero, below the P-256 order.
_SECRETS = {
    "signing_a": 0x6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A6A,
    "signing_b": 0x6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B,
    "unpinned": 0x6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C6C,
    "log_ecdsa": 0x7D7D7D7D7D7D7D7D7D7D7D7D7D7D7D7D7D7D7D7D7D7D7D7D7D7D7D7D7D7D7D7D,
    "unknown_log": 0x7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E,
    "tsa_root": 0x7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F,
    "tsa_leaf": 0x8080808080808080808080808080808080808080808080808080808080808080,
}
LOG_ED25519_SEED = bytes.fromhex("8f" * 32)

KEY_A = P256KeyPair.from_secret(_SECRETS["signing_a"])
KEY_B = P256KeyPair.from_secret(_SECRETS["signing_b"])
KEY_UNPINNED = P256KeyPair.from_secret(_SECRETS["unpinned"])
PINNED_KEYS = [KEY_A, KEY_B]

LOG_ECDSA = P256KeyPair.from_secret(_SECRETS["log_ecdsa"])
LOG_ED25519 = Ed25519KeyPair.from_seed(LOG_ED25519_SEED)
LOG_UNKNOWN = P256KeyPair.from_secret(_SECRETS["unknown_log"])

# A checkpoint's origin (and signer name) is the hostname of the log's base URL.
ORIGIN_ECDSA = "rekor.tinfoil-conformance.test"
ORIGIN_ED25519 = "rekor-ed25519.tinfoil-conformance.test"
ORIGIN_UNKNOWN = "rekor-unknown.tinfoil-conformance.test"

BASE_TIME = datetime(2025, 1, 1, tzinfo=timezone.utc)
ARTIFACT = b"tinfoil-conformance approval layer vector artifact\n"
DIGEST_HEX = hashlib.sha256(ARTIFACT).hexdigest()
OTHER_DIGEST_HEX = hashlib.sha256(b"a different artifact").hexdigest()

# The happy entry sits in the middle of a small tree so its inclusion proof
# carries sibling hashes a verifier must actually fold.
TREE_SIZE = 5
LOG_INDEX = 2


def b64(data: bytes) -> str:
    return base64.standard_b64encode(data).decode()


def key_hint(key: P256KeyPair) -> str:
    """base64 SHA-256 of the DER SubjectPublicKeyInfo: how a bundle names a pinned key."""
    return b64(hashlib.sha256(key.public_der).digest())


def statement(digest_hex=DIGEST_HEX, subjects=None) -> bytes:
    if subjects is None:
        subjects = [{"name": "artifact", "digest": {"sha256": digest_hex}}]
    return json.dumps({
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": PREDICATE_TYPE,
        "predicate": {"approved": True, "note": "tinfoil-conformance layer vector"},
    }, separators=(",", ":")).encode()


def trusted_root() -> dict:
    valid_from = BASE_TIME
    return trust_root.build_trust_root_from_parts(tlogs=[
        trust_root.tlog_instance(key=LOG_ECDSA, base_url=f"https://{ORIGIN_ECDSA}", valid_from=valid_from),
        trust_root.tlog_instance(key=LOG_ED25519, base_url=f"https://{ORIGIN_ED25519}", valid_from=valid_from),
    ])


TRUSTED_ROOT = trusted_root()


def log_entry(*, signature: bytes, pae: bytes, verifier_key=KEY_A, log_key=LOG_ECDSA, origin=ORIGIN_ECDSA,
              log_index=LOG_INDEX, tree_size=TREE_SIZE, body_digest=None, **kw) -> dict:
    """A hashedrekord 0.0.2 entry for `signature` over `pae` under
    `verifier_key`, in a tree of `tree_size` leaves at `log_index`."""
    body = rekor.build_hashedrekord_v002_body(
        digest=hashlib.sha256(pae).digest() if body_digest is None else body_digest,
        signature_der=signature,
        verifier_spki_der=verifier_key.public_der,
    )
    return rekor.build_rekor_v2_entry(body=body, log_key=log_key, log_id=log_key.log_id, origin=origin,
                                      log_index=log_index, tree_size=tree_size, **kw)


def bundle(*, signer=KEY_A, hint_key=None, keyid=None, stmt=None, entries=None, entry_kw=None) -> dict:
    """A key-signed bundle over `stmt` signed by `signer`, with the hint naming
    `hint_key` (default: the signer) and `entries` log entries (default: one
    consistent entry built with `entry_kw`)."""
    payload = statement() if stmt is None else stmt
    pae = compute_pae(PAYLOAD_TYPE, payload)
    sig = signer.sign_prehashed_sha256(pae)
    if entries is None:
        entries = [log_entry(signature=sig, pae=pae, **{"verifier_key": signer, **(entry_kw or {})})]
    signature = {"sig": b64(sig)}
    if keyid is not None:
        signature["keyid"] = keyid
    return {
        "mediaType": BUNDLE_MEDIA_TYPE,
        "verificationMaterial": {
            "publicKey": {"hint": key_hint(hint_key or signer)},
            "tlogEntries": entries,
        },
        "dsseEnvelope": {"payloadType": PAYLOAD_TYPE, "payload": b64(payload), "signatures": [signature]},
    }


def signed_parts(stmt=None, signer=KEY_A):
    payload = statement() if stmt is None else stmt
    pae = compute_pae(PAYLOAD_TYPE, payload)
    return payload, pae, signer.sign_prehashed_sha256(pae)


def with_entries(n: int) -> dict:
    """A bundle with `n` entries, each at a distinct index of its own tree."""
    payload, pae, sig = signed_parts()
    entries = [log_entry(signature=sig, pae=pae, log_index=i, tree_size=n) for i in range(n)]
    return bundle(entries=entries)


# Each vector returns (bundle, expected); its docstring is the rule it exercises.
def happy():
    """A key-signed approval with one hashedrekord 0.0.2 inclusion proof under the ECDSA P-256 log."""
    return bundle(), accept(KEY_A)


def happy_ed25519_log():
    """The log entry's checkpoint is signed by an Ed25519 log (its note key hint hashes origin, 0x01 and the raw key)."""
    return bundle(entry_kw={"log_key": LOG_ED25519, "origin": ORIGIN_ED25519}), accept(KEY_A)


def happy_second_key():
    """The approval is signed by the second pinned key; the hint selects it."""
    return bundle(signer=KEY_B), accept(KEY_B)


def keyid_equals_hint():
    """The DSSE signature carries a keyid equal to the public-key hint. The stage
    accepts no non-empty keyid at all (only an empty keyid verifies), so this
    rejects even though the keyid names the right key."""
    return bundle(keyid=key_hint(KEY_A)), reject()


def eight_entries():
    """Eight log entries, the maximum, each with its own inclusion proof."""
    return with_entries(8), accept(KEY_A)


def digest_in_second_subject():
    """The artifact digest is carried by the statement's second subject, not its first."""
    stmt = statement(subjects=[{"name": "other", "digest": {"sha256": OTHER_DIGEST_HEX}},
                               {"name": "artifact", "digest": {"sha256": DIGEST_HEX}}])
    return bundle(stmt=stmt), accept(KEY_A)


def wrong_hint():
    """The public-key hint names a key that is not pinned."""
    return bundle(hint_key=KEY_UNPINNED), reject()


def keyid_mismatch():
    """The DSSE keyid is set but differs from the public-key hint."""
    return bundle(keyid=key_hint(KEY_B)), reject()


def zero_entries():
    """No transparency log entries."""
    return bundle(entries=[]), reject()


def nine_entries():
    """Nine log entries, one more than the maximum of eight."""
    return with_entries(9), reject()


def entry_wrong_kind():
    """The log entry declares kind dsse instead of hashedrekord."""
    return bundle(entry_kw={"kind": "dsse"}), reject()


def entry_wrong_version():
    """The log entry declares hashedrekord version 0.0.1 (Rekor v1) instead of 0.0.2."""
    return bundle(entry_kw={"version": "0.0.1"}), reject()


def integrated_time_present():
    """The log entry carries an integrated time; a key-signed approval states no time."""
    b = bundle()
    b["verificationMaterial"]["tlogEntries"][0]["integratedTime"] = str(int(BASE_TIME.timestamp()) + 1)
    return b, reject()


def inclusion_promise_present():
    """The log entry carries an inclusion promise alongside its proof."""
    b = bundle()
    body = base64.standard_b64decode(b["verificationMaterial"]["tlogEntries"][0]["canonicalizedBody"])
    set_sig = LOG_ECDSA.sign_prehashed_sha256(b"synthetic signed entry timestamp over " + body)
    b["verificationMaterial"]["tlogEntries"][0]["inclusionPromise"] = {"signedEntryTimestamp": b64(set_sig)}
    return b, reject()


def rfc3161_timestamps_present():
    """The bundle carries an RFC 3161 timestamp; an approval's time comes only from its own signed timestamp."""
    b = bundle()
    authority = tsa.build_timestamp_authority(
        root_key=P256KeyPair.from_secret(_SECRETS["tsa_root"]), leaf_key=P256KeyPair.from_secret(_SECRETS["tsa_leaf"]),
        root_not_before=BASE_TIME, root_not_after=BASE_TIME.replace(year=2035),
        leaf_not_before=BASE_TIME, leaf_not_after=BASE_TIME.replace(year=2030), root_serial=1, leaf_serial=2)
    pae = compute_pae(PAYLOAD_TYPE, base64.standard_b64decode(b["dsseEnvelope"]["payload"]))
    info = tsa.build_tst_info(imprint=hashlib.sha256(pae).digest(), gen_time=BASE_TIME, serial=1)
    response = tsa.build_timestamp_response(tsa=authority, tst_info=info)
    b["verificationMaterial"]["timestampVerificationData"] = {"rfc3161Timestamps": [{"signedTimestamp": b64(response)}]}
    return b, reject()


def body_digest_mismatch():
    """The entry body's data.digest is SHA-256 of the bare payload, not of the signed PAE bytes (proof consistent with the body)."""
    payload, pae, sig = signed_parts()
    entry = log_entry(signature=sig, pae=pae, body_digest=hashlib.sha256(payload).digest())
    return bundle(entries=[entry]), reject()


def body_key_mismatch():
    """The entry body's verifier key is a different pinned key than the one the hint names (proof consistent with the body)."""
    payload, pae, sig = signed_parts()
    entry = log_entry(signature=sig, pae=pae, verifier_key=KEY_B)
    return bundle(entries=[entry]), reject()


def bad_inclusion_proof():
    """One sibling hash of the inclusion proof is corrupted; the path no longer reaches the checkpoint root."""
    b = bundle()
    hashes = b["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["hashes"]
    first = bytearray(base64.standard_b64decode(hashes[0]))
    first[0] ^= 0x01
    hashes[0] = b64(bytes(first))
    return b, reject()


def checkpoint_unknown_log():
    """The entry names a log id, and its checkpoint is signed by a log key, that the trusted root does not list."""
    return bundle(entry_kw={"log_key": LOG_UNKNOWN, "origin": ORIGIN_UNKNOWN}), reject()


def checkpoint_bad_signature():
    """The entry names the trusted ECDSA log but its checkpoint signature is not by that log's key."""
    payload, pae, sig = signed_parts()
    # The entry names the ECDSA log but its checkpoint is signed by another key under that log's origin.
    entry = log_entry(signature=sig, pae=pae, log_key=LOG_UNKNOWN, origin=ORIGIN_ECDSA)
    entry["logId"] = {"keyId": b64(LOG_ECDSA.log_id)}
    return bundle(entries=[entry]), reject()


def bad_dsse_signature():
    """The DSSE signature was made by another key; the hint, body and proof all name the pinned key."""
    payload, pae, sig = signed_parts(signer=KEY_UNPINNED)
    entry = log_entry(signature=sig, pae=pae, verifier_key=KEY_A)
    b = bundle(entries=[entry])
    b["dsseEnvelope"]["signatures"] = [{"sig": b64(sig)}]
    return b, reject()


def subject_digest_mismatch():
    """No subject of the statement names the artifact digest."""
    return bundle(stmt=statement(digest_hex=OTHER_DIGEST_HEX)), reject()


def certificate_instead_of_key():
    """The verification material is a certificate for the signing key instead of a public-key hint."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tinfoil-conformance self-signed approval key")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(KEY_A.public)
            .serial_number(1).not_valid_before(BASE_TIME.replace(tzinfo=None))
            .not_valid_after(BASE_TIME.replace(year=2035, tzinfo=None))
            .sign(KEY_A.private, hashes.SHA256(), ecdsa_deterministic=True))
    b = bundle()
    vm = b["verificationMaterial"]
    del vm["publicKey"]
    vm["certificate"] = {"rawBytes": b64(cert.public_bytes(serialization.Encoding.DER))}
    return b, reject()


def accept(key: P256KeyPair) -> dict:
    return {"accepted": True, "signing_key_hint": key_hint(key)}


def reject() -> dict:
    return {"accepted": False, "code": "PROVENANCE_REJECTED"}


VECTORS = {
    "happy": happy,
    "happy-ed25519-log": happy_ed25519_log,
    "happy-second-key": happy_second_key,
    "keyid-equals-hint": keyid_equals_hint,
    "eight-entries": eight_entries,
    "digest-in-second-subject": digest_in_second_subject,
    "wrong-hint": wrong_hint,
    "keyid-mismatch": keyid_mismatch,
    "zero-entries": zero_entries,
    "nine-entries": nine_entries,
    "entry-wrong-kind": entry_wrong_kind,
    "entry-wrong-version": entry_wrong_version,
    "integrated-time-present": integrated_time_present,
    "inclusion-promise-present": inclusion_promise_present,
    "rfc3161-timestamps-present": rfc3161_timestamps_present,
    "body-digest-mismatch": body_digest_mismatch,
    "body-key-mismatch": body_key_mismatch,
    "bad-inclusion-proof": bad_inclusion_proof,
    "checkpoint-unknown-log": checkpoint_unknown_log,
    "checkpoint-bad-signature": checkpoint_bad_signature,
    "bad-dsse-signature": bad_dsse_signature,
    "subject-digest-mismatch": subject_digest_mismatch,
    "certificate-instead-of-key": certificate_instead_of_key,
}


def fixture(fid, b, expected) -> dict:
    return {
        "id": fid,
        "stage": STAGE,
        "input": {
            "schema_version": "1",
            "bundle_json_b64": b64(json.dumps(b).encode()),
            "signing_keys_pem": [k.public_pem for k in PINNED_KEYS],
            "artifact_digest_hex": DIGEST_HEX,
            "sigstore_trusted_root_json_b64": b64(json.dumps(TRUSTED_ROOT).encode()),
        },
        "expected": expected,
    }


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    n = 0
    for fid, fn in VECTORS.items():
        b, expected = fn()
        with open(OUT_DIR / (fid + ".json"), "w") as fh:
            fh.write(json.dumps(fixture(fid, copy.deepcopy(b), expected), indent=2) + "\n")
        n += 1
    print(f"wrote {n} approval-bundle fixtures to {OUT_DIR.relative_to(REPO_ROOT)}/")


if __name__ == "__main__":
    main()
