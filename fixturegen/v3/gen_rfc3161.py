#!/usr/bin/env python3
"""Generate the RFC 3161 timestamp fixtures (vectors/v3/rfc3161/) for the
`v3-verify-timestamp` stage (CONFORMANCE_ADAPTER_SPEC §2.1).

Each fixture is a DER TimeStampResp over `timestamp_input` plus the trusted
root whose timestamp authorities may authenticate it, appraised at
`verification_time_unix` (one hour after genTime, so only the response itself
is judged). The stage accepts when: the status is granted (every other status,
including grantedWithMods, rejects); the TSTInfo's messageImprint is SHA-256
of the input; the policy OID is the Sigstore timestamp policy
1.3.6.1.4.1.57264.2; the token's signer (issuer + serial) is the signing
certificate of an authority in the trusted root and chains to that
authority's root (byte-identical); the signing certificate is an end entity
with a critical extended key usage of timestamping only; the chain and the
authority's validity window both contain genTime; genTime lies in the
appraisal window. Accepts report genTime as `timestamp`; every rejection
attributes to PROVENANCE_REJECTED. Emits the shared fixture format
{id, stage, input, expected}; each vector function's docstring says what it
exercises.

Deterministic: fixed keys, RFC 6979 ECDSA nonces, fixed times.

Run from the repo root:  uv run --with cryptography fixturegen/v3/gen_rfc3161.py
"""

import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "fixturegen"))

from lib import trust_root, tsa  # noqa: E402
from lib.keys import P256KeyPair, P384KeyPair  # noqa: E402

STAGE = "v3-verify-timestamp"
OUT_DIR = REPO_ROOT / "vectors" / "v3" / "rfc3161"

# Fixed secrets -> reproducible keys (P-256 scalars; the P-384 ones are below its order too).
_SECRETS = {
    "p256_root": 0x9191919191919191919191919191919191919191919191919191919191919191,
    "p256_leaf": 0x9292929292929292929292929292929292929292929292929292929292929292,
    "p384_root": 0x9393939393939393939393939393939393939393939393939393939393939393,
    "p384_leaf": 0x9494949494949494949494949494949494949494949494949494949494949494,
    "other_root": 0x9595959595959595959595959595959595959595959595959595959595959595,
    "other_leaf": 0x9696969696969696969696969696969696969696969696969696969696969696,
}

GEN_TIME = datetime(2025, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
GEN_TIME_RFC3339 = "2025-03-01T12:00:00Z"
# The appraisal clock: an hour after genTime, inside the stage's
# [verification_time - 7 days, verification_time + 5 minutes] window.
VERIFICATION_TIME_UNIX = int((GEN_TIME + timedelta(hours=1)).timestamp())
WINDOW_START = datetime(2025, 1, 1, tzinfo=timezone.utc)
WINDOW_END = datetime(2026, 1, 1, tzinfo=timezone.utc)
ROOT_NOT_BEFORE = datetime(2024, 1, 1, tzinfo=timezone.utc)
ROOT_NOT_AFTER = datetime(2034, 1, 1, tzinfo=timezone.utc)
LEAF_NOT_BEFORE = datetime(2025, 1, 1, tzinfo=timezone.utc)
LEAF_NOT_AFTER = datetime(2026, 1, 1, tzinfo=timezone.utc)

# The bytes timestamped: a domain string followed by canonical JSON, the
# shape tinfoil's signed approval timestamps cover.
INPUT = b"tinfoil-conformance/rfc3161-layer-vector/v1" + json.dumps(
    {"artifact": "sha256:" + hashlib.sha256(b"approval core").hexdigest(), "revision": "1"},
    separators=(",", ":"), sort_keys=True).encode()
TST_SERIAL = 0x1A2B3C


def b64(data: bytes) -> str:
    return base64.standard_b64encode(data).decode()


def authority(root_secret, leaf_secret, *, keypair=P256KeyPair, root_serial, leaf_serial,
              leaf_not_before=LEAF_NOT_BEFORE, leaf_not_after=LEAF_NOT_AFTER, **kw) -> tsa.TimestampAuthority:
    return tsa.build_timestamp_authority(
        root_key=keypair.from_secret(_SECRETS[root_secret]), leaf_key=keypair.from_secret(_SECRETS[leaf_secret]),
        root_not_before=ROOT_NOT_BEFORE, root_not_after=ROOT_NOT_AFTER,
        leaf_not_before=leaf_not_before, leaf_not_after=leaf_not_after,
        root_serial=root_serial, leaf_serial=leaf_serial, **kw)


TSA_P256 = authority("p256_root", "p256_leaf", root_serial=1, leaf_serial=2)
TSA_P384 = authority("p384_root", "p384_leaf", keypair=P384KeyPair, root_serial=11, leaf_serial=12,
                     root_common_name="tinfoil-conformance test TSA root (P-384)",
                     leaf_common_name="tinfoil-conformance test TSA signer (P-384)")
TSA_OTHER = authority("other_root", "other_leaf", root_serial=21, leaf_serial=22,
                      root_common_name="tinfoil-conformance other TSA root",
                      leaf_common_name="tinfoil-conformance other TSA signer")


def root_with(*authorities, start=WINDOW_START, end=WINDOW_END) -> dict:
    return trust_root.build_trust_root_from_parts(timestamp_authorities=[
        trust_root.timestamp_authority(chain_der=a.chain_der, uri=f"https://tsa{i}.tinfoil-conformance.test",
                                       valid_from=start, valid_to=end)
        for i, a in enumerate(authorities, start=1)
    ])


TRUSTED_ROOT = root_with(TSA_P256, TSA_P384)


def response(tsa_=TSA_P256, *, imprint_of=INPUT, policy=tsa.SIGSTORE_TIMESTAMP_POLICY,
             status=tsa.STATUS_GRANTED, gen_time=GEN_TIME) -> bytes:
    info = tsa.build_tst_info(imprint=hashlib.sha256(imprint_of).digest(), gen_time=gen_time,
                              serial=TST_SERIAL, policy=policy)
    return tsa.build_timestamp_response(tsa=tsa_, tst_info=info, status=status)


# Each vector returns (response_bytes, trusted_root, expected); its docstring is the rule it exercises.
def granted_p256():
    """A granted response signed by the P-256 timestamp authority."""
    return response(), TRUSTED_ROOT, accept()


def granted_p384_key_sha256_digest():
    """A granted response signed by the P-384 authority over a SHA-256 digest with ecdsa-with-SHA256, as the production TSA does."""
    return response(TSA_P384), TRUSTED_ROOT, accept()


def granted_with_mods():
    """The status is grantedWithMods (1) with a valid token. RFC 3161 lets such a
    response carry a token, but the stage accepts only status granted (0) and
    rejects every other status."""
    return response(status=tsa.STATUS_GRANTED_WITH_MODS), TRUSTED_ROOT, reject()


def status_rejected():
    """The status is rejection (2) with a failure info and no token."""
    return tsa.build_rejected_response(), TRUSTED_ROOT, reject()


def imprint_mismatch():
    """The messageImprint is SHA-256 of different bytes than the input."""
    return response(imprint_of=INPUT + b"x"), TRUSTED_ROOT, reject()


def wrong_policy():
    """The TSTInfo policy is not the Sigstore timestamp policy OID."""
    return response(policy="1.3.6.1.4.1.57264.3"), TRUSTED_ROOT, reject()


def unknown_authority():
    """The token is signed by an authority (and chains to a root) the trusted root does not list."""
    return response(TSA_OTHER), TRUSTED_ROOT, reject()


def before_window():
    """genTime precedes the authority's validFor start (certificates are valid)."""
    return (response(), root_with(TSA_P256, TSA_P384, start=datetime(2025, 6, 1, tzinfo=timezone.utc)),
            reject())


def after_window():
    """genTime follows the authority's validFor end (certificates are valid)."""
    return (response(), root_with(TSA_P256, TSA_P384, end=datetime(2025, 2, 1, tzinfo=timezone.utc)),
            reject())


def signer_expired():
    """The signing certificate expired before genTime; the authority's window contains genTime."""
    expired = authority("p256_root", "p256_leaf", root_serial=1, leaf_serial=2,
                        leaf_not_before=datetime(2024, 1, 1, tzinfo=timezone.utc),
                        leaf_not_after=datetime(2025, 2, 1, tzinfo=timezone.utc))
    return response(expired), root_with(expired, TSA_P384), reject()


def eku_not_critical():
    """The signing certificate's extended key usage (timestamping) is not marked critical."""
    noncrit = authority("p256_root", "p256_leaf", root_serial=1, leaf_serial=2, eku_critical=False)
    return response(noncrit), root_with(noncrit, TSA_P384), reject()


def no_eku():
    """The signing certificate has no extended key usage extension."""
    none = authority("p256_root", "p256_leaf", root_serial=1, leaf_serial=2, eku=False)
    return response(none), root_with(none, TSA_P384), reject()


def trailing_bytes():
    """Bytes follow the DER TimeStampResp."""
    return response() + b"\x00", TRUSTED_ROOT, reject()


def tampered_gentime():
    """genTime was altered after signing, so the message-digest attribute no longer matches the TSTInfo."""
    good = response()
    original = b"\x18\x0f" + GEN_TIME.strftime("%Y%m%d%H%M%SZ").encode()
    assert good.count(original) == 1
    tampered = good.replace(original, b"\x18\x0f" + b"20250301130000Z")
    return tampered, TRUSTED_ROOT, reject()


def accept() -> dict:
    return {"accepted": True, "timestamp": GEN_TIME_RFC3339}


def reject() -> dict:
    return {"accepted": False, "code": "PROVENANCE_REJECTED"}


VECTORS = {
    "granted-p256": granted_p256,
    "granted-p384-key-sha256-digest": granted_p384_key_sha256_digest,
    "granted-with-mods": granted_with_mods,
    "status-rejected": status_rejected,
    "imprint-mismatch": imprint_mismatch,
    "wrong-policy": wrong_policy,
    "unknown-authority": unknown_authority,
    "before-window": before_window,
    "after-window": after_window,
    "signer-expired": signer_expired,
    "eku-not-critical": eku_not_critical,
    "no-eku": no_eku,
    "trailing-bytes": trailing_bytes,
    "tampered-gentime": tampered_gentime,
}


def fixture(fid, resp, troot, expected) -> dict:
    return {
        "id": fid,
        "stage": STAGE,
        "input": {
            "schema_version": "1",
            "timestamp_response_b64": b64(resp),
            "timestamp_input_b64": b64(INPUT),
            "verification_time_unix": VERIFICATION_TIME_UNIX,
            "sigstore_trusted_root_json_b64": b64(json.dumps(troot).encode()),
        },
        "expected": expected,
    }


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    n = 0
    for fid, fn in VECTORS.items():
        resp, troot, expected = fn()
        with open(OUT_DIR / (fid + ".json"), "w") as fh:
            fh.write(json.dumps(fixture(fid, resp, troot, expected), indent=2) + "\n")
        n += 1
    print(f"wrote {n} rfc3161 fixtures to {OUT_DIR.relative_to(REPO_ROOT)}/")


if __name__ == "__main__":
    main()
