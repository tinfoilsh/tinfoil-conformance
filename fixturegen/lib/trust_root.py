"""Synthetic Sigstore trust_root.json assembly.

Schema reference (v0.1):
https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_trustroot.proto
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone

from .fulcio import RootCA
from .keys import Ed25519KeyPair, P256KeyPair


def build_trust_root(
    *,
    fulcio_root: RootCA,
    ct_log_key: P256KeyPair,
    ct_log_valid_from: datetime,
    rekor_key: P256KeyPair,
    rekor_valid_from: datetime,
    # Rekor v2 log as (Ed25519 key, origin host); baseUrl is https://<origin>.
    rekor_v2_log: tuple[Ed25519KeyPair, str] | None = None,
    timestamp_authorities: list[dict] = (),
) -> dict:
    """Build a TrustedRoot v0.1 dict that endorses the supplied test keys
    and Fulcio root for the synthetic bundle they signed.

    The SDK's trust-root loader looks at:
      * tlogs (Rekor):  baseUrl, hashAlgorithm, publicKey.rawBytes (SPKI DER),
                        publicKey.keyDetails, publicKey.validFor, logId.keyId
      * certificateAuthorities (Fulcio): subject, certChain.certificates, validFor
      * ctlogs (CT): publicKey.rawBytes, keyDetails, validFor, logId.keyId
    """
    root = {
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "tlogs": [
            {
                "baseUrl": "https://tinfoil-conformance.test/rekor",
                "hashAlgorithm": "SHA2_256",
                "publicKey": {
                    "rawBytes": base64.standard_b64encode(rekor_key.public_der).decode(),
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                    "validFor": {"start": _rfc3339(rekor_valid_from)},
                },
                "logId": {
                    "keyId": base64.standard_b64encode(rekor_key.log_id).decode()
                },
            }
        ],
        "certificateAuthorities": [
            {
                "subject": {
                    "organization": "tinfoil-conformance",
                    "commonName": "tinfoil-conformance test Fulcio root",
                },
                "uri": "https://tinfoil-conformance.test/fulcio",
                "certChain": {
                    "certificates": [
                        {
                            "rawBytes": base64.standard_b64encode(
                                fulcio_root.cert_der
                            ).decode()
                        }
                    ]
                },
                "validFor": {
                    "start": _rfc3339(
                        fulcio_root.cert.not_valid_before_utc
                    ),
                    "end": _rfc3339(fulcio_root.cert.not_valid_after_utc),
                },
            }
        ],
        "ctlogs": [
            {
                "baseUrl": "https://tinfoil-conformance.test/ctlog",
                "hashAlgorithm": "SHA2_256",
                "publicKey": {
                    "rawBytes": base64.standard_b64encode(ct_log_key.public_der).decode(),
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                    "validFor": {"start": _rfc3339(ct_log_valid_from)},
                },
                "logId": {
                    "keyId": base64.standard_b64encode(ct_log_key.log_id).decode()
                },
            }
        ],
    }
    if rekor_v2_log:
        key, origin = rekor_v2_log
        root["tlogs"].append(
            {
                "baseUrl": f"https://{origin}",
                "hashAlgorithm": "SHA2_256",
                "publicKey": {
                    "rawBytes": base64.standard_b64encode(key.public_der).decode(),
                    "keyDetails": "PKIX_ED25519",
                    "validFor": {"start": _rfc3339(rekor_valid_from)},
                },
                "logId": {"keyId": base64.standard_b64encode(key.log_id(origin)).decode()},
            }
        )
    if timestamp_authorities:
        root["timestampAuthorities"] = list(timestamp_authorities)
    return root


def _rfc3339(dt: datetime) -> str:
    """RFC 3339 timestamp with Z suffix."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
