"""Synthetic Sigstore trust_root.json assembly.

Schema reference (v0.1):
https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_trustroot.proto
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone

from .fulcio import RootCA
from .keys import P256KeyPair


def build_trust_root(
    *,
    fulcio_root: RootCA,
    ct_log_key: P256KeyPair,
    ct_log_valid_from: datetime,
    rekor_key: P256KeyPair,
    rekor_valid_from: datetime,
) -> dict:
    """Build a TrustedRoot v0.1 dict that endorses the supplied test keys
    and Fulcio root for the synthetic bundle they signed.

    The SDK's trust-root loader looks at:
      * tlogs (Rekor):  baseUrl, hashAlgorithm, publicKey.rawBytes (SPKI DER),
                        publicKey.keyDetails, publicKey.validFor, logId.keyId
      * certificateAuthorities (Fulcio): subject, certChain.certificates, validFor
      * ctlogs (CT): publicKey.rawBytes, keyDetails, validFor, logId.keyId
    """
    return {
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


def _rfc3339(dt: datetime) -> str:
    """RFC 3339 timestamp with Z suffix."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Piecewise trusted-root assembly for the approval-bundle and rfc3161 fixtures,
# which need roots with only transparency logs (key-signed approval bundles)
# or only timestamp authorities (RFC 3161 responses).


def tlog_instance(
    *,
    key,
    base_url: str,
    valid_from: datetime,
    valid_to: datetime | None = None,
    key_details: str | None = None,
) -> dict:
    """One `tlogs[]` TransparencyLogInstance. `key` is a P256KeyPair or an
    Ed25519KeyPair; the key details default to the key's type. The log id is
    SHA-256 of the SPKI DER, which is also how every verifier names the log."""
    if key_details is None:
        key_details = "PKIX_ED25519" if hasattr(key, "public_raw") else "PKIX_ECDSA_P256_SHA_256"
    valid_for = {"start": _rfc3339(valid_from)}
    if valid_to is not None:
        valid_for["end"] = _rfc3339(valid_to)
    return {
        "baseUrl": base_url,
        "hashAlgorithm": "SHA2_256",
        "publicKey": {
            "rawBytes": base64.standard_b64encode(key.public_der).decode(),
            "keyDetails": key_details,
            "validFor": valid_for,
        },
        "logId": {"keyId": base64.standard_b64encode(key.log_id).decode()},
    }


def timestamp_authority(
    *,
    chain_der: list[bytes],
    uri: str,
    valid_from: datetime,
    valid_to: datetime | None = None,
    organization: str = "tinfoil-conformance",
    common_name: str = "tinfoil-conformance test TSA",
) -> dict:
    """One `timestampAuthorities[]` CertificateAuthority. `chain_der` is in
    wire order: the signing (leaf) certificate first, the root last."""
    valid_for = {"start": _rfc3339(valid_from)}
    if valid_to is not None:
        valid_for["end"] = _rfc3339(valid_to)
    return {
        "subject": {"organization": organization, "commonName": common_name},
        "uri": uri,
        "certChain": {
            "certificates": [
                {"rawBytes": base64.standard_b64encode(der).decode()} for der in chain_der
            ]
        },
        "validFor": valid_for,
    }


def build_trust_root_from_parts(
    *,
    tlogs: list[dict] = (),
    certificate_authorities: list[dict] = (),
    ctlogs: list[dict] = (),
    timestamp_authorities: list[dict] = (),
) -> dict:
    """A TrustedRoot v0.1 dict from already-built members (see the helpers
    above). Every list is emitted, empty or not, so the document always has
    the full shape a strict parser expects."""
    return {
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "tlogs": list(tlogs),
        "certificateAuthorities": list(certificate_authorities),
        "ctlogs": list(ctlogs),
        "timestampAuthorities": list(timestamp_authorities),
    }
