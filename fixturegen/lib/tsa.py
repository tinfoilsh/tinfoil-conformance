"""Synthetic RFC 3161 timestamp authority.

Certificates come from `cryptography`; the TimeStampResp itself from
`openssl ts -reply`, since `cryptography` cannot sign CMS/TSTInfo. genTime is
the wall clock at generation, so a fixture that embeds a token must place the
signing certificate's validity around "now".
"""

from __future__ import annotations

import base64
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .fulcio import RootCA, _naive_utc, build_root_ca
from .keys import P256KeyPair
from .trust_root import _rfc3339


@dataclass
class SynthTsa:
    root: RootCA
    leaf_cert: x509.Certificate
    leaf_key: P256KeyPair
    valid_from: datetime
    uri: str = "https://tinfoil-conformance.test/tsa"


def build_synth_tsa(*, not_before: datetime, not_after: datetime) -> SynthTsa:
    root_key = P256KeyPair.generate()
    root = build_root_ca(
        key=root_key,
        common_name="tinfoil-conformance test TSA root",
        not_before=not_before,
        not_after=not_after,
    )
    leaf_key = P256KeyPair.generate()
    leaf = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "tinfoil-conformance test TSA"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "tinfoil-conformance"),
                ]
            )
        )
        .issuer_name(root.cert.subject)
        .public_key(leaf_key.public)
        .serial_number(x509.random_serial_number())
        .not_valid_before(_naive_utc(not_before))
        .not_valid_after(_naive_utc(not_after))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # RFC 3161 §2.3: exactly one EKU, timeStamping, critical.
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
        .sign(root_key.private, hashes.SHA256())
    )
    return SynthTsa(root=root, leaf_cert=leaf, leaf_key=leaf_key, valid_from=not_before)


_OPENSSL_CNF = """[ tsa ]
default_tsa = tsa1
[ tsa1 ]
dir = {dir}
serial = {dir}/serial
signer_cert = {dir}/tsa.pem
signer_key = {dir}/tsa.key
certs = {dir}/root.pem
signer_digest = sha256
default_policy = 1.3.6.1.4.1.57264.2
digests = sha256
accuracy = secs:1
ordering = no
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
"""


def timestamp(tsa: SynthTsa, data: bytes) -> bytes:
    """DER TimeStampResp over `data` (Sigstore timestamps the signature bytes)."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / "tsa.pem").write_bytes(tsa.leaf_cert.public_bytes(serialization.Encoding.PEM))
        (p / "tsa.key").write_bytes(
            tsa.leaf_key.private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        (p / "root.pem").write_text(tsa.root.cert_pem)
        (p / "serial").write_text("01\n")
        (p / "tsa.cnf").write_text(_OPENSSL_CNF.format(dir=d))
        (p / "data.bin").write_bytes(data)
        subprocess.run(
            ["openssl", "ts", "-query", "-data", str(p / "data.bin"), "-sha256", "-cert",
             "-no_nonce", "-out", str(p / "req.tsq")],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "ts", "-reply", "-config", str(p / "tsa.cnf"), "-queryfile",
             str(p / "req.tsq"), "-out", str(p / "resp.tsr")],
            check=True, capture_output=True,
        )
        return (p / "resp.tsr").read_bytes()


def trust_root_entry(tsa: SynthTsa) -> dict:
    """`timestampAuthorities[]` entry: chain is [leaf, root]."""
    return {
        "subject": {
            "organization": "tinfoil-conformance",
            "commonName": "tinfoil-conformance test TSA",
        },
        "uri": tsa.uri,
        "certChain": {
            "certificates": [
                {"rawBytes": base64.standard_b64encode(
                    tsa.leaf_cert.public_bytes(serialization.Encoding.DER)).decode()},
                {"rawBytes": base64.standard_b64encode(tsa.root.cert_der).decode()},
            ]
        },
        "validFor": {"start": _rfc3339(tsa.valid_from)},
    }
