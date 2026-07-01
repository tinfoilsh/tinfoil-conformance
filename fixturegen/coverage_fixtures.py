#!/usr/bin/env python3
"""Coverage fixtures for thin spots in SPEC §5.2 verification: observer-timestamp
threshold, Fulcio chain-to-trusted-root, SCT signature validity, and Rekor
checkpoint signature. Mutations of the real-frozen seed bundle (fixture 001),
via policy_variations.write_fixture.
"""
import base64, copy, datetime, json
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from policy_variations import load_seed, write_fixture


def _b(i): return json.loads(base64.b64decode(i["bundle_b64"]))
def _setb(i, x): i["bundle_b64"] = base64.b64encode(json.dumps(x).encode()).decode()
def _t(i): return json.loads(base64.b64decode(i["trust_root_b64"]))
def _sett(i, x): i["trust_root_b64"] = base64.b64encode(json.dumps(x).encode()).decode()


def mut_observer_timestamp(i):
    bun = _b(i)
    tl = bun["verificationMaterial"]["tlogEntries"][0]
    tl.pop("integratedTime", None)          # drop the tlog integrated time
    tl.pop("inclusionPromise", None)        # drop the SET (signed entry timestamp)
    bun["verificationMaterial"]["timestampVerificationData"] = {}  # no RFC3161 TSA
    _setb(i, bun)


def mut_untrusted_fulcio_root(i):
    key = ec.generate_private_key(ec.SECP384R1())
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rogue-fulcio-root")])
    cert = (x509.CertificateBuilder().subject_name(n).issuer_name(n)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2040, 1, 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA384()))
    der = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    t = _t(i)
    for ca in t["certificateAuthorities"]:
        ca["certChain"]["certificates"] = [{"rawBytes": der}]
    _sett(i, t)


def mut_sct_signature_invalid(i):
    # Keep each CT log's declared logId (so the SCT still maps to a known log)
    # but replace its public key -> the SCT signature no longer verifies.
    key = ec.generate_private_key(ec.SECP256R1())
    spki = base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    t = _t(i)
    for cl in t["ctlogs"]:
        cl["publicKey"]["rawBytes"] = spki
    _sett(i, t)


def mut_checkpoint_sig_tampered(i):
    bun = _b(i)
    tl = bun["verificationMaterial"]["tlogEntries"][0]
    env = tl["inclusionProof"]["checkpoint"]["envelope"]
    lines = env.rstrip("\n").split("\n")
    pre, sig = lines[-1].rsplit(" ", 1)
    j = len(sig) // 2
    sig = sig[:j] + ("A" if sig[j] != "A" else "B") + sig[j + 1:]
    lines[-1] = pre + " " + sig
    tl["inclusionProof"]["checkpoint"]["envelope"] = "\n".join(lines) + "\n"
    _setb(i, bun)


def main():
    seed = load_seed()

    write_fixture(
        "090-observer-timestamp-missing",
        "Bundle with no observer timestamp (no integratedTime, inclusion promise, or RFC3161) must reject.",
        ["5.2"], "real-frozen-bundle-mutation",
        "SPEC §5.2 #5 requires at least 1 valid observer timestamp. This strips the\n"
        "tlog entry's integratedTime and inclusionPromise (SET) and clears\n"
        "timestampVerificationData, leaving only the Merkle inclusion proof.\n"
        "go/rs/py reject (no verifiable timestamp source); tinfoil-js via\n"
        "@freedomofpress/sigstore-browser accepts, i.e. does not enforce the\n"
        "observer-timestamp threshold. Divergence captured in list-form code.",
        seed, mutate_input=mut_observer_timestamp, expected_exit=10,
        rejection_code=["OBSERVER_TIMESTAMP_INSUFFICIENT", "TLOG_COUNT_OUT_OF_RANGE", "BUNDLE_MALFORMED"],
        expected_outputs=None,
    )
    write_fixture(
        "091-fulcio-cert-untrusted-root",
        "Leaf certificate that does not chain to any trusted Fulcio root must reject.",
        ["5.2"], "real-frozen-bundle-mutation",
        "Replaces every trust-root certificateAuthority cert chain with an\n"
        "unrelated self-signed CA, so the leaf no longer chains to a trusted\n"
        "root. All SDKs reject with FULCIO_CHAIN_INVALID.",
        seed, mutate_input=mut_untrusted_fulcio_root, expected_exit=10,
        rejection_code="FULCIO_CHAIN_INVALID", expected_outputs=None,
    )
    write_fixture(
        "092-sct-signature-invalid",
        "Leaf SCT that does not verify against the trust root's CT log key must reject.",
        ["5.2"], "real-frozen-bundle-mutation",
        "Keeps each CT log's declared logId but swaps its public key, so the\n"
        "embedded SCT's signature no longer verifies. All SDKs reject (SCT\n"
        "verification fails); codes vary but the reason is uniform.",
        seed, mutate_input=mut_sct_signature_invalid, expected_exit=10,
        rejection_code=["SCT_INSUFFICIENT", "BUNDLE_MALFORMED", "DSSE_SIGNATURE_INVALID"],
        expected_outputs=None,
    )
    write_fixture(
        "093-rekor-checkpoint-signature-tampered",
        "Rekor checkpoint (SignedNote) with a tampered signature must reject.",
        ["5.2"], "real-frozen-bundle-mutation",
        "Flips a byte in the checkpoint signature while leaving the Rekor key in\n"
        "the trust root, so the checkpoint (SignedNote) signature no longer\n"
        "verifies. All SDKs reject with REKOR_INCLUSION_INVALID.",
        seed, mutate_input=mut_checkpoint_sig_tampered, expected_exit=10,
        rejection_code="REKOR_INCLUSION_INVALID", expected_outputs=None,
    )
    print("wrote 090-093")


if __name__ == "__main__":
    main()
