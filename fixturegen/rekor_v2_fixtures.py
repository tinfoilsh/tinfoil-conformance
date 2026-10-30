#!/usr/bin/env python3
"""Rekor v2 (rekor-tiles) fixtures: the DSSE envelope is logged as a
hashedrekord 0.0.2 entry in a synthetic Ed25519 log with no integratedTime,
and an RFC 3161 timestamp from a synthetic TSA is the observer time.
Gated on sigstore.rekor_v2_supported. 100 is a Rekor v1 SET check.

Tokens carry the generation wall clock as genTime, so v2 fixtures put the
leaf cert validity around NOW; regenerate all of them together.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib import tsa as tsa_lib  # noqa: E402
from lib.spec import FixtureSpec  # noqa: E402
from signed_fixtures import DEFAULT_REPO, seed_digest, seed_payload, write_fixture  # noqa: E402

NOW = datetime.now(timezone.utc).replace(microsecond=0)
V2_CAP = {"sigstore.rekor_v2_supported": True}
ACCEPT_OUTPUTS = {
    "predicate_type": "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1",
    "in_toto_statement_type": "https://in-toto.io/Statement/v1",
    "subject_name": "tinfoil-deployment.json",
    "subject_digest_sha256_hex": seed_digest(),
    "tlog_entry_count": 1,
}


def v2_spec(leaf_from: datetime = NOW - timedelta(minutes=5), **kw) -> FixtureSpec:
    return FixtureSpec(
        payload_bytes=seed_payload(),
        workflow_repository=DEFAULT_REPO,
        rekor_v2=True,
        leaf_valid_from=leaf_from,
        leaf_valid_until=leaf_from + timedelta(minutes=10),
        sct_timestamp=leaf_from + timedelta(minutes=1),
        **kw,
    )


def strip_timestamps(b):
    b["verificationMaterial"].pop("timestampVerificationData")


def tamper_checkpoint(b):
    env = b["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["checkpoint"]["envelope"]
    lines = env.rstrip("\n").split("\n")
    pre, sig = lines[-1].rsplit(" ", 1)
    j = len(sig) // 2
    lines[-1] = pre + " " + sig[:j] + ("A" if sig[j] != "A" else "B") + sig[j + 1 :]
    b["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["checkpoint"]["envelope"] = (
        "\n".join(lines) + "\n"
    )


def tamper_set(b):
    tl = b["verificationMaterial"]["tlogEntries"][0]
    s = tl["inclusionPromise"]["signedEntryTimestamp"]
    j = len(s) // 2
    tl["inclusionPromise"]["signedEntryTimestamp"] = s[:j] + ("A" if s[j] != "A" else "B") + s[j + 1 :]


def untrusted_tsa(tr):
    other = tsa_lib.build_synth_tsa(
        not_before=datetime(2024, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2034, 1, 1, tzinfo=timezone.utc),
    )
    tr["timestampAuthorities"] = [tsa_lib.trust_root_entry(other)]


def main() -> None:
    common = dict(repo=DEFAULT_REPO, policy_override=None, spec_refs=["5.2"])

    write_fixture(
        fixture_id="094-rekor-v2-hashedrekord-happy-path",
        title="Rekor v2 entry (hashedrekord 0.0.2 over the DSSE PAE, Ed25519 checkpoint, RFC 3161 observer timestamp) must verify.",
        notes=(
            "rekor-tiles logs DSSE envelopes as hashedrekord 0.0.2 with data.digest =\n"
            "SHA-256(PAE); the entry has no integratedTime or inclusion promise, the\n"
            "checkpoint origin is the bare log host signed with the log's Ed25519 key\n"
            "(key hint = rekor-tiles log id prefix), and the only observer timestamp\n"
            "is an RFC 3161 token over the DSSE signature from the trust root's TSA."
        ),
        spec=v2_spec(),
        expected_exit=0,
        rejection_code=None,
        expected_outputs=ACCEPT_OUTPUTS,
        extra_capabilities=V2_CAP,
        **common,
    )
    write_fixture(
        fixture_id="095-rekor-v2-no-timestamp",
        title="Rekor v2 entry with no RFC 3161 timestamp has no observer time and must reject.",
        notes="Same bundle as 094 with timestampVerificationData removed. Nothing binds the\nsignature to a time inside the certificate window.",
        spec=v2_spec(),
        expected_exit=10,
        rejection_code=["OBSERVER_TIMESTAMP_INSUFFICIENT"],
        extra_capabilities=V2_CAP,
        mutate_bundle=strip_timestamps,
        **common,
    )
    write_fixture(
        fixture_id="096-rekor-v2-tsa-untrusted",
        title="Rekor v2 entry whose RFC 3161 timestamp comes from a TSA not in the trust root must reject.",
        notes="The trust root's timestampAuthorities is swapped for an unrelated synthetic TSA,\nso the token's signer is unknown and no observer timestamp remains.",
        spec=v2_spec(),
        expected_exit=10,
        rejection_code=["OBSERVER_TIMESTAMP_INSUFFICIENT"],
        extra_capabilities=V2_CAP,
        mutate_trust_root=untrusted_tsa,
        **common,
    )
    write_fixture(
        fixture_id="097-rekor-v2-checkpoint-signature-tampered",
        title="Rekor v2 checkpoint with a tampered Ed25519 signature must reject.",
        notes="One byte of the checkpoint signature line is flipped; the log key is still trusted.",
        spec=v2_spec(),
        expected_exit=10,
        rejection_code=["REKOR_INCLUSION_INVALID"],
        extra_capabilities=V2_CAP,
        mutate_bundle=tamper_checkpoint,
        **common,
    )
    write_fixture(
        fixture_id="098-rekor-v2-pae-digest-mismatch",
        title="Rekor v2 hashedrekord whose logged digest is not SHA-256(PAE) of the bundle envelope must reject.",
        notes=(
            "The log entry is internally valid (checkpoint signed over this body) but\n"
            "records a different digest, i.e. a different envelope was logged.\n"
            "Verifiers must bind data.digest to the bundle's PAE (rekor-v2-spec §6.1.4)."
        ),
        spec=v2_spec(rekor_v2_digest_override=b"\x00" * 32),
        expected_exit=10,
        rejection_code=["REKOR_INCLUSION_INVALID"],
        extra_capabilities=V2_CAP,
        **common,
    )
    write_fixture(
        fixture_id="099-rekor-v2-timestamp-outside-cert-validity",
        title="Rekor v2 entry whose RFC 3161 timestamp falls outside the signing certificate's validity must reject.",
        notes=(
            "The leaf certificate is valid for ten minutes a day before the token's genTime.\n"
            "The timestamp verifies but does not place the signature inside the cert window.\n"
            "sigstore-go reports this as a generic leaf-certificate failure (FULCIO_CHAIN_INVALID)."
        ),
        spec=v2_spec(leaf_from=NOW - timedelta(days=1)),
        expected_exit=10,
        rejection_code=["CERT_EXPIRED", "OBSERVER_TIMESTAMP_INSUFFICIENT", "FULCIO_CHAIN_INVALID"],
        extra_capabilities=V2_CAP,
        **common,
    )
    write_fixture(
        fixture_id="100-rekor-v1-set-tampered",
        title="Rekor v1 inclusion promise (SET) with a tampered signature must reject.",
        notes=(
            "The Merkle leaf covers only the entry body; integratedTime is authenticated\n"
            "solely by the signed entry timestamp. One byte of it is flipped here.\n"
            "sigstore-go skips the entry and then fails its log threshold (TLOG_COUNT_OUT_OF_RANGE)."
        ),
        spec=FixtureSpec(payload_bytes=seed_payload(), workflow_repository=DEFAULT_REPO),
        expected_exit=10,
        rejection_code=["REKOR_INCLUSION_INVALID", "TLOG_COUNT_OUT_OF_RANGE"],
        mutate_bundle=tamper_set,
        **common,
    )
    print("wrote 094-100")


if __name__ == "__main__":
    main()
