#!/usr/bin/env python3
"""Generate the container-provenance fixtures (vectors/v3/container-provenance/)
for the `v3-authenticate-containers` stage (CONFORMANCE_ADAPTER_SPEC §2.2).

A deployment config may require, per container, the GitHub Actions build of
its image (`containers[].provenance.github`). Each fixture is a v3 document
that carries a config and container-provenance entries {digest,
sigstore_bundle}; the stage reads the requirements from the config and
authenticates each image's entry against its requirement.

Most fixtures carry the recorded build attestation of
ghcr.io/tinfoilsh/measure-image-action (container_provenance_bundle.json),
which verifies under the embedded production Sigstore root, and change the
config around it. The synthetic-* fixtures carry an attestation signed under
a synthetic root (see sigstore_synth), for what a recorded certificate cannot
show. Every rejection is one change away from a document that is accepted,
and attributes to PROVENANCE_REJECTED. Emits the shared fixture format {id,
stage, input, expected}; each vector function's docstring says what it
exercises.

Run from the repo root:  uv run --with cryptography fixturegen/v3/gen_container_provenance.py

The synthetic bundles are signed with fresh ECDSA nonces, so a run rewrites
the synthetic-* fixtures with new signatures.
"""

import base64
import copy
import hashlib
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "fixturegen" / "v3"))

import sigstore_synth as ss  # noqa: E402
from gen_envelope import b64, base_doc, canon  # noqa: E402

STAGE = "v3-authenticate-containers"
OUT_DIR = REPO_ROOT / "vectors" / "v3" / "container-provenance"

COLLATERAL_V3 = "https://tinfoil.sh/predicate/attestation-collaterals/v3"
CONFIG_FMT = "https://tinfoil.sh/collateral/config/v1"
CONTAINER_FMT = "https://tinfoil.sh/collateral/container-provenance/v1"
CONFIG_ID = "tinfoil-config"
CONTAINER_ID_PREFIX = "container:sha256:"
ROLE_RV = "reference-values"

STATEMENT_V1 = "https://in-toto.io/Statement/v1"
SLSA_V1 = "https://slsa.dev/provenance/v1"
GITHUB = "https://github.com/"

# The recorded attestation, and the build that it proves.
RECORDED_BUNDLE = json.loads((Path(__file__).parent / "container_provenance_bundle.json").read_text())
IMAGE = "ghcr.io/tinfoilsh/measure-image-action"
DIGEST = "85306e3ab312a2d80466e901081e855cc53f21c4802c638f861e6ef31ba4f5d1"
REPOSITORY = "tinfoilsh/measure-image-action"
REPOSITORY_ID = "924941172"
WORKFLOW = "build.yml"
TAG = "build-v0.14.2"
REF = "refs/tags/" + TAG
COMMIT = "01a05df207140a8e8e1d2cd26028ab7c51dad9d1"

# An image and a commit that the recorded attestation does not name.
OTHER_DIGEST = hashlib.sha256(b"container-image-other").hexdigest()
OTHER_COMMIT = hashlib.sha1(b"container-source-commit-other").hexdigest()

ACCEPT = {"accepted": True}
REJECT = {"accepted": False, "code": "PROVENANCE_REJECTED"}


# --- Config ------------------------------------------------------------------
def github(**changes):
    """The provenance.github members that the recorded build meets, with
    `changes` applied; a change to None drops the member."""
    members = {"repository": REPOSITORY, "repository_id": REPOSITORY_ID, "workflow": WORKFLOW, "ref": REF,
               "commit": COMMIT, **changes}
    return {name: value for name, value in members.items() if value is not None}


def pinned(digest=DIGEST):
    return f"{IMAGE}@sha256:{digest}"


def container(image=pinned(), name="app", **members):
    """One containers[] item; `members` are its members besides name and image."""
    return {"name": name, "image": image, **members}


def config(*containers):
    return json.dumps({"containers": containers}, sort_keys=True, separators=(",", ":")).encode()


def requiring(**changes):
    """A config whose one container requires the recorded build, with
    `changes` applied to the github members."""
    return config(container(provenance={"github": github(**changes)}))


# --- Entries -----------------------------------------------------------------
def entry(bundle=RECORDED_BUNDLE, digest=DIGEST, entry_id=None):
    """A container-provenance collateral entry for the image `digest`."""
    return {"id": entry_id or CONTAINER_ID_PREFIX + digest, "role": ROLE_RV, "format": CONTAINER_FMT,
            "data": {"digest": digest, "sigstore_bundle": bundle}}


def unverifiable_bundle():
    """The recorded bundle with one bit of its signature changed."""
    bundle = copy.deepcopy(RECORDED_BUNDLE)
    signature = bundle["dsseEnvelope"]["signatures"][0]
    raw = bytearray(base64.b64decode(signature["sig"]))
    raw[-1] ^= 1
    signature["sig"] = b64(bytes(raw))
    return bundle


def synthetic(identity_repository=REPOSITORY, source_repository=REPOSITORY, source_ref=REF, predicate_type=SLSA_V1):
    """(entry, trusted root) for an attestation of the image under the
    synthetic root: a run at `source_ref` and COMMIT of `source_repository`,
    which has REPOSITORY_ID, signed by the WORKFLOW file of
    `identity_repository` at REF."""
    statement = canon({"_type": STATEMENT_V1, "subject": [{"name": IMAGE, "digest": {"sha256": DIGEST}}],
                       "predicateType": predicate_type, "predicate": {}})
    bundle, root = ss.build_bundle(
        f"{GITHUB}{identity_repository}/.github/workflows/{WORKFLOW}@{REF}", statement,
        source_repo_uri=GITHUB + source_repository, source_repo_id=REPOSITORY_ID, source_ref=source_ref,
        source_digest=COMMIT)
    return entry(bundle), root


# Each vector returns (config bytes, entries, expected), and the trusted root
# to verify under when that is not the embedded one.
def build_matches():
    """The requirement names the repository, repository ID, workflow, ref and commit of the recorded build."""
    return requiring(), [entry()], ACCEPT


# One member of the requirement is not what the recorded certificate states.
def build_other_repository_id():
    """The requirement names the repository under another ID."""
    return requiring(repository_id="92494117"), [entry()], REJECT


def build_other_workflow():
    """The requirement names another workflow of the repository."""
    return requiring(workflow="release.yml"), [entry()], REJECT


def build_other_commit():
    """The requirement names another commit."""
    return requiring(commit=OTHER_COMMIT), [entry()], REJECT


def build_ref_with_wildcard():
    """The requirement writes the ref with a "*" in place of the end of the build's tag; the "*" stands for itself."""
    return requiring(ref="refs/tags/build-v*"), [entry()], REJECT


def build_of_another_image():
    """The entry for the required image carries the attestation of another image."""
    return (config(container(pinned(OTHER_DIGEST), provenance={"github": github()})),
            [entry(digest=OTHER_DIGEST)], REJECT)


# The entry of an image.
def entry_missing():
    """The config requires a build and the document carries no entry."""
    return requiring(), [], REJECT


def entry_first_wins():
    """Two entries name the image; the first, under another id, does not verify, and the valid second one does not replace it."""
    return requiring(), [entry(unverifiable_bundle(), entry_id="container-other"), entry()], REJECT


# Reading the requirements. A config that requires nothing comes without an
# entry, and one that cannot be read comes with the entry that the readable
# requirement accepts.
def config_no_provenance_image_not_string():
    """A container that declares no provenance is not read further: its image is a number."""
    return config(container(image=7)), [], ACCEPT


def config_provenance_null():
    """A null provenance member is a requirement that cannot be read, not the absence of one."""
    return config(container(provenance=None)), [entry()], REJECT


def config_provenance_unknown_kind():
    """The provenance member carries a kind of requirement beside the GitHub one."""
    return config(container(provenance={"github": github(), "gitlab": {}})), [entry()], REJECT


def config_github_unknown_member():
    """The GitHub requirement carries a member beside the five it defines."""
    return requiring(environment="release"), [entry()], REJECT


def config_github_missing_member():
    """The GitHub requirement names no commit."""
    return requiring(commit=None), [entry()], REJECT


def config_github_number_member():
    """The repository ID is a number, not a string."""
    return requiring(repository_id=int(REPOSITORY_ID)), [entry()], REJECT


def config_containers_null():
    """A null containers member is not an array, and is not the absence of the member."""
    return b'{"containers":null}', [], REJECT


def config_image_without_digest():
    """The container declares provenance for an image named by tag."""
    return config(container(f"{IMAGE}:{TAG}", provenance={"github": github()})), [entry()], REJECT


def config_not_json():
    """The config states the requirement in bytes that are not JSON."""
    members = "".join(f"        {name}: {json.dumps(value)}\n" for name, value in github().items())
    text = f"containers:\n  - name: app\n    image: {pinned()}\n    provenance:\n      github:\n{members}"
    return text.encode(), [entry()], REJECT


# What the recorded certificate cannot show, under the synthetic root. Each
# rejected certificate differs from the accepted one in a single respect.
def synthetic_matches():
    """A synthetic attestation of the image that meets the requirement."""
    proof, root = synthetic()
    return requiring(), [proof], ACCEPT, root


def synthetic_run_of_another_repository():
    """The run is of a repository with another name; the repository ID, workflow identity, ref and commit are the required ones."""
    proof, root = synthetic(source_repository="example/measure-image-action")
    return requiring(), [proof], REJECT, root


def synthetic_workflow_of_another_repository():
    """The workflow that signed is another repository's file of the same name at the same ref; the run is the required one."""
    proof, root = synthetic(identity_repository="example/shared-workflows")
    return requiring(), [proof], REJECT, root


def synthetic_run_from_another_ref():
    """The run is from a branch at the required commit and calls the required workflow at the required ref."""
    proof, root = synthetic(source_ref="refs/heads/main")
    return requiring(), [proof], REJECT, root


def synthetic_predicate_type():
    """The required workflow attested the image with a predicate that is not SLSA provenance v1."""
    proof, root = synthetic(predicate_type="https://spdx.dev/Document/v2.3")
    return requiring(), [proof], REJECT, root


VECTORS = {
    "build-matches": build_matches,
    "build-other-repository-id": build_other_repository_id,
    "build-other-workflow": build_other_workflow,
    "build-other-commit": build_other_commit,
    "build-ref-with-wildcard": build_ref_with_wildcard,
    "build-of-another-image": build_of_another_image,
    "entry-missing": entry_missing,
    "entry-first-wins": entry_first_wins,
    "config-no-provenance-image-not-string": config_no_provenance_image_not_string,
    "config-provenance-null": config_provenance_null,
    "config-provenance-unknown-kind": config_provenance_unknown_kind,
    "config-github-unknown-member": config_github_unknown_member,
    "config-github-missing-member": config_github_missing_member,
    "config-github-number-member": config_github_number_member,
    "config-containers-null": config_containers_null,
    "config-image-without-digest": config_image_without_digest,
    "config-not-json": config_not_json,
    "synthetic-matches": synthetic_matches,
    "synthetic-run-of-another-repository": synthetic_run_of_another_repository,
    "synthetic-workflow-of-another-repository": synthetic_workflow_of_another_repository,
    "synthetic-run-from-another-ref": synthetic_run_from_another_ref,
    "synthetic-predicate-type": synthetic_predicate_type,
}


def document(config_bytes, entries):
    doc = base_doc()
    doc["collateral_format"] = COLLATERAL_V3
    doc["collateral"] = [{"id": CONFIG_ID, "role": ROLE_RV, "format": CONFIG_FMT,
                          "data": {"config_base64": b64(config_bytes)}}, *entries]
    return doc


def fixture(fid, config_bytes, entries, expected, root=None):
    fixture_input = {
        "schema_version": "1",
        "document_b64": b64(canon(document(config_bytes, entries))),
        "nonce_hex": "",
    }
    if root is not None:
        fixture_input["sigstore_trusted_root_json_b64"] = b64(json.dumps(root).encode())
    return {"id": fid, "stage": STAGE, "input": fixture_input, "expected": expected}


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    for fid, vector in VECTORS.items():
        with open(OUT_DIR / (fid + ".json"), "w") as fh:
            fh.write(json.dumps(fixture(fid, *vector()), indent=2) + "\n")
    print(f"wrote {len(VECTORS)} container-provenance fixtures to {OUT_DIR.relative_to(REPO_ROOT)}/")


if __name__ == "__main__":
    main()
