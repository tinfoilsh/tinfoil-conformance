#!/usr/bin/env python3
"""Generate the container-provenance fixtures (vectors/v3/container-provenance/)
for the `v3-authenticate-containers` stage (CONFORMANCE_ADAPTER_SPEC §2.2,
SPEC_COVERAGE_V3 C-rules).

A deployment config may require, per container, the GitHub Actions build of
its image (`containers[].provenance.github`). Each fixture is a v3 document
carrying the config bytes (the `tinfoil-config` entry) and, per image, a
container-provenance entry {digest, sigstore_bundle} whose bundle is a SLSA v1
build attestation signed under a synthetic Sigstore root (see sigstore_synth).
The stage reads the requirements from the config, finds each image's proof by
digest and authenticates it against its requirement.

The happy document accepts and reports one result per requirement; every
rejection is a single change to the config or to a proof and attributes to
PROVENANCE_REJECTED. Emits the shared fixture format {id, stage, input,
expected}; each vector function's docstring says what it exercises.

Run from the repo root:  uv run --with cryptography fixturegen/v3/gen_container_provenance.py [id ...]

Bundles are signed with fresh ECDSA nonces, so a run rewrites every fixture it
generates with new signatures. Name fixture ids to generate only those and
leave the others as they are.
"""

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

# The build the happy config requires, and the run that satisfies it.
REPOSITORY = "example/app"
REPOSITORY_ID = "123456789"
WORKFLOW = "release.yml"
REF_PATTERN = "refs/tags/v*"
REF = "refs/tags/v1.4.2"
COMMIT = hashlib.sha1(b"container-source-commit").hexdigest()  # 40-hex source commit
IMAGE = "ghcr.io/example/app"
DIGEST = hashlib.sha256(b"container-image-app").hexdigest()
PINNED_IMAGE = f"{IMAGE}@sha256:{DIGEST}"

# A second image, built by another repository's workflow from a branch.
OTHER_REPOSITORY = "example/worker"
OTHER_REPOSITORY_ID = "987654321"
OTHER_WORKFLOW = "images.yaml"
OTHER_REF = "refs/heads/main"
OTHER_COMMIT = hashlib.sha1(b"container-source-commit-worker").hexdigest()
OTHER_IMAGE = "ghcr.io/example/worker"
OTHER_DIGEST = hashlib.sha256(b"container-image-worker").hexdigest()

# An image no requirement names.
UNCONSTRAINED_IMAGE = "ghcr.io/example/sidecar@sha256:" + hashlib.sha256(b"container-image-sidecar").hexdigest()

# A repository that calls the required workflow from its own run.
CALLER_REPOSITORY = "attacker/fork"
CALLER_REPOSITORY_ID = "555555555"

# The longest repository name, workflow file name and ref pattern a requirement
# may carry, and the most digits of its repository ID.
MAX_REPOSITORY_LENGTH = 140
MAX_WORKFLOW_LENGTH = 255
MAX_REF_LENGTH = 255
MAX_REPOSITORY_ID_DIGITS = 18

CONFIG_HEAD = (
    "cvm-version: 0.15.5@sha256:" + hashlib.sha256(b"container-runtime-manifest").hexdigest() + "\n"
    "security:\n"
    "  include-config-in-attestation: true\n"
)


# --- Config ------------------------------------------------------------------
def github(repository=REPOSITORY, repository_id=REPOSITORY_ID, workflow=WORKFLOW, ref=REF_PATTERN, extra=()):
    """The members of a provenance.github mapping, as YAML lines. None drops a
    member; extra appends (key, value) members after the four known ones."""
    members = [("repository", repository), ("repository_id", repository_id),
               ("workflow", workflow), ("ref", ref), *extra]
    return "".join(f"        {key}: {value}\n" for key, value in members if value is not None)


def github_flow():
    """The happy provenance.github mapping in YAML flow style."""
    return ("{" + f"repository: {REPOSITORY}, repository_id: {REPOSITORY_ID}, "
            f"workflow: {WORKFLOW}, ref: {REF_PATTERN}" + "}")


def provenance(members=None, siblings=""):
    """A container's provenance member requiring a GitHub build; siblings are
    raw YAML lines beside the github mapping."""
    return "    provenance:\n      github:\n" + (github() if members is None else members) + siblings


def container(name="app", image=PINNED_IMAGE, requirement=None):
    """One containers[] item. requirement is the raw YAML of its provenance
    member (default: the happy requirement); "" declares none."""
    return f"  - name: {name}\n    image: {image}\n" + (provenance() if requirement is None else requirement)


def config(*containers):
    return (CONFIG_HEAD + "containers:\n" + "".join(containers or (container(),))).encode()


# --- Proof -------------------------------------------------------------------
def statement(digest=DIGEST, name=IMAGE, statement_type=STATEMENT_V1, predicate_type=SLSA_V1, subjects=None):
    if subjects is None:
        subjects = [{"name": name, "digest": {"sha256": digest}}]
    return json.dumps({
        "_type": statement_type,
        "subject": subjects,
        "predicateType": predicate_type,
        "predicate": {
            "buildDefinition": {"buildType": "https://actions.github.io/buildtypes/workflow/v1"},
            "runDetails": {"builder": {"id": "https://github.com/actions/runner/github-hosted"}},
        },
    }, separators=(",", ":")).encode()


def bundle(repository=REPOSITORY, workflow=WORKFLOW, ref=REF, *, workflow_ref=None, source_repository=None,
           source_repository_id=REPOSITORY_ID, source_ref=None, source_commit=COMMIT, stmt=None, **kw):
    """A build attestation signed by `workflow` of `repository` in a run on
    `ref`. The signing identity names the workflow file at workflow_ref, and
    the certificate's source fields name the repository, ref and commit that
    triggered the run; both default to the same repository and ref, as for a
    workflow that runs in its own repository."""
    identity = f"{GITHUB}{repository}/.github/workflows/{workflow}@{workflow_ref or ref}"
    signed, _ = ss.build_bundle(
        identity, statement() if stmt is None else stmt,
        source_repo_uri=GITHUB + (source_repository or repository), source_repo_id=source_repository_id,
        source_ref=source_ref or ref, source_digest=source_commit, **kw)
    return signed


def other_bundle():
    """The build attestation of the second image."""
    return bundle(OTHER_REPOSITORY, OTHER_WORKFLOW, OTHER_REF, source_repository_id=OTHER_REPOSITORY_ID,
                  source_commit=OTHER_COMMIT, stmt=statement(OTHER_DIGEST, OTHER_IMAGE))


def proof(signed=None, digest=DIGEST, entry_id=None):
    """A container-provenance collateral entry for the image `digest`."""
    return {"id": entry_id or CONTAINER_ID_PREFIX + digest, "role": ROLE_RV, "format": CONTAINER_FMT,
            "data": {"digest": digest, "sigstore_bundle": bundle() if signed is None else signed}}


# Every bundle is signed under the same synthetic keys, so one trusted root
# verifies them all.
_, TRUSTED_ROOT = ss.build_bundle(GITHUB + REPOSITORY, statement())


# --- Expected ----------------------------------------------------------------
def result(name="app", digest=DIGEST, repository=REPOSITORY, workflow=WORKFLOW, ref=REF, commit=COMMIT):
    return {"container": name, "digest": digest, "repository": repository, "workflow": workflow,
            "ref": ref, "commit": commit}


def accept(*containers):
    return {"accepted": True, "containers": list(containers)}


def reject():
    return {"accepted": False, "code": "PROVENANCE_REJECTED"}


# Each vector returns (config, proofs, expected), and optionally the trusted
# root to verify under; its docstring is the rule it exercises.
def happy():
    """One container requires a build from a tag series; its proof is a SLSA v1 attestation of the image by that workflow on a matching tag."""
    return config(), [proof()], accept(result())


# Positive variations: valid alternatives that must accept, and the results
# they must report.
def pos_exact_ref():
    """The requirement names one tag exactly, without a wildcard."""
    return config(container(requirement=provenance(github(ref=REF)))), [proof()], accept(result())


def pos_branch_pattern():
    """The requirement names a branch series; the wildcard stands for the last ref segment."""
    ref = "refs/heads/release/2026"
    return (config(container(requirement=provenance(github(ref="refs/heads/release/*")))),
            [proof(bundle(ref=ref))], accept(result(ref=ref)))


def pos_two_containers():
    """Two containers require different builds and a third requires none; the proofs are found by image digest, whatever their order, and reported in config order."""
    web = container("web")
    sidecar = container("sidecar", UNCONSTRAINED_IMAGE, "")
    worker = container("worker", f"{OTHER_IMAGE}@sha256:{OTHER_DIGEST}", provenance(github(
        repository=OTHER_REPOSITORY, repository_id=OTHER_REPOSITORY_ID, workflow=OTHER_WORKFLOW, ref=OTHER_REF)))
    return (config(web, sidecar, worker), [proof(other_bundle(), OTHER_DIGEST), proof()],
            accept(result("web"), result("worker", OTHER_DIGEST, OTHER_REPOSITORY, OTHER_WORKFLOW, OTHER_REF,
                                         OTHER_COMMIT)))


def pos_yaml_alias():
    """Two containers run the same image and share one requirement through a YAML alias; the one proof serves both."""
    primary = container("primary", requirement="    provenance: &build\n      github:\n" + github())
    replica = container("replica", requirement="    provenance: *build\n")
    return config(primary, replica), [proof()], accept(result("primary"), result("replica"))


def pos_yaml_merge_key():
    """The second container takes its image and requirement from the first through a YAML merge key."""
    primary = f"  - &primary\n    name: primary\n    image: {PINNED_IMAGE}\n" + provenance()
    replica = "  - <<: *primary\n    name: replica\n"
    return config(primary, replica), [proof()], accept(result("primary"), result("replica"))


def pos_workflow_ref_differs():
    """The workflow file is taken from one matching tag and the run is on another; the reported ref is the run's."""
    return config(), [proof(bundle(workflow_ref="refs/tags/v1.4.0"))], accept(result())


def pos_first_proof_wins():
    """Two entries name the image; the first is its proof and the second, from another workflow, is not used."""
    return (config(), [proof(), proof(bundle(workflow="build.yml"), entry_id="container-extra")],
            accept(result()))


def long_repository(length):
    """A repository name of `length` characters."""
    owner = "example/"
    return owner + "a" * (length - len(owner))


def long_workflow(length):
    """A workflow file name of `length` characters."""
    extension = ".yml"
    return "w" * (length - len(extension)) + extension


def long_ref(length):
    """A ref pattern of `length` characters that matches every tag REF_PATTERN does."""
    return REF_PATTERN + "*" * (length - len(REF_PATTERN))


def pos_repository_at_limit():
    """The repository name is exactly as long as a requirement allows."""
    repository = long_repository(MAX_REPOSITORY_LENGTH)
    return (config(container(requirement=provenance(github(repository=repository)))),
            [proof(bundle(repository))], accept(result(repository=repository)))


def pos_workflow_at_limit():
    """The workflow file name is exactly as long as a requirement allows."""
    workflow = long_workflow(MAX_WORKFLOW_LENGTH)
    return (config(container(requirement=provenance(github(workflow=workflow)))),
            [proof(bundle(workflow=workflow))], accept(result(workflow=workflow)))


def pos_ref_at_limit():
    """The ref pattern is exactly as long as a requirement allows."""
    ref = long_ref(MAX_REF_LENGTH)
    return config(container(requirement=provenance(github(ref=ref)))), [proof()], accept(result())


# A tag ref pattern with as many wildcards as fit under the length bound while
# each is followed by a literal: refs/tags/*a*a…*a, padded to the bound with
# the literal. Matching a run of that literal against it is cheap in time
# polynomial in the two lengths, while a matcher that backtracks tries every
# way to share the run out among the wildcards.
TAG_PREFIX = "refs/tags/"
WILDCARD_LITERAL = "a"
OTHER_LITERAL = "b"


def many_wildcards():
    """The pattern, and the longest ref under the bound that it matches."""
    unit = "*" + WILDCARD_LITERAL
    pattern = TAG_PREFIX + unit * ((MAX_REF_LENGTH - len(TAG_PREFIX)) // len(unit))
    pattern += WILDCARD_LITERAL * (MAX_REF_LENGTH - len(pattern))
    return pattern, TAG_PREFIX + WILDCARD_LITERAL * (MAX_REF_LENGTH - len(TAG_PREFIX))


def pos_many_wildcards():
    """The ref pattern is as many wildcards as fit, each followed by the same character; the run is on a tag made of that character alone."""
    pattern, ref = many_wildcards()
    return (config(container(requirement=provenance(github(ref=pattern)))),
            [proof(bundle(ref=ref))], accept(result(ref=ref)))


def long_repository_id(digits):
    """A repository ID of `digits` decimal digits."""
    cycle = "1234567890"
    return (cycle * digits)[:digits]


def pos_repository_id_at_limit():
    """The repository ID has as many digits as a requirement allows, more than a double-precision number holds exactly."""
    repository_id = long_repository_id(MAX_REPOSITORY_ID_DIGITS)
    return (config(container(requirement=provenance(github(repository_id=repository_id)))),
            [proof(bundle(source_repository_id=repository_id))], accept(result()))


def pos_no_requirement():
    """No container declares provenance: the config requires no build and the result is empty."""
    return config(container(requirement="")), [], accept()


def pos_null_requirement():
    """A null provenance member declares no requirement."""
    return config(container(requirement="    provenance:\n")), [], accept()


# C1: the requirement is read fail-closed. Each unreadable requirement comes
# with the proof the readable one would accept.
def c1_unknown_kind():
    """The requirement carries a kind of provenance the verifier cannot read beside the GitHub one."""
    siblings = "      gitlab:\n        project: example/app\n"
    return config(container(requirement=provenance(siblings=siblings))), [proof()], reject()


def c1_unknown_detail():
    """The GitHub requirement carries a member the verifier cannot read."""
    members = github(extra=[("environment", "release")])
    return config(container(requirement=provenance(members))), [proof()], reject()


def c1_repeated_member():
    """The GitHub requirement repeats a member; the last value alone would match the proof."""
    members = github(ref="refs/heads/main", extra=[("ref", REF_PATTERN)])
    return config(container(requirement=provenance(members))), [proof()], reject()


def c1_empty():
    """An empty provenance mapping is a requirement without a build, not the absence of one."""
    return config(container(requirement="    provenance: {}\n")), [proof()], reject()


# A mapping under an explicit null tag is neither a requirement the verifier
# reads nor the absence of one. These two carry no proof, so only reading the
# mapping as "no requirement" accepts.
def c1_null_tagged_requirement():
    """The provenance member is a mapping under an explicit null tag."""
    tagged = "    provenance: !!null {github: " + github_flow() + "}\n"
    return config(container(requirement=tagged)), [], reject()


def c1_null_tagged_detail():
    """The GitHub requirement is a mapping under an explicit null tag."""
    tagged = "    provenance:\n      github: !!null " + github_flow() + "\n"
    return config(container(requirement=tagged)), [], reject()


def c1_two_documents():
    """The config holds a second YAML document after the one that declares the requirement."""
    return config() + b"---\ncontainers: []\n", [proof()], reject()


def c1_no_config():
    """The document carries a proof but no config to read the requirement from."""
    return None, [proof()], reject()


# C2: the requirement's values. Each proof matches the out-of-range value, so
# only the check on the value rejects.
def c2_repository_oversized():
    """The repository name is one character longer than a requirement allows; the proof is from that repository."""
    repository = long_repository(MAX_REPOSITORY_LENGTH + 1)
    return (config(container(requirement=provenance(github(repository=repository)))),
            [proof(bundle(repository))], reject())


def c2_workflow_oversized():
    """The workflow file name is one character longer than a requirement allows; the proof is from that workflow."""
    workflow = long_workflow(MAX_WORKFLOW_LENGTH + 1)
    return (config(container(requirement=provenance(github(workflow=workflow)))),
            [proof(bundle(workflow=workflow))], reject())


def c2_ref_oversized():
    """The ref pattern is one character longer than a requirement allows; it would match the proof."""
    ref = long_ref(MAX_REF_LENGTH + 1)
    return config(container(requirement=provenance(github(ref=ref)))), [proof()], reject()


def c2_no_repository_id():
    """The requirement names no repository ID."""
    return config(container(requirement=provenance(github(repository_id=None)))), [proof()], reject()


# The repository ID is an integer written in plain decimal. YAML libraries
# read the other spellings differently, so each comes with a proof from the
# repository whose ID a reader that accepted the spelling would take it for.
def repository_id_spelling(spelling, read_as=REPOSITORY_ID):
    return (config(container(requirement=provenance(github(repository_id=spelling)))),
            [proof(bundle(source_repository_id=read_as))], reject())


# The happy repository ID with a leading zero: all its digits are octal, so
# it reads as one number in octal and as another in decimal.
LEADING_ZERO_ID = "0" + format(int(REPOSITORY_ID), "o")


def c2_repository_id_hex():
    """The repository ID is written in hexadecimal."""
    return repository_id_spelling(hex(int(REPOSITORY_ID)))


def c2_repository_id_octal():
    """The repository ID is written in octal with the 0o prefix."""
    return repository_id_spelling(oct(int(REPOSITORY_ID)))


def c2_repository_id_leading_zero_octal():
    """The repository ID has a leading zero; the proof is from the repository it names when read as octal."""
    return repository_id_spelling(LEADING_ZERO_ID, read_as=str(int(LEADING_ZERO_ID, 8)))


def c2_repository_id_leading_zero_decimal():
    """The repository ID has a leading zero; the proof is from the repository it names when read as decimal."""
    return repository_id_spelling(LEADING_ZERO_ID, read_as=str(int(LEADING_ZERO_ID)))


def c2_repository_id_sign():
    """The repository ID carries a plus sign."""
    return repository_id_spelling("+" + REPOSITORY_ID)


def c2_repository_id_grouped():
    """The repository ID groups its digits with underscores."""
    return repository_id_spelling(format(int(REPOSITORY_ID), "_"))


def c2_repository_id_float():
    """The repository ID is written as a floating-point number with an exponent."""
    return repository_id_spelling(f"{REPOSITORY_ID[0]}.{REPOSITORY_ID[1:]}e{len(REPOSITORY_ID) - 1}")


def c2_repository_id_string():
    """The repository ID is a quoted string of digits."""
    return repository_id_spelling(f'"{REPOSITORY_ID}"')


def c2_repository_id_list():
    """The repository ID is a one-item list."""
    return repository_id_spelling(f"[{REPOSITORY_ID}]")


def c2_repository_id_negative():
    """The repository ID is negative; the certificate carries the same text."""
    negative = "-" + REPOSITORY_ID
    return repository_id_spelling(negative, read_as=negative)


def c2_repository_id_zero():
    """The repository ID is zero; the certificate carries the same text."""
    zero = "0"
    return repository_id_spelling(zero, read_as=zero)


def c2_repository_id_oversized():
    """The repository ID has one digit more than a requirement allows; the proof is from that repository."""
    repository_id = long_repository_id(MAX_REPOSITORY_ID_DIGITS + 1)
    return repository_id_spelling(repository_id, read_as=repository_id)


def c2_workflow_path():
    """The required workflow is a path, not a file name; the proof's identity carries that path."""
    workflow = "nested/release.yml"
    return (config(container(requirement=provenance(github(workflow=workflow)))),
            [proof(bundle(workflow=workflow))], reject())


def c2_ref_kind():
    """The required ref pattern names pull-request refs; the proof's run is on one."""
    return (config(container(requirement=provenance(github(ref="refs/pull/*/merge")))),
            [proof(bundle(ref="refs/pull/7/merge"))], reject())


def c2_image_not_pinned():
    """The container declares provenance for an image named by tag, without a digest."""
    return config(container(image=IMAGE + ":1.4.2")), [proof()], reject()


# C3: the proof is the first entry for the image digest.
def c3_missing_proof():
    """The config requires a build and the document carries no proof."""
    return config(), [], reject()


def c3_proof_for_another_image():
    """The only proof in the document is a valid one for another image."""
    return config(), [proof(other_bundle(), OTHER_DIGEST)], reject()


def c3_first_proof_wins():
    """Two entries name the image; the first is from another workflow, and the valid second one does not replace it."""
    return (config(), [proof(bundle(workflow="build.yml")), proof(entry_id="container-extra")], reject())


# C4: the bundle itself.
def c4_untrusted_ca():
    """The proof is valid under a certificate authority the trusted root does not list."""
    root = copy.deepcopy(TRUSTED_ROOT)
    root["certificateAuthorities"][0]["certChain"]["certificates"] = ss.rogue_ca_cert_chain()
    return config(), [proof()], reject(), root


def c4_issuer():
    """The certificate's OIDC issuer is not GitHub Actions."""
    return config(), [proof(bundle(issuer="https://accounts.evil.example"))], reject()


def c4_runner():
    """The build ran on a self-hosted runner."""
    return config(), [proof(bundle(runner_environment="self-hosted"))], reject()


# C5: the signing identity.
def c5_repository():
    """The image was built by the same workflow file name in another repository."""
    return (config(), [proof(bundle(OTHER_REPOSITORY, source_repository_id=OTHER_REPOSITORY_ID))], reject())


def c5_workflow():
    """The image was built by another workflow of the required repository."""
    return config(), [proof(bundle(workflow="build.yml"))], reject()


def c5_workflow_dot():
    """The dot of the workflow file name is not a wildcard."""
    return config(), [proof(bundle(workflow="releasexyml"))], reject()


def c5_tag_series():
    """The run is on a tag outside the required series."""
    return config(), [proof(bundle(ref="refs/tags/nightly-20261101"))], reject()


def c5_branch():
    """The run is on a branch where a tag series is required."""
    return config(), [proof(bundle(ref="refs/heads/main"))], reject()


def c5_pull_request():
    """The run is on a pull-request ref where a tag series is required."""
    return config(), [proof(bundle(ref="refs/pull/7/merge"))], reject()


def c5_wildcard_slash():
    """The wildcard does not match across a ref separator."""
    return config(), [proof(bundle(ref="refs/tags/v1/4.2"))], reject()


def c5_ref_dot():
    """The dots of an exact ref are not wildcards."""
    return (config(container(requirement=provenance(github(ref=REF)))),
            [proof(bundle(ref="refs/tags/v1x4x2"))], reject())


def c5_ref_longer():
    """The run is on a tag that only begins with the exact ref required."""
    return (config(container(requirement=provenance(github(ref=REF)))),
            [proof(bundle(ref=REF + "0"))], reject())


def c5_workflow_ref():
    """The run is on a matching tag but the workflow file is taken from a branch."""
    return config(), [proof(bundle(workflow_ref="refs/heads/main"))], reject()


# C6 and C7: the statement.
def c6_another_image():
    """The entry names the required image but its attestation's subject is another image."""
    return config(), [proof(bundle(stmt=statement(OTHER_DIGEST, OTHER_IMAGE)))], reject()


def c6_second_subject():
    """The image digest is carried by the attestation's second subject, not its first."""
    stmt = statement(subjects=[{"name": OTHER_IMAGE, "digest": {"sha256": OTHER_DIGEST}},
                               {"name": IMAGE, "digest": {"sha256": DIGEST}}])
    return config(), [proof(bundle(stmt=stmt))], reject()


def c7_predicate_type():
    """The required workflow attested the image with a predicate that is not SLSA provenance v1."""
    return config(), [proof(bundle(stmt=statement(predicate_type="https://spdx.dev/Document/v2.3")))], reject()


def c7_statement_type():
    """The attestation's statement is not an in-toto v1 statement."""
    stmt = statement(statement_type="https://in-toto.io/Statement/v0.1")
    return config(), [proof(bundle(stmt=stmt))], reject()


# C8 and C9: the run the certificate's source fields name. Each signing
# identity matches the requirement, so only the source check rejects.
def c8_called_from_another_repository():
    """Another repository's run called the required workflow: the signing identity matches, the source repository does not."""
    signed = bundle(source_repository=CALLER_REPOSITORY, source_repository_id=CALLER_REPOSITORY_ID)
    return config(), [proof(signed)], reject()


def c8_repository_uri():
    """The certificate's source repository URI names another repository under the required repository's ID."""
    return config(), [proof(bundle(source_repository=CALLER_REPOSITORY))], reject()


def c8_repository_id():
    """The source repository carries the required name under another ID, as a deleted and recreated repository does."""
    return config(), [proof(bundle(source_repository_id=CALLER_REPOSITORY_ID))], reject()


def c8_no_repository_id():
    """The certificate carries no source repository ID."""
    return config(), [proof(bundle(source_repository_id=None))], reject()


def c9_source_ref():
    """The workflow file is taken from a matching tag but the run is on a branch."""
    return config(), [proof(bundle(source_ref="refs/heads/main"))], reject()


def c9_commit():
    """The certificate's source digest is one character short of a Git commit."""
    return config(), [proof(bundle(source_commit=COMMIT[:-1]))], reject()


# C11: matching a ref takes time polynomial in the lengths of the pattern
# and the ref.
def c11_wildcards_near_miss():
    """The many-wildcard pattern against a tag that differs from a matching one in its last character alone: it does not match, and a matcher that backtracks over the wildcards does not finish."""
    pattern, ref = many_wildcards()
    near_miss = ref[:-1] + OTHER_LITERAL
    return (config(container(requirement=provenance(github(ref=pattern)))),
            [proof(bundle(ref=near_miss))], reject())


VECTORS = {
    "containers-happy": happy,
    "containers-pos-exact-ref": pos_exact_ref,
    "containers-pos-branch-pattern": pos_branch_pattern,
    "containers-pos-two-containers": pos_two_containers,
    "containers-pos-yaml-alias": pos_yaml_alias,
    "containers-pos-yaml-merge-key": pos_yaml_merge_key,
    "containers-pos-workflow-ref-differs": pos_workflow_ref_differs,
    "containers-pos-first-proof-wins": pos_first_proof_wins,
    "containers-pos-repository-at-limit": pos_repository_at_limit,
    "containers-pos-workflow-at-limit": pos_workflow_at_limit,
    "containers-pos-ref-at-limit": pos_ref_at_limit,
    "containers-pos-repository-id-at-limit": pos_repository_id_at_limit,
    "containers-pos-many-wildcards": pos_many_wildcards,
    "containers-pos-no-requirement": pos_no_requirement,
    "containers-pos-null-requirement": pos_null_requirement,
    "c1-unknown-kind": c1_unknown_kind,
    "c1-unknown-detail": c1_unknown_detail,
    "c1-repeated-member": c1_repeated_member,
    "c1-empty": c1_empty,
    "c1-null-tagged-requirement": c1_null_tagged_requirement,
    "c1-null-tagged-detail": c1_null_tagged_detail,
    "c1-two-documents": c1_two_documents,
    "c1-no-config": c1_no_config,
    "c2-repository-oversized": c2_repository_oversized,
    "c2-workflow-oversized": c2_workflow_oversized,
    "c2-ref-oversized": c2_ref_oversized,
    "c2-no-repository-id": c2_no_repository_id,
    "c2-repository-id-hex": c2_repository_id_hex,
    "c2-repository-id-octal": c2_repository_id_octal,
    "c2-repository-id-leading-zero-octal": c2_repository_id_leading_zero_octal,
    "c2-repository-id-leading-zero-decimal": c2_repository_id_leading_zero_decimal,
    "c2-repository-id-sign": c2_repository_id_sign,
    "c2-repository-id-grouped": c2_repository_id_grouped,
    "c2-repository-id-float": c2_repository_id_float,
    "c2-repository-id-string": c2_repository_id_string,
    "c2-repository-id-list": c2_repository_id_list,
    "c2-repository-id-negative": c2_repository_id_negative,
    "c2-repository-id-zero": c2_repository_id_zero,
    "c2-repository-id-oversized": c2_repository_id_oversized,
    "c2-workflow-path": c2_workflow_path,
    "c2-ref-kind": c2_ref_kind,
    "c2-image-not-pinned": c2_image_not_pinned,
    "c3-missing-proof": c3_missing_proof,
    "c3-proof-for-another-image": c3_proof_for_another_image,
    "c3-first-proof-wins": c3_first_proof_wins,
    "c4-untrusted-ca": c4_untrusted_ca,
    "c4-issuer": c4_issuer,
    "c4-runner": c4_runner,
    "c5-repository": c5_repository,
    "c5-workflow": c5_workflow,
    "c5-workflow-dot": c5_workflow_dot,
    "c5-tag-series": c5_tag_series,
    "c5-branch": c5_branch,
    "c5-pull-request": c5_pull_request,
    "c5-wildcard-slash": c5_wildcard_slash,
    "c5-ref-dot": c5_ref_dot,
    "c5-ref-longer": c5_ref_longer,
    "c5-workflow-ref": c5_workflow_ref,
    "c6-another-image": c6_another_image,
    "c6-second-subject": c6_second_subject,
    "c7-predicate-type": c7_predicate_type,
    "c7-statement-type": c7_statement_type,
    "c8-called-from-another-repository": c8_called_from_another_repository,
    "c8-repository-uri": c8_repository_uri,
    "c8-repository-id": c8_repository_id,
    "c8-no-repository-id": c8_no_repository_id,
    "c9-source-ref": c9_source_ref,
    "c9-commit": c9_commit,
    "c11-wildcards-near-miss": c11_wildcards_near_miss,
}


def document(config_bytes, proofs):
    doc = base_doc()
    doc["collateral_format"] = COLLATERAL_V3
    if config_bytes is not None:
        doc["collateral"].append({"id": CONFIG_ID, "role": ROLE_RV, "format": CONFIG_FMT,
                                  "data": {"config_base64": b64(config_bytes)}})
    doc["collateral"].extend(proofs)
    return doc


def fixture(fid, config_bytes, proofs, expected, root=TRUSTED_ROOT):
    return {
        "id": fid,
        "stage": STAGE,
        "input": {
            "schema_version": "1",
            "document_b64": b64(canon(document(config_bytes, proofs))),
            "nonce_hex": "",
            "sigstore_trusted_root_json_b64": b64(json.dumps(root).encode()),
            # The stage reads no clock; pinning it to the proofs' log time
            # keeps the fixtures hermetic for an adapter that consults one.
            "verification_time_unix": ss.INTEGRATED_TIME,
        },
        "expected": expected,
    }


def main():
    selected = sys.argv[1:] or list(VECTORS)
    unknown = [fid for fid in selected if fid not in VECTORS]
    if unknown:
        sys.exit(f"unknown fixture ids: {', '.join(unknown)}")
    os.makedirs(OUT_DIR, exist_ok=True)
    for fid in selected:
        with open(OUT_DIR / (fid + ".json"), "w") as fh:
            fh.write(json.dumps(fixture(fid, *VECTORS[fid]()), indent=2) + "\n")
    print(f"wrote {len(selected)} of {len(VECTORS)} container-provenance fixtures to {OUT_DIR.relative_to(REPO_ROOT)}/")


if __name__ == "__main__":
    main()
