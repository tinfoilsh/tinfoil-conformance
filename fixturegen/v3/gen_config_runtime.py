#!/usr/bin/env python3
"""Generate the config-runtime fixtures (vectors/v3/config-runtime/) for the
`v3-read-config-runtime` stage (CONFORMANCE_ADAPTER_SPEC §2.2,
SPEC_COVERAGE_V3 CR-rules).

A deployment config pins the runtime it boots as
`cvm-version: <version>@sha256:<digest>`. From cvm-version v0.15.5-rc.1 on a
config is JSON in one byte form (RFC 8785 canonical JSON, integers only, no
null) and YAML is refused; earlier versions keep YAML. Each fixture is a v3
document carrying the config bytes (the `tinfoil-config` entry); the stage
reads the pin from them and authenticates nothing.

The accepts report the pin; every rejection is a single change to an
accepting config and attributes to PROVENANCE_REJECTED. Emits the shared
fixture format {id, stage, input, expected}; each vector function's docstring
says what it exercises.

Run from the repo root:  python3 fixturegen/v3/gen_config_runtime.py [id ...]

The fixtures are deterministic: a run rewrites them byte for byte.
"""

import hashlib
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "fixturegen" / "v3"))

from gen_envelope import b64, base_doc, canon  # noqa: E402

STAGE = "v3-read-config-runtime"
OUT_DIR = REPO_ROOT / "vectors" / "v3" / "config-runtime"

COLLATERAL_V3 = "https://tinfoil.sh/predicate/attestation-collaterals/v3"
CONFIG_FMT = "https://tinfoil.sh/collateral/config/v1"
CONFIG_ID = "tinfoil-config"
ROLE_RV = "reference-values"

RUNTIME_REPO = "tinfoilsh/cvmimage"
DIGEST_SEPARATOR = "@sha256:"
RUNTIME_DIGEST = hashlib.sha256(b"config-runtime-manifest").hexdigest()

# The first cvm-version whose config is JSON, the release candidate before it
# and the release before that.
CUTOFF = "0.15.5-rc.1"
LAST_YAML_CANDIDATE = "0.15.5-rc.0"
LAST_YAML_RELEASE = "0.15.4"

# The integers every JSON implementation reads exactly are those up to 2^53-1
# in absolute value.
MAX_INTEGER = 2**53 - 1

APP_IMAGE = "ghcr.io/example/app@sha256:" + hashlib.sha256(b"config-runtime-image-app").hexdigest()
WORKER_IMAGE = "ghcr.io/example/worker@sha256:" + hashlib.sha256(b"config-runtime-image-worker").hexdigest()

# Escape sequences and non-ASCII text are assembled from code points, so that
# no tool that rewrites an escape sequence or a character in source text can
# change the bytes of a fixture. check_bytes() asserts the bytes that matter.
BACKSLASH = chr(0x5C)
ESCAPE = chr(0x1B)
BYTE_ORDER_MARK = bytes([0xEF, 0xBB, 0xBF])
INVALID_UTF8_BYTE = bytes([0xFF])
HIGH_SURROGATE = 0xD800


def text(*code_points):
    return "".join(map(chr, code_points))


def unicode_escape(code_unit, uppercase=False):
    """The six-character JSON escape of a UTF-16 code unit."""
    return BACKSLASH + "u" + format(code_unit, "04X" if uppercase else "04x")


E_ACUTE = text(0xE9)
U_UMLAUT = text(0xFC)
SHARP_S = text(0xDF)
WORLD = text(0x4E16, 0x754C)
JAPANESE = text(0x65E5, 0x672C, 0x8A9E)
GRINNING_FACE = text(0x1F600)
# A family name written with U+20BB7, outside the Basic Multilingual Plane,
# and "cache" in halfwidth katakana, U+FF77 and up. UTF-16 writes U+20BB7 as
# the surrogates D842 DFB7, which sort before FF77; by code point, and by
# UTF-8 bytes (F0... after EF...), it sorts after.
YOSHINOYA = text(0x20BB7, 0x91CE, 0x5BB6)
HALFWIDTH_CACHE = text(0xFF77, 0xFF6C, 0xFF6F, 0xFF7C, 0xFF6D)

TMPFS = {
    "/run": "size=16m",
    "/srv/donn" + E_ACUTE + "es": "size=64m",
    "/srv/" + JAPANESE: "size=64m",
    "/srv/" + YOSHINOYA: "size=64m",
    "/srv/" + HALFWIDTH_CACHE: "size=256m,noexec",
}


# --- Config ------------------------------------------------------------------
def utf16_units(name):
    """The key RFC 8785 orders member names by: their UTF-16 code units."""
    return name.encode("utf-16-be")


def code_points(name):
    """The order a serializer gets by comparing code points, which is also the
    order of the names' UTF-8 bytes."""
    return [ord(c) for c in name]


def serialize(value, order=utf16_units):
    """RFC 8785 serialization of a value made of objects, arrays, strings,
    integers and booleans. `order` overrides the member order."""
    def ordered(v):
        if isinstance(v, dict):
            return {name: ordered(v[name]) for name in sorted(v, key=order)}
        if isinstance(v, list):
            return [ordered(item) for item in v]
        return v
    return json.dumps(ordered(value), ensure_ascii=False, separators=(",", ":")).encode()


def replace(data, old, new):
    """data with its one occurrence of old replaced."""
    old, new = (part.encode() if isinstance(part, str) else part for part in (old, new))
    assert data.count(old) == 1, (old, data)
    return data.replace(old, new)


def pin(version=CUTOFF, digest=RUNTIME_DIGEST):
    return version + DIGEST_SEPARATOR + digest


def small(cvm_version=None):
    """A minimal config: one container behind the shim."""
    return {
        "cvm-version": pin() if cvm_version is None else cvm_version,
        "cpus": 2,
        "memory": 4096,
        "containers": [{"name": "app", "image": APP_IMAGE}],
        "shim": {"upstream-port": 8080},
    }


def large():
    """A config with nested members, two containers, every kind of value a
    JSON config holds, non-ASCII text and tmpfs paths whose order tells UTF-16
    code units from code points."""
    return {
        "cvm-version": pin(),
        "cpus": 8,
        "memory": 16384,
        "gpus": 2,
        "cvm-network": {"inbound-ports": [8443]},
        "networks": {"app": {}, "web": {"allow": ["example.com"], "egress": "allowlist"}},
        "security": {"include-config-in-attestation": True},
        "shim": {
            "upstream-port": 8080,
            "paths": ["/v1/chat/completions", "/health"],
            "authenticated-endpoints": [],
            "rate-limit": "0.5",
            "drain_connections": True,
            "drain_timeout": "90s",
        },
        "volumes": [{"name": "data", "size": "10GiB"}],
        "containers": [
            {
                "name": "app",
                "image": APP_IMAGE,
                "command": ["serve", "--port", "8080"],
                "cpus": "1.5",
                "env": [
                    "HF_TOKEN",
                    {"PORT": "8080"},
                    {"GREETING": f"Gr{U_UMLAUT}{SHARP_S}e, {WORLD} {GRINNING_FACE}"},
                    {"PROMPT": f"{ESCAPE}[1mapp{ESCAPE}[0m> "},
                    {"BANNER": 'first line\nsecond "line"\tC:' + BACKSLASH + "data"},
                ],
                "gpus": 2,
                "healthcheck": {"test": ["CMD", "true"], "retries": 3},
                "networks": ["app", "web"],
                "persistent_volumes": ["data:/data"],
                "pids_limit": 4096,
                "provenance": {"github": {
                    "repository": "example/app",
                    "repository_id": "123456789",
                    "workflow": "release.yml",
                    "ref": "refs/tags/v*",
                }},
                "read_only": True,
                "runtime": "nvidia",
                "stop_timeout": 30,
                "tmpfs": TMPFS,
            },
            {
                "name": "worker",
                "image": WORKER_IMAGE,
                "gpus": "0,1",
                "networks": ["app"],
                "read_only": False,
                "runtime": "nvidia",
                "stop_timeout": 0,
            },
        ],
    }


def yaml_config(version, digest=RUNTIME_DIGEST):
    """The minimal config in YAML block style."""
    return (
        f"cvm-version: {pin(version, digest)}\n"
        "cpus: 2\n"
        "memory: 4096\n"
        "containers:\n"
        "  - name: app\n"
        f"    image: {APP_IMAGE}\n"
        "shim:\n"
        "  upstream-port: 8080\n"
    ).encode()


def yaml_flow_config(version):
    """The minimal config in YAML flow style, with the unquoted names and
    single-quoted strings that JSON does not allow."""
    return (
        "{" + f"cvm-version: '{pin(version)}', cpus: 2, memory: 4096, "
        f"containers: [{{name: app, image: '{APP_IMAGE}'}}], "
        "shim: {upstream-port: 8080}}\n"
    ).encode()


# --- Expected ----------------------------------------------------------------
def accept(version=CUTOFF, digest=RUNTIME_DIGEST):
    """The pin a config that states `version` reports: the tag carries a
    leading v whether or not the config wrote one."""
    tag = version if version.startswith("v") else "v" + version
    return {"accepted": True, "runtime": {"repo": RUNTIME_REPO, "tag": tag, "digest": digest}}


def reject():
    return {"accepted": False, "code": "PROVENANCE_REJECTED"}


# Each vector returns (config bytes, expected); its docstring is the rule it
# exercises.
def happy():
    """Canonical JSON that pins the first JSON version."""
    return serialize(small()), accept()


# Positive variations: valid alternatives that must accept, and the pin they
# must report.
def pos_v_prefix():
    """The version carries a leading v; the tag is reported with a single v."""
    version = "v" + CUTOFF
    return serialize(small(pin(version))), accept(version)


def pos_build_metadata():
    """Build metadata does not order a version: the first JSON version with metadata is JSON, and the tag keeps the metadata."""
    version = CUTOFF + "+gpu"
    return serialize(small(pin(version))), accept(version)


def pos_release():
    """The release the first JSON version is a candidate of."""
    version = "0.15.5"
    return serialize(small(pin(version))), accept(version)


def pos_minor():
    """A later minor version."""
    version = "0.16.0"
    return serialize(small(pin(version))), accept(version)


def pos_major():
    """A later major version."""
    version = "1.0.0"
    return serialize(small(pin(version))), accept(version)


def pos_large():
    """A full config: nested members, two containers, booleans, zero, empty arrays and objects, non-ASCII text and an escaped control character in values, and tmpfs paths that sort differently by UTF-16 code units and by code points."""
    return serialize(large()), accept()


def pos_integer_bounds():
    """The largest and the smallest integer a JSON config may hold, 2^53-1 and its negative."""
    config = small()
    config["memory"] = MAX_INTEGER
    config["containers"][0]["pids_limit"] = -MAX_INTEGER
    return serialize(config), accept()


def pos_yaml_release():
    """A YAML config for the last release before the first JSON version."""
    return yaml_config(LAST_YAML_RELEASE), accept(LAST_YAML_RELEASE)


def pos_yaml_candidate():
    """A YAML config for the release candidate just before the first JSON version: pre-release identifiers order versions."""
    return yaml_config(LAST_YAML_CANDIDATE), accept(LAST_YAML_CANDIDATE)


# CR1: the document carries the config.
def cr1_no_config():
    """The document carries no config entry."""
    return None, reject()


# CR2: from the first JSON version on, YAML is refused.
def cr2_yaml_at_cutoff():
    """A YAML config in block style that pins the first JSON version."""
    return yaml_config(CUTOFF), reject()


def cr2_yaml_later():
    """A YAML config in block style that pins a later minor version."""
    return yaml_config("0.16.0"), reject()


def cr2_yaml_flow():
    """A YAML config in flow style that pins the first JSON version: braces and brackets as in JSON, but unquoted names and single-quoted strings."""
    return yaml_flow_config(CUTOFF), reject()


# CR3: the version is compared by semantic version precedence. Each of these
# is YAML, so a comparison that takes the version for an earlier one, or for
# no version at all, accepts it.
def cr3_yaml_v_prefix():
    """YAML that pins the first JSON version written with a leading v."""
    return yaml_config("v" + CUTOFF), reject()


def cr3_yaml_build_metadata():
    """YAML that pins the first JSON version with build metadata."""
    return yaml_config(CUTOFF + "+gpu"), reject()


def cr3_yaml_release():
    """YAML that pins the release the first JSON version is a candidate of: a release follows its pre-releases."""
    return yaml_config("0.15.5"), reject()


def cr3_yaml_numeric_patch():
    """YAML that pins patch 10 of the same minor version: version numbers compare as numbers, not as text."""
    return yaml_config("0.15.10"), reject()


# CR4: bytes that are not strictly one JSON object are not a JSON config, and
# from the first JSON version on nothing else is accepted.
def cr4_repeated_member():
    """A member appears twice with the same value."""
    return replace(serialize(small()), '"cpus":2,', '"cpus":2,"cpus":2,'), reject()


def cr4_second_value():
    """A second JSON value follows the config."""
    return serialize(small()) * 2, reject()


def cr4_top_level_array():
    """The config is wrapped in an array."""
    return b"[" + serialize(small()) + b"]", reject()


def cr4_not_utf8():
    """A string value holds a byte that is not UTF-8."""
    return replace(serialize(small()), b'"name":"app"', b'"name":"ap' + INVALID_UTF8_BYTE + b'p"'), reject()


def cr4_byte_order_mark():
    """A UTF-8 byte-order mark precedes the config."""
    return BYTE_ORDER_MARK + serialize(small()), reject()


def cr4_unpaired_surrogate():
    """A string value holds the escape of a high surrogate with no low surrogate after it, written in lowercase as a serializer that keeps it would."""
    return replace(serialize(small()), '"name":"app"', '"name":"app' + unicode_escape(HIGH_SURROGATE) + '"'), reject()


# CR5: a JSON config is byte for byte its RFC 8785 serialization.
def cr5_space():
    """A space follows a colon."""
    return replace(serialize(small()), '"cpus":2', '"cpus": 2'), reject()


def cr5_trailing_newline():
    """A newline follows the config."""
    return serialize(small()) + b"\n", reject()


def cr5_member_order():
    """Two members are in the other order."""
    canonical = serialize(small())
    containers = serialize(small()["containers"]).decode()
    return replace(canonical, f'"containers":{containers},"cpus":2,', f'"cpus":2,"containers":{containers},'), reject()


def cr5_member_order_code_points():
    """The full config with its members ordered by code point, which is also the order of their UTF-8 bytes: the tmpfs path with a character outside the Basic Multilingual Plane moves after the halfwidth one."""
    return serialize(large(), order=code_points), reject()


def cr5_escaped_letter():
    """A member name writes an ASCII letter as an escape."""
    return replace(serialize(small()), '"cpus"', '"' + unicode_escape(ord("c")) + 'pus"'), reject()


def cr5_escaped_solidus():
    """A string value escapes a solidus."""
    return replace(serialize(small()), '"ghcr.io/example/app@', '"ghcr.io' + BACKSLASH + "/example/app@"), reject()


def cr5_uppercase_escape():
    """The full config with the hex digits of a control character's escape in uppercase."""
    canonical = serialize(large())
    lowercase, uppercase = (unicode_escape(ord(ESCAPE), uppercase=upper) + "[1m" for upper in (False, True))
    return replace(canonical, lowercase, uppercase), reject()


def cr5_negative_zero():
    """An integer member is written as negative zero, which serializes as 0."""
    return replace(serialize(large()), '"stop_timeout":0', '"stop_timeout":-0'), reject()


# CR6: every number is an integer of at most 2^53-1 in absolute value. Each
# of these is how RFC 8785 itself writes the number, so only this rule
# rejects it.
def cr6_fraction():
    """A number has a fraction."""
    return replace(serialize(small()), '"cpus":2', '"cpus":1.5'), reject()


def cr6_exponent():
    """A number has an exponent, in the form RFC 8785 gives a number that large."""
    return replace(serialize(small()), '"memory":4096', '"memory":1e+21'), reject()


def cr6_above_max():
    """An integer is 2^53, one more than the largest allowed."""
    return replace(serialize(small()), '"memory":4096', f'"memory":{MAX_INTEGER + 1}'), reject()


def cr6_below_min():
    """An integer is -2^53, one less than the smallest allowed."""
    return replace(serialize(small()), '"memory":4096', f'"memory":{-MAX_INTEGER - 1}'), reject()


# CR7: no null.
def cr7_null_member():
    """A top-level member is null."""
    return replace(serialize(small()), '"cpus":2', '"cpus":null'), reject()


def cr7_null_nested():
    """A member three levels down is null."""
    return replace(serialize(large()), '"retries":3', '"retries":null'), reject()


# CR8: the pin.
def cr8_version_number():
    """cvm-version is a number, in a config that is otherwise canonical JSON."""
    return replace(serialize(small()), f'"cvm-version":"{pin()}"', '"cvm-version":1'), reject()


def cr8_version_missing():
    """The config, otherwise canonical JSON, has no cvm-version."""
    config = small()
    del config["cvm-version"]
    return serialize(config), reject()


def cr8_unpinned():
    """cvm-version names the first JSON version without a digest."""
    return serialize(small(CUTOFF)), reject()


def cr8_digest_uppercase():
    """The digest is written in uppercase hex."""
    return serialize(small(pin(digest=RUNTIME_DIGEST.upper()))), reject()


def cr8_digest_short():
    """The digest is one byte short."""
    return serialize(small(pin(digest=RUNTIME_DIGEST[:-2]))), reject()


VECTORS = {
    "runtime-happy": happy,
    "runtime-pos-v-prefix": pos_v_prefix,
    "runtime-pos-build-metadata": pos_build_metadata,
    "runtime-pos-release": pos_release,
    "runtime-pos-minor": pos_minor,
    "runtime-pos-major": pos_major,
    "runtime-pos-large": pos_large,
    "runtime-pos-integer-bounds": pos_integer_bounds,
    "runtime-pos-yaml-release": pos_yaml_release,
    "runtime-pos-yaml-candidate": pos_yaml_candidate,
    "cr1-no-config": cr1_no_config,
    "cr2-yaml-at-cutoff": cr2_yaml_at_cutoff,
    "cr2-yaml-later": cr2_yaml_later,
    "cr2-yaml-flow": cr2_yaml_flow,
    "cr3-yaml-v-prefix": cr3_yaml_v_prefix,
    "cr3-yaml-build-metadata": cr3_yaml_build_metadata,
    "cr3-yaml-release": cr3_yaml_release,
    "cr3-yaml-numeric-patch": cr3_yaml_numeric_patch,
    "cr4-repeated-member": cr4_repeated_member,
    "cr4-second-value": cr4_second_value,
    "cr4-top-level-array": cr4_top_level_array,
    "cr4-not-utf8": cr4_not_utf8,
    "cr4-byte-order-mark": cr4_byte_order_mark,
    "cr4-unpaired-surrogate": cr4_unpaired_surrogate,
    "cr5-space": cr5_space,
    "cr5-trailing-newline": cr5_trailing_newline,
    "cr5-member-order": cr5_member_order,
    "cr5-member-order-code-points": cr5_member_order_code_points,
    "cr5-escaped-letter": cr5_escaped_letter,
    "cr5-escaped-solidus": cr5_escaped_solidus,
    "cr5-uppercase-escape": cr5_uppercase_escape,
    "cr5-negative-zero": cr5_negative_zero,
    "cr6-fraction": cr6_fraction,
    "cr6-exponent": cr6_exponent,
    "cr6-above-max": cr6_above_max,
    "cr6-below-min": cr6_below_min,
    "cr7-null-member": cr7_null_member,
    "cr7-null-nested": cr7_null_nested,
    "cr8-version-number": cr8_version_number,
    "cr8-version-missing": cr8_version_missing,
    "cr8-unpinned": cr8_unpinned,
    "cr8-digest-uppercase": cr8_digest_uppercase,
    "cr8-digest-short": cr8_digest_short,
}


def check_bytes():
    """Assert the bytes the fixtures exist for, so that a change to this file
    that loses one of them fails the run instead of weakening a fixture."""
    canonical = serialize(large())
    names = list(TMPFS)
    by_units, by_points = sorted(names, key=utf16_units), sorted(names, key=code_points)
    by_utf8 = sorted(names, key=str.encode)
    assert by_units != by_points and by_points == by_utf8, names
    assert any(ord(c) > 0xFFFF for name in names for c in name), names
    positions = [canonical.index(json.dumps(name, ensure_ascii=False).encode() + b":") for name in by_units]
    assert positions == sorted(positions), positions
    assert canonical != serialize(large(), order=code_points)

    backslash = bytes([0x5C])
    assert canonical.count(backslash + b"u001b") == 2 and backslash + b"u001B" not in canonical
    assert backslash + b"n" in canonical and backslash + b"t" in canonical
    assert backslash + b'"' in canonical and backslash * 2 in canonical
    assert GRINNING_FACE.encode() == bytes([0xF0, 0x9F, 0x98, 0x80]) and GRINNING_FACE.encode() in canonical
    assert all(byte >= 0x20 for byte in canonical)

    assert backslash + b"u001B[1m" in cr5_uppercase_escape()[0]
    assert b'"' + backslash + b'u0063pus":2' in cr5_escaped_letter()[0]
    assert b"ghcr.io" + backslash + b"/example" in cr5_escaped_solidus()[0]
    assert b'app' + backslash + b'ud800"' in cr4_unpaired_surrogate()[0]
    assert cr4_byte_order_mark()[0][:4] == bytes([0xEF, 0xBB, 0xBF]) + b"{"
    assert bytes([0x70, 0xFF, 0x70]) in cr4_not_utf8()[0]
    assert b'"memory":9007199254740992,' in cr6_above_max()[0]
    assert b'"memory":-9007199254740992,' in cr6_below_min()[0]
    assert b'"memory":9007199254740991,' in pos_integer_bounds()[0]
    assert b'"pids_limit":-9007199254740991}' in pos_integer_bounds()[0]


def document(config_bytes):
    doc = base_doc()
    doc["collateral_format"] = COLLATERAL_V3
    if config_bytes is not None:
        doc["collateral"].append({"id": CONFIG_ID, "role": ROLE_RV, "format": CONFIG_FMT,
                                  "data": {"config_base64": b64(config_bytes)}})
    return doc


def fixture(fid, config_bytes, expected):
    return {
        "id": fid,
        "stage": STAGE,
        "input": {
            "schema_version": "1",
            "document_b64": b64(canon(document(config_bytes))),
            # The stage compares no nonce; the member is there because
            # adapters decode it before they dispatch on the stage.
            "nonce_hex": "",
        },
        "expected": expected,
    }


def main():
    selected = sys.argv[1:] or list(VECTORS)
    unknown = [fid for fid in selected if fid not in VECTORS]
    if unknown:
        sys.exit(f"unknown fixture ids: {', '.join(unknown)}")
    check_bytes()
    os.makedirs(OUT_DIR, exist_ok=True)
    for fid in selected:
        with open(OUT_DIR / (fid + ".json"), "w") as fh:
            fh.write(json.dumps(fixture(fid, *VECTORS[fid]()), indent=2) + "\n")
    print(f"wrote {len(selected)} of {len(VECTORS)} config-runtime fixtures to {OUT_DIR.relative_to(REPO_ROOT)}/")


if __name__ == "__main__":
    main()
