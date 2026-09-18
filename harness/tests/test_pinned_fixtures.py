"""Validate fixture contracts and generation, not SDK cryptographic conformance."""

import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import yaml
from jsonschema import Draft202012Validator

from tinfoil_conformance.runner import EXIT_ACCEPT, EXIT_REJECT, discover_fixtures


ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "verify-full"
SEV_HAPPY = ROOT / "vectors" / "attestation-sev" / "200-real-sev-snp-happy"
HAPPY = "510-pinned-flow-sev-happy"
IGNORED_PROVENANCE = "511-pinned-flow-ignores-sigstore"
UPPERCASE = "512-pinned-flow-uppercase"
MISMATCH = "520-pinned-flow-measurement-mismatch"
POLICY_MISMATCH = "521-pinned-flow-sev-policy-mismatch"
NO_FALLBACK = "522-pinned-flow-provenance-cannot-replace-pin"
PINNED_FIXTURES = {
    HAPPY,
    IGNORED_PROVENANCE,
    UPPERCASE,
    MISMATCH,
    POLICY_MISMATCH,
    NO_FALLBACK,
}
EXPECTED_OUTPUT_KEYS = {
    "mode",
    "platform",
    "attestation_measurement",
    "final_measurement_fingerprint_hex",
}


def read_json(path):
    return json.loads(path.read_text())


class PinnedFixtureTests(unittest.TestCase):
    def test_pinned_inputs_outputs_and_manifests_follow_contract(self):
        validators = {}
        for kind in ("input", "output"):
            schema = read_json(ROOT / "schemas" / f"verify-full.{kind}.schema.json")
            Draft202012Validator.check_schema(schema)
            validators[kind] = Draft202012Validator(schema)
        found = set()
        for fixture in discover_fixtures(VECTORS):
            payload = read_json(fixture / "input.json")
            if payload["mode"] != "pinned":
                continue
            found.add(fixture.name)
            with self.subTest(fixture=fixture.name):
                expected = read_json(fixture / "expected.json")
                manifest = yaml.safe_load((fixture / "manifest.yaml").read_text())
                validators["input"].validate(payload)
                validators["output"].validate(expected)
                self.assertEqual(manifest["id"], fixture.name)
                self.assertEqual(manifest["stage"], expected["stage"])
                self.assertIn("11.3", manifest["spec_refs"])
                self.assertEqual(
                    manifest["required_capabilities"]["flow_modes_supported"], "pinned"
                )
                self.assertTrue(
                    manifest["required_capabilities"]["attestation_sev.supported"]
                )
                self.assertTrue(
                    manifest["required_capabilities"][
                        "attestation_sev.injected_collateral_supported"
                    ]
                )
                self.assertEqual(
                    manifest["expects"]["exit_code"],
                    EXIT_ACCEPT if expected["accepted"] else EXIT_REJECT,
                )
                if not expected["accepted"]:
                    self.assertEqual(
                        manifest["expects"]["rejection_code"],
                        expected["rejection"]["code"],
                    )
                    self.assertEqual(
                        manifest["expects"]["rejection_stage"],
                        expected["rejection"]["stage"],
                    )
        self.assertEqual(found, PINNED_FIXTURES)

    def test_accept_outputs_are_anchored_to_authenticated_fixture(self):
        measurement = read_json(SEV_HAPPY / "expected.json")["outputs"]["measurement"]
        for name in (HAPPY, IGNORED_PROVENANCE, UPPERCASE):
            with self.subTest(fixture=name):
                outputs = read_json(VECTORS / name / "expected.json")["outputs"]
                self.assertEqual(set(outputs), EXPECTED_OUTPUT_KEYS)
                self.assertEqual(outputs["mode"], "pinned")
                self.assertEqual(outputs["platform"], "sev-snp")
                self.assertEqual(outputs["attestation_measurement"], measurement)
                self.assertEqual(
                    outputs["final_measurement_fingerprint_hex"],
                    measurement["registers"][0],
                )

    def test_uppercase_case_changes_only_pin_spelling(self):
        baseline = read_json(VECTORS / HAPPY / "input.json")
        uppercase = read_json(VECTORS / UPPERCASE / "input.json")
        self.assertNotEqual(
            uppercase["pinned_measurement"], baseline["pinned_measurement"]
        )
        self.assertEqual(
            uppercase["pinned_measurement"]["registers"],
            [value.upper() for value in baseline["pinned_measurement"]["registers"]],
        )
        uppercase["pinned_measurement"] = baseline["pinned_measurement"]
        self.assertEqual(uppercase, baseline)

    def test_policy_failure_reuses_report_and_does_not_change_code_pin(self):
        baseline = read_json(VECTORS / HAPPY / "input.json")
        payload = read_json(VECTORS / POLICY_MISMATCH / "input.json")
        policy_source = read_json(
            ROOT
            / "vectors"
            / "attestation-sev"
            / "400-measurement-pin-mismatch"
            / "input.json"
        )
        policy_source.pop("schema_version")
        self.assertEqual(payload["pinned_measurement"], baseline["pinned_measurement"])
        self.assertEqual(payload["attestation_sev"], policy_source)
        policy_source.pop("policy")
        self.assertEqual(policy_source, baseline["attestation_sev"])
        manifest = yaml.safe_load(
            (VECTORS / POLICY_MISMATCH / "manifest.yaml").read_text()
        )
        self.assertTrue(
            manifest["required_capabilities"][
                "attestation_sev.extended_checks_supported"
            ]
        )
        self.assertEqual(
            manifest["expects"]["rejection_stage"], "verify-attestation-sev"
        )

    def test_provenance_cases_keep_caller_pin_authoritative(self):
        baseline = read_json(VECTORS / HAPPY / "input.json")
        ignored = read_json(VECTORS / IGNORED_PROVENANCE / "input.json")
        no_fallback = read_json(VECTORS / NO_FALLBACK / "input.json")
        standard = read_json(VECTORS / "500-standard-flow-sev-happy" / "input.json")
        failing = read_json(
            ROOT / "vectors" / "sigstore" / "016-subject-digest-mismatch" / "input.json"
        )
        ignored_sigstore = ignored.pop("sigstore")
        valid_sigstore = no_fallback.pop("sigstore")
        self.assertEqual(ignored, baseline)
        self.assertEqual(no_fallback, read_json(VECTORS / MISMATCH / "input.json"))
        self.assertEqual(
            ignored_sigstore["expected_digest_sha256_hex"],
            failing["expected_digest_sha256_hex"],
        )
        self.assertEqual(
            valid_sigstore["expected_digest_sha256_hex"],
            standard["sigstore"]["expected_digest_sha256_hex"],
        )
        self.assertNotEqual(
            ignored_sigstore["expected_digest_sha256_hex"],
            valid_sigstore["expected_digest_sha256_hex"],
        )
        ignored_sigstore["expected_digest_sha256_hex"] = valid_sigstore[
            "expected_digest_sha256_hex"
        ]
        self.assertEqual(ignored_sigstore, valid_sigstore)
        for field in ("bundle_b64", "trust_root_b64", "verification_time_unix"):
            self.assertEqual(valid_sigstore[field], standard["sigstore"][field])

    def test_generator_is_byte_deterministic_and_matches_checked_in_vectors(self):
        spec = importlib.util.spec_from_file_location(
            "verify_full_phase1_fixtures",
            ROOT / "fixturegen" / "verify_full_phase1_fixtures.py",
        )
        assert spec is not None and spec.loader is not None
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        with tempfile.TemporaryDirectory() as directory:
            generated = Path(directory)
            with (
                patch.object(generator, "VECTORS_DIR", generated),
                redirect_stdout(io.StringIO()),
            ):
                generator.main()
                first = {
                    p.relative_to(generated): p.read_bytes()
                    for p in generated.glob("*/*")
                }
                generator.main()
                second = {
                    p.relative_to(generated): p.read_bytes()
                    for p in generated.glob("*/*")
                }
            self.assertEqual(first, second)
            self.assertTrue(PINNED_FIXTURES <= {p.parts[0] for p in first})
            for path, content in first.items():
                with self.subTest(path=str(path)):
                    self.assertEqual(content, (VECTORS / path).read_bytes())


if __name__ == "__main__":
    unittest.main()
