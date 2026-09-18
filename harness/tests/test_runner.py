"""Runner contract tests; the synthetic subprocess is not an SDK verifier."""

import json
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

import yaml

from tinfoil_conformance.runner import (
    EXIT_ACCEPT,
    EXIT_BAD_INPUT,
    EXIT_REJECT,
    EXIT_UNSUPPORTED,
    SdkRegistration,
    run_fixture,
)


STAGE = "verify-full"
REJECTION_CODE = "MEASUREMENT_MISMATCH"
REJECTION_STAGE = "verify-measurement"
SYNTHETIC_ADAPTER = (
    "import json, sys; json.load(sys.stdin); "
    "sys.stdout.write(sys.argv[1]); sys.exit(int(sys.argv[2]))"
)
ACCEPTED = {"stage": STAGE, "accepted": True, "outputs": {"mode": "pinned"}}
REJECTED = {
    "stage": STAGE,
    "accepted": False,
    "rejection": {"code": REJECTION_CODE, "stage": REJECTION_STAGE},
}


class RunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fixture = Path(temporary.name)
        (self.fixture / "input.json").write_text('{"schema_version": "1"}')

    def run_response(
        self, response, exit_code=EXIT_ACCEPT, *, expects=None, outputs=None
    ):
        return self.run_stdout(
            json.dumps(response), exit_code, expects=expects, outputs=outputs
        )

    def run_stdout(self, stdout, exit_code, *, expects=None, outputs=None):
        manifest = {"stage": STAGE, "expects": expects or {"exit_code": exit_code}}
        (self.fixture / "manifest.yaml").write_text(yaml.safe_dump(manifest))
        (self.fixture / "expected.json").write_text(
            json.dumps({"outputs": outputs or {}})
        )
        sdk = SdkRegistration(
            name="synthetic-runner-test",
            binary=[sys.executable, "-c", SYNTHETIC_ADAPTER, stdout, str(exit_code)],
            capabilities={"stages_supported": [STAGE]},
        )
        return run_fixture(self.fixture, sdk)

    def test_accepts_matching_output_subset(self):
        response = deepcopy(ACCEPTED)
        response["outputs"]["platform"] = "sev-snp"
        result = self.run_response(response, outputs={"mode": "pinned"})
        self.assertEqual(result.status, "pass", result.reason)
        self.assertEqual(result.got_output, response)

    def test_rejects_missing_or_different_expected_outputs(self):
        for outputs in ({"platform": "sev-snp"}, {"mode": "standard"}):
            with self.subTest(outputs=outputs):
                result = self.run_response(ACCEPTED, outputs=outputs)
                self.assertEqual(result.status, "fail")
                self.assertIn("outputs differ", result.reason)

    def test_compares_complete_nested_measurement(self):
        response = deepcopy(ACCEPTED)
        response["outputs"]["attestation_measurement"] = {
            "type": "sev",
            "registers": ["aa"],
        }
        result = self.run_response(
            response,
            outputs={
                "attestation_measurement": {"type": "sev", "registers": ["bb"]},
            },
        )
        self.assertEqual(result.status, "fail")
        self.assertIn("attestation_measurement", result.reason)

    def test_requires_object_envelope_for_accept_and_reject(self):
        for exit_code in (EXIT_ACCEPT, EXIT_REJECT):
            for response in (None, [], "not an envelope", 0):
                with self.subTest(exit_code=exit_code, response=response):
                    result = self.run_response(response, exit_code)
                    self.assertEqual(result.status, "fail")
                    self.assertIn("object", result.reason)

    def test_requires_matching_stage_for_accept_and_reject(self):
        for exit_code, baseline in ((EXIT_ACCEPT, ACCEPTED), (EXIT_REJECT, REJECTED)):
            for stage in (None, "verify-sigstore"):
                with self.subTest(exit_code=exit_code, stage=stage):
                    response = deepcopy(baseline)
                    if stage is None:
                        del response["stage"]
                    else:
                        response["stage"] = stage
                    result = self.run_response(response, exit_code)
                    self.assertEqual(result.status, "fail")
                    self.assertIn("stage", result.reason)

    def test_requires_boolean_verdict_consistent_with_exit(self):
        for exit_code, baseline, wrong in (
            (EXIT_ACCEPT, ACCEPTED, [False, 1, "true", None]),
            (EXIT_REJECT, REJECTED, [True, 0, "false", None]),
        ):
            for accepted in wrong:
                with self.subTest(exit_code=exit_code, accepted=accepted):
                    response = deepcopy(baseline)
                    if accepted is None:
                        del response["accepted"]
                    else:
                        response["accepted"] = accepted
                    result = self.run_response(response, exit_code)
                    self.assertEqual(result.status, "fail")
                    self.assertIn("accepted", result.reason)

    def test_requires_outputs_object_even_without_expected_subset(self):
        for outputs in (None, [], "not outputs"):
            with self.subTest(outputs=outputs):
                response = deepcopy(ACCEPTED)
                if outputs is None:
                    del response["outputs"]
                else:
                    response["outputs"] = outputs
                result = self.run_response(response)
                self.assertEqual(result.status, "fail")
                self.assertIn("outputs", result.reason)

    def test_requires_rejection_object_and_string_code(self):
        for rejection in (None, [], "not rejection", {}, {"code": 0}):
            with self.subTest(rejection=rejection):
                response = deepcopy(REJECTED)
                if rejection is None:
                    del response["rejection"]
                else:
                    response["rejection"] = rejection
                result = self.run_response(response, EXIT_REJECT)
                self.assertEqual(result.status, "fail")
                self.assertIn("rejection", result.reason)

    def test_checks_rejection_code_and_substage(self):
        for code in (REJECTION_CODE, ["OTHER_CODE", REJECTION_CODE]):
            with self.subTest(code=code):
                result = self.run_response(
                    REJECTED,
                    EXIT_REJECT,
                    expects={
                        "exit_code": EXIT_REJECT,
                        "rejection_code": code,
                        "rejection_stage": REJECTION_STAGE,
                    },
                )
                self.assertEqual(result.status, "pass", result.reason)
        for field, value in (
            ("rejection_code", "OTHER_CODE"),
            ("rejection_stage", STAGE),
        ):
            with self.subTest(field=field):
                result = self.run_response(
                    REJECTED,
                    EXIT_REJECT,
                    expects={
                        "exit_code": EXIT_REJECT,
                        field: value,
                    },
                )
                self.assertEqual(result.status, "fail")
                self.assertIn(field.replace("_", "."), result.reason)

    def test_wrong_exit_is_not_rescued_by_matching_envelope(self):
        result = self.run_response(
            ACCEPTED, EXIT_REJECT, expects={"exit_code": EXIT_ACCEPT}
        )
        self.assertEqual(result.status, "fail")
        self.assertIn("exit", result.reason)

    def test_invalid_json_is_a_runner_error(self):
        result = self.run_stdout("not JSON", EXIT_ACCEPT)
        self.assertEqual(result.status, "error")
        self.assertIn("stdout not JSON", result.reason)

    def test_empty_stdout_does_not_pass_accept_or_reject(self):
        for exit_code in (EXIT_ACCEPT, EXIT_REJECT):
            with self.subTest(exit_code=exit_code):
                self.assertEqual(self.run_stdout("", exit_code).status, "fail")

    def test_non_verdict_exits_do_not_require_verdict_envelope(self):
        for exit_code in (EXIT_BAD_INPUT, EXIT_UNSUPPORTED):
            with self.subTest(exit_code=exit_code):
                result = self.run_stdout("", exit_code)
                self.assertEqual(result.status, "pass", result.reason)


if __name__ == "__main__":
    unittest.main()
