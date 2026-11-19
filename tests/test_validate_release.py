# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / ".github/scripts/validate_release.py"
SPEC = importlib.util.spec_from_file_location("validate_release", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class ReleaseValidationTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.repository = Path(scratch.name)
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Release validation test")
        self.git("config", "user.email", "release-test@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "tag.gpgsign", "false")
        (self.repository / "pyproject.toml").write_text(
            '[project]\nname = "vogtcon"\nversion = "0.1.0"\n'
        )
        self.git("add", "pyproject.toml")
        self.git("commit", "-m", "Initial release fixture")

    def git(self, *arguments):
        return subprocess.check_output(
            ["git", "-C", str(self.repository), *arguments],
            text=True, stderr=subprocess.PIPE,
        ).strip()

    def validate(self, ref="refs/tags/v0.1.0"):
        return validator.validate_release(self.repository, "push", ref, "refs/heads/main")

    def test_lightweight_tag_matches_version_and_main(self):
        self.git("tag", "v0.1.0")
        result = self.validate()
        self.assertTrue(result["validated"])
        self.assertEqual(result["commit"], self.git("rev-parse", "HEAD"))
        self.assertEqual(result["version"], "0.1.0")

    def test_annotated_tag_is_peeled_to_its_commit(self):
        self.git("tag", "-a", "v0.1.0", "-m", "Annotated fixture")
        self.assertTrue(self.validate()["validated"])

    def test_historical_main_commit_is_allowed(self):
        self.git("tag", "v0.1.0")
        self.git("commit", "--allow-empty", "-m", "Main advances")
        self.git("checkout", "--detach", "v0.1.0")
        result = self.validate()
        self.assertTrue(result["validated"])
        self.assertNotEqual(result["commit"], result["main_commit"])

    def test_wrong_version_is_rejected(self):
        self.git("tag", "v0.2.0")
        with self.assertRaisesRegex(ValueError, "Expected refs/tags/v0.1.0"):
            self.validate("refs/tags/v0.2.0")

    def test_unmerged_branch_commit_is_rejected(self):
        self.git("switch", "-c", "feature")
        self.git("commit", "--allow-empty", "-m", "Unmerged feature")
        self.git("tag", "v0.1.0")
        with self.assertRaisesRegex(ValueError, "not reachable from main"):
            self.validate()

    def test_wrong_checkout_is_rejected(self):
        self.git("tag", "v0.1.0")
        self.git("commit", "--allow-empty", "-m", "Different checkout")
        with self.assertRaisesRegex(ValueError, "checked-out commit"):
            self.validate()

    def test_missing_main_history_is_rejected(self):
        self.git("tag", "v0.1.0")
        with self.assertRaisesRegex(ValueError, "Git validation failed"):
            validator.validate_release(
                self.repository, "push", "refs/tags/v0.1.0", "refs/remotes/missing/main"
            )

    def test_missing_static_version_is_rejected(self):
        (self.repository / "pyproject.toml").write_text('[project]\nname="vogtcon"\n')
        with self.assertRaisesRegex(ValueError, "static project.version"):
            self.validate()

    def test_non_release_events_never_approve_publication(self):
        for event, ref in [
            ("pull_request", "refs/pull/22/merge"),
            ("pull_request", "refs/tags/v0.1.0"),
            ("push", "refs/heads/main"),
            ("push", "refs/heads/v0.1.0"),
            ("push", "refs/tags/other"),
            ("workflow_dispatch", "refs/tags/v0.1.0"),
        ]:
            with self.subTest(event=event, ref=ref):
                result = validator.validate_release(self.repository / "missing", event, ref)
                self.assertFalse(result["validated"])

    def run_cli(self, output, ref="refs/tags/v0.1.0", event="push"):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--repository", str(self.repository),
             "--event-name", event, "--ref", ref, "--main-ref", "refs/heads/main",
             "--github-output", str(output)],
            capture_output=True, text=True,
        )

    def test_cli_only_sets_true_after_successful_validation(self):
        self.git("tag", "v0.1.0")
        output = self.repository / "job-output"
        result = self.run_cli(output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["validated"])
        self.assertEqual(output.read_text(), "validated=true\n")

    def test_cli_failed_release_does_not_set_approval(self):
        output = self.repository / "job-output"
        result = self.run_cli(output, ref="refs/tags/v9.9.9")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())

    def test_cli_pull_request_sets_false(self):
        output = self.repository / "job-output"
        result = self.run_cli(output, event="pull_request", ref="refs/pull/22/merge")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(), "validated=false\n")


if __name__ == "__main__":
    unittest.main()
