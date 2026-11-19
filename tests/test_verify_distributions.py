# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / ".github/scripts/verify_distributions.py"
SPEC = importlib.util.spec_from_file_location("verify_distributions", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class DistributionVerificationTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.directory = Path(scratch.name)
        self.files = {
            "vogtcon-0.1.0-py3-none-any.whl": b"wheel bytes",
            "vogtcon-0.1.0.tar.gz": b"source bytes",
        }
        for name, contents in self.files.items():
            (self.directory / name).write_bytes(contents)
        self.expected = {
            name: hashlib.sha256(contents).hexdigest()
            for name, contents in self.files.items()
        }

    def test_manifest_and_check_accept_the_original_bytes(self):
        self.assertEqual(validator.manifest(self.directory), self.expected)
        self.assertEqual(
            validator.check(self.directory, json.dumps(self.expected)), self.expected
        )

    def test_changed_bytes_are_rejected_against_independent_expected_hashes(self):
        (self.directory / next(iter(self.files))).write_bytes(b"altered download")
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            validator.check(self.directory, json.dumps(self.expected))

    def test_uv_build_bookkeeping_is_not_a_distribution(self):
        (self.directory / ".gitignore").write_text("*\n")
        self.assertEqual(validator.manifest(self.directory), self.expected)
        self.assertEqual(
            validator.check(self.directory, json.dumps(self.expected)), self.expected
        )

    def test_missing_extra_and_renamed_files_are_rejected(self):
        wheel = self.directory / next(iter(self.files))
        wheel.rename(self.directory / "different.whl")
        with self.assertRaisesRegex(ValueError, "filenames do not match"):
            validator.check(self.directory, json.dumps(self.expected))
        (self.directory / "different.whl").unlink()
        with self.assertRaises(ValueError):
            validator.check(self.directory, json.dumps(self.expected))
        wheel.write_bytes(b"wheel bytes")
        (self.directory / "unexpected.txt").write_text("unexpected")
        with self.assertRaises(ValueError):
            validator.check(self.directory, json.dumps(self.expected))

    def test_invalid_manifests_are_rejected(self):
        for value in ["not json", "[]", "{}", '{"../escape.whl":"x"}',
                      json.dumps({name: "invalid" for name in self.files}),
                      '{"a.whl":"x","a.whl":"y"}',
                      '{"../a.whl":"x","a.tar.gz":"y"}']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validator.check(self.directory, value)

    def test_symlinks_and_missing_directory_are_rejected(self):
        with self.assertRaises(ValueError):
            validator.manifest(self.directory / "missing")
        wheel = self.directory / next(iter(self.files))
        wheel.unlink()
        wheel.symlink_to(self.directory / "vogtcon-0.1.0.tar.gz")
        with self.assertRaisesRegex(ValueError, "regular file"):
            validator.check(self.directory, json.dumps(self.expected))

    def test_cli_exits_nonzero_on_corruption(self):
        wheel = self.directory / next(iter(self.files))
        wheel.write_bytes(b"corruption")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "check", "--directory", str(self.directory),
             "--expected-json", json.dumps(self.expected)],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
