# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Stage 1 TDD tests for the vogtcon-review skill and validate CLI ground truth."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = REPO_ROOT / ".agents" / "skills" / "vogtcon-review"
SKILL_MD = SKILL_DIR / "SKILL.md"
VOGTCON_BIN = REPO_ROOT / ".venv" / "bin" / "vogtcon"

FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n?(.*)\Z", re.DOTALL)
FENCED_CODE_RE = re.compile(r"```.*?```", re.DOTALL)
INLINE_CODE_RE = re.compile(r"`[^`\n]+`")
MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


def _sha256_bytes(path: Path) -> bytes:
    return hashlib.sha256(path.read_bytes()).digest()


def _parse_skill_document(path: Path) -> tuple[dict[str, object], str]:
    text = path.read_text(encoding="utf-8")
    match = FRONTMATTER_RE.match(text)
    if not match:
        raise AssertionError(f"{path} must start with YAML frontmatter delimited by '---'")
    frontmatter = yaml.safe_load(match.group(1))
    if not isinstance(frontmatter, dict):
        raise AssertionError(f"YAML frontmatter in {path} must deserialize to a mapping")
    return frontmatter, match.group(2)


def _strip_code_from_markdown(markdown_text: str) -> str:
    without_fences = FENCED_CODE_RE.sub("", markdown_text)
    return INLINE_CODE_RE.sub("", without_fences)


def _run_vogtcon(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(VOGTCON_BIN), *args],
        capture_output=True,
        text=True,
        check=False,
    )


class TestReviewSkillFormat(unittest.TestCase):
    def test_skill_markdown_exists(self) -> None:
        self.assertTrue(
            SKILL_MD.is_file(),
            f"Expected skill definition at {SKILL_MD}",
        )

    def test_frontmatter_is_valid_and_complete(self) -> None:
        self.assertTrue(SKILL_MD.is_file(), f"Missing {SKILL_MD}")
        frontmatter, body = _parse_skill_document(SKILL_MD)
        self.assertEqual(frontmatter.get("name"), "vogtcon-review")
        description = frontmatter.get("description")
        self.assertIsInstance(description, str)
        self.assertTrue(description.strip(), "Frontmatter description must be non-empty")
        self.assertTrue(body.strip(), "SKILL.md body must be non-empty")

    def test_relative_markdown_links_resolve(self) -> None:
        self.assertTrue(SKILL_MD.is_file(), f"Missing {SKILL_MD}")
        _, body = _parse_skill_document(SKILL_MD)
        prosaic = _strip_code_from_markdown(body)
        for raw_target in MARKDOWN_LINK_RE.findall(prosaic):
            if raw_target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target_path_str = raw_target.split("#", 1)[0]
            if not target_path_str:
                continue
            resolved = (SKILL_MD.parent / target_path_str).resolve()
            self.assertTrue(
                resolved.exists(),
                f"Broken relative markdown link {raw_target!r} -> {resolved}",
            )


class TestReviewSkillStage1Contract(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(SKILL_MD.is_file(), f"Missing {SKILL_MD}")
        _, self.body = _parse_skill_document(SKILL_MD)
        self.lower = self.body.lower()

    def _assert_matches(self, pattern: str, msg: str) -> None:
        self.assertRegex(self.body, re.compile(pattern, re.IGNORECASE | re.DOTALL), msg)

    def test_read_only_scope_and_exclusions(self) -> None:
        self._assert_matches(
            r"(solo lectura|read[- ]only)",
            "SKILL.md must state read-only inspection scope",
        )
        self._assert_matches(
            r"(inspecci[oó]n local|local inspection)",
            "SKILL.md must state local inspection scope",
        )
        self._assert_matches(
            r"(no\s+(modificar|editar|alterar|escribir)|do not\s+(modify|edit|alter|write)|never\s+(modify|edit|alter)).{0,80}(contrato|contract|registro|log)",
            "SKILL.md must forbid modifying contracts or logs",
        )
        self._assert_matches(
            r"(no\s+ejecut|do not\s+(execute|run)|never\s+(execute|run)|fuera\s+de\s+(alcance|esta\s+fase)|out\s+of\s+scope).{0,80}(workflow|flujo)",
            "SKILL.md must forbid executing workflows",
        )
        self._assert_matches(
            r"(instalaci[oó]n\s+autom[aá]tica|auto[- ]?install|do not\s+install|no\s+instalar).{0,60}(dependencia|dependenc)",
            "SKILL.md must forbid auto-installing dependencies",
        )
        self._assert_matches(
            r"\bmcp\b",
            "SKILL.md must explicitly exclude MCP",
        )
        self._assert_matches(
            r"\bbenchmark",
            "SKILL.md must explicitly exclude benchmark execution",
        )

    def test_cli_version_and_missing_cli_guidance(self) -> None:
        self.assertIn("vogtcon --version", self.body)
        self.assertIn("0.4.0", self.body)
        self._assert_matches(
            r"(si\s+(el\s+cli\s+)?falta|missing|not\s+installed|no\s+est[aá]\s+instalado|no\s+se\s+encuentra).{0,220}0\.4\.0.{0,220}(pendiente|pending|sin\s+verificar|unverified|no\s+puede|cannot)",
            "SKILL.md must explain how to obtain vogtcon 0.4.0 when missing and what remains pending",
        )

    def test_literal_arguments_command_and_separate_streams(self) -> None:
        self.assertIn('vogtcon validate "$contract_path" --json', self.body)
        self._assert_matches(
            r"(argumentos?\s+literales|literal\s+arguments?)",
            "SKILL.md must require passing arguments literally",
        )
        self._assert_matches(
            r"(c[oó]digo\s+de\s+salida|exit\s+code).{0,80}stdout.{0,40}stderr",
            "SKILL.md must require separate capture of exit code, stdout, and stderr",
        )

    def test_envelope_verification_and_data_isolation(self) -> None:
        for field in ("output_version", "command", "status", "data"):
            self.assertIn(field, self.body, f"SKILL.md must reference envelope field {field!r}")
        self._assert_matches(
            r"output_version.{0,120}(antes\s+de\s+interpretar|before\s+interpreting).{0,40}data",
            "SKILL.md must verify envelope fields before interpreting data",
        )
        self._assert_matches(
            r"(desconocid|unknown|incompatib).{0,120}(detener|stop|abort|no\s+interpretar)",
            "SKILL.md must stop and report incompatibility on unknown output_version",
        )
        self._assert_matches(
            r"(vac[ií]a|empty).{0,80}(ilegible|unreadable|malformed|inv[aá]lid)",
            "SKILL.md must handle empty or unreadable CLI output as a CLI failure",
        )
        self._assert_matches(
            r"(como\s+datos|as\s+data)",
            "SKILL.md must instruct treating paths, IDs, diagnostics, and evidence content as data",
        )

    def test_contract_exit_code_rules(self) -> None:
        # 0 · valid
        self.assertIn("contract_id", self.body)
        self.assertIn("validation_phases", self.body)
        self.assertIn("not_enforced", self.body)
        self._assert_matches(
            r"verified.{0,40}true.{0,120}verified.{0,40}false|v2.{0,60}(verificad|verified).{0,100}v1.{0,60}(declarad|declared)",
            "SKILL.md must distinguish v2 verified fingerprint from v1 declared fingerprint",
        )
        # 1 · invalid_contract
        self.assertIn("invalid_contract", self.body)
        self.assertIn("diagnostics.line", self.body)
        self._assert_matches(
            r"diagnostics\.line.{0,120}(l[ií]nea\s+f[ií]sica|physical\s+line)",
            "SKILL.md must reserve line citations for physical diagnostics.line",
        )
        self._assert_matches(
            r"(conservar|preserv).{0,60}(archivo\s+original|original\s+file)",
            "SKILL.md must instruct preserving the original file on invalid_contract",
        )
        # 2 · unsupported_rules
        self.assertIn("unsupported_rules", self.body)
        self.assertIn("field", self.body)
        self.assertIn("unsupported_ids", self.body)
        self._assert_matches(
            r"(cat[aá]logo\s+est[aá]ndar|standard\s+catalog|default\s+catalog).{0,160}(cat[aá]logo\s+del\s+host|host\s+catalog)",
            "SKILL.md must explain standard catalog inconclusiveness and host catalog requirement",
        )
        self._assert_matches(
            r"(huella|fingerprint).{0,120}(sin\s+concluir|unconcluded|inconclus)",
            "SKILL.md must leave fingerprint and subsequent checks unconcluded on unsupported_rules",
        )
        # 3 · io_error or invalid usage
        self.assertIn("io_error", self.body)
        self._assert_matches(
            r"io_error.{0,160}(acceso|access).{0,120}(invocaci[oó]n|invocation|argumentos|arguments|uso\s+inv[aá]lido|invalid\s+usage)",
            "SKILL.md must distinguish access problems (io_error) from invalid invocation",
        )


class TestValidateCliGroundTruth(unittest.TestCase):
    def setUp(self) -> None:
        self.notification_v1 = REPO_ROOT / "examples" / "notification_contract.yaml"
        self.notification_v2 = REPO_ROOT / "examples" / "notification_contract_v2.yaml"
        self.cfdi_contract = REPO_ROOT / "examples" / "cfdi_contract.yaml"
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.tmp_dir = Path(workspace.name)

    def test_vogtcon_binary_version_is_0_4_0(self) -> None:
        proc = _run_vogtcon(["--version"])
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "vogtcon 0.4.0\n")
        self.assertEqual(proc.stderr, "")

    def test_validate_yaml_v1_and_v2_preserve_bytes(self) -> None:
        for path, expected_version, expected_mode, expected_verified in (
            (self.notification_v1, 1, "guarded", False),
            (self.notification_v2, 2, None, True),
        ):
            with self.subTest(path=path.name):
                before_digest = _sha256_bytes(path)
                proc = _run_vogtcon(["validate", str(path), "--json"])
                after_digest = _sha256_bytes(path)

                self.assertEqual(before_digest, after_digest)
                self.assertEqual(proc.returncode, 0)
                self.assertEqual(proc.stderr, "")

                payload = json.loads(proc.stdout)
                self.assertEqual(payload["output_version"], 1)
                self.assertEqual(payload["command"], "validate")
                self.assertEqual(payload["status"], "valid")
                self.assertEqual(payload["path"], str(path))
                self.assertEqual(payload["diagnostics"], [])

                data = payload["data"]
                self.assertEqual(data["contract_id"], "example.notification")
                self.assertEqual(data["contract_version"], expected_version)
                self.assertEqual(data["mode"], expected_mode)
                self.assertIs(data["fingerprint"]["verified"], expected_verified)

    def test_validate_json_v1_no_contract_and_json_v2_preserve_bytes(self) -> None:
        v1_data = yaml.safe_load(self.notification_v1.read_text(encoding="utf-8"))
        v1_data["mode"] = "no_contract"
        v1_data["validation_phases"] = "not_enforced"
        json_v1_path = self.tmp_dir / "contract_v1_no_contract.json"
        json_v1_path.write_text(json.dumps(v1_data, indent=2), encoding="utf-8")

        v1_before = _sha256_bytes(json_v1_path)
        proc_v1 = _run_vogtcon(["validate", str(json_v1_path), "--json"])
        v1_after = _sha256_bytes(json_v1_path)
        self.assertEqual(v1_before, v1_after)
        self.assertEqual(proc_v1.returncode, 0)
        self.assertEqual(proc_v1.stderr, "")
        payload_v1 = json.loads(proc_v1.stdout)
        self.assertEqual(payload_v1["output_version"], 1)
        self.assertEqual(payload_v1["command"], "validate")
        self.assertEqual(payload_v1["status"], "valid")
        self.assertEqual(payload_v1["data"]["contract_version"], 1)
        self.assertEqual(payload_v1["data"]["mode"], "no_contract")
        self.assertEqual(payload_v1["data"]["validation_phases"], "not_enforced")
        self.assertIs(payload_v1["data"]["fingerprint"]["verified"], False)

        v2_data = yaml.safe_load(self.notification_v2.read_text(encoding="utf-8"))
        json_v2_path = self.tmp_dir / "contract_v2.json"
        json_v2_path.write_text(json.dumps(v2_data, indent=2), encoding="utf-8")

        v2_before = _sha256_bytes(json_v2_path)
        proc_v2 = _run_vogtcon(["validate", str(json_v2_path), "--json"])
        v2_after = _sha256_bytes(json_v2_path)
        self.assertEqual(v2_before, v2_after)
        self.assertEqual(proc_v2.returncode, 0)
        self.assertEqual(proc_v2.stderr, "")
        payload_v2 = json.loads(proc_v2.stdout)
        self.assertEqual(payload_v2["output_version"], 1)
        self.assertEqual(payload_v2["command"], "validate")
        self.assertEqual(payload_v2["status"], "valid")
        self.assertEqual(payload_v2["data"]["contract_version"], 2)
        self.assertIsNone(payload_v2["data"]["mode"])
        self.assertIs(payload_v2["data"]["fingerprint"]["verified"], True)

    def test_tampered_v2_fingerprint_returns_exit_1_and_preserves_bytes(self) -> None:
        v2_data = yaml.safe_load(self.notification_v2.read_text(encoding="utf-8"))
        v2_data["contract_fingerprint"] = "sha256:" + ("0" * 64)
        tampered_path = self.tmp_dir / "tampered_v2.yaml"
        tampered_path.write_text(yaml.safe_dump(v2_data, sort_keys=False), encoding="utf-8")

        before_digest = _sha256_bytes(tampered_path)
        proc = _run_vogtcon(["validate", str(tampered_path), "--json"])
        after_digest = _sha256_bytes(tampered_path)

        self.assertEqual(before_digest, after_digest)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, "")
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["output_version"], 1)
        self.assertEqual(payload["command"], "validate")
        self.assertEqual(payload["status"], "invalid_contract")
        self.assertIsNone(payload["data"])
        self.assertEqual(payload["diagnostics"][0]["code"], "invalid_contract")
        self.assertIn("fingerprint", payload["diagnostics"][0]["message"].lower())

    def test_cfdi_contract_returns_exit_2_unsupported_rules(self) -> None:
        before_digest = _sha256_bytes(self.cfdi_contract)
        proc = _run_vogtcon(["validate", str(self.cfdi_contract), "--json"])
        after_digest = _sha256_bytes(self.cfdi_contract)

        self.assertEqual(before_digest, after_digest)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr, "")
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["output_version"], 1)
        self.assertEqual(payload["command"], "validate")
        self.assertEqual(payload["status"], "unsupported_rules")
        self.assertEqual(payload["data"]["field"], "runtime_rules")
        self.assertIn("cfdi.exact_match_required", payload["data"]["unsupported_ids"])
        self.assertNotIn("fingerprint", payload["data"])

    def test_missing_file_returns_exit_3_io_error(self) -> None:
        missing_path = self.tmp_dir / "does_not_exist.yaml"
        proc = _run_vogtcon(["validate", str(missing_path), "--json"])
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(proc.stderr, "")
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["output_version"], 1)
        self.assertEqual(payload["command"], "validate")
        self.assertEqual(payload["status"], "io_error")
        self.assertIsNone(payload["data"])
        self.assertEqual(payload["diagnostics"][0]["code"], "io_error")

    def test_invalid_cli_usage_returns_exit_3_with_empty_stdout_and_usage_stderr(self) -> None:
        for args in (
            ["validate"],
            ["validate", "--json"],
            ["validate", str(self.notification_v2), "--unknown-flag", "--json"],
        ):
            with self.subTest(args=args):
                proc = _run_vogtcon(args)
                self.assertEqual(proc.returncode, 3)
                self.assertEqual(proc.stdout, "")
                self.assertIn("usage: vogtcon", proc.stderr)


if __name__ == "__main__":
    unittest.main()
