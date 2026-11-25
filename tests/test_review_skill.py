# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Stage 1, 2 & 3 TDD tests for the vogtcon-review skill and CLI ground truth."""

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
SKILL_EXAMPLES = SKILL_DIR / "examples"
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


def _find_broken_markdown_links(md_path: Path, markdown_text: str) -> list[tuple[str, Path]]:
    prosaic = _strip_code_from_markdown(markdown_text)
    broken: list[tuple[str, Path]] = []
    for raw_target in MARKDOWN_LINK_RE.findall(prosaic):
        if raw_target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        target_path_str = raw_target.split("#", 1)[0]
        if not target_path_str:
            continue
        resolved = (md_path.parent / target_path_str).resolve()
        if not resolved.exists():
            broken.append((raw_target, resolved))
    return broken


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
        broken = _find_broken_markdown_links(SKILL_MD, body)
        self.assertEqual(
            broken,
            [],
            f"Broken relative markdown links in {SKILL_MD}: {broken}",
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


class TestReviewSkillStage2Contract(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(SKILL_MD.is_file(), f"Missing {SKILL_MD}")
        _, self.body = _parse_skill_document(SKILL_MD)
        self.lower = self.body.lower()

    def _assert_matches(self, pattern: str, msg: str) -> None:
        self.assertRegex(self.body, re.compile(pattern, re.IGNORECASE | re.DOTALL), msg)

    def test_explain_invocation_run_id_and_run_separation(self) -> None:
        self.assertIn('vogtcon explain "$log_path" --json', self.body)
        self.assertIn('--run-id "$run_id"', self.body)
        self._assert_matches(
            r"(mantener|keep).{0,60}(ejecuciones|runs).{0,40}(separad|separate)",
            "SKILL.md must keep runs separated when reviewing an entire log",
        )
        self._assert_matches(
            r"output_version.{0,40}1.{0,120}(detener|stop)",
            "SKILL.md must check output_version == 1 and stop on incompatible version",
        )

    def test_explain_reporting_fields_and_contract_id_comparison(self) -> None:
        for field in ("run_id", "action_index", "decision_sequence", "tool_event_sequence", "diagnostics.line"):
            self.assertIn(field, self.body, f"SKILL.md must reference {field!r}")
        self._assert_matches(
            r"contract_id.{0,180}(difieren|difere|mismatch|differs|distint)",
            "SKILL.md must flag mismatched contract_id when both contract and trace are provided",
        )
        self._assert_matches(
            r"(coincidencia|match).{0,120}contract_id.{0,160}(pendiente|pending|unverified|no\s+prueba|does\s+not\s+prove).{0,120}(identidad|identity|revisi[oó]n|revision|fingerprint|huella)",
            "SKILL.md must note matching contract_id leaves exact contract revision/fingerprint identity pending",
        )

    def test_traces_table_block_abort_and_prior_block_retry_guard(self) -> None:
        # Row 1: block / abort & pre_abort
        self.assertIn("violation_rules", self.body)
        self.assertIn("pre_abort", self.body)
        self._assert_matches(
            r"(block|abort).{0,140}(impidi[oó]|prevented)",
            "SKILL.md must state block/abort prevented tool invocation",
        )
        self._assert_matches(
            r"pre_abort.{0,120}(sin\s+acciones|no\s+runtime\s+actions|without\s+runtime\s+actions)",
            "SKILL.md must state pre_abort is a terminal without runtime actions",
        )
        # Row 2: allow / allow_with_warning + prior_same_tool_block_action_index
        self.assertIn("allow_with_warning", self.body)
        self.assertIn("prior_same_tool_block_action_index", self.body)
        self.assertNotIn(
            "is_retry",
            self.lower,
            "SKILL.md must NOT use fabricated field name 'is_retry'",
        )
        self._assert_matches(
            r"prior_same_tool_block_action_index.{0,220}(mismo\s+nombre|same\s+tool(?:\s+name)?).{0,180}(ambos\s+[ií]ndices|both\s+indices|both\s+action\s+indices)",
            "SKILL.md must explain prior_same_tool_block_action_index as subsequent allowed same-tool-name attempt and cite both indices",
        )
        self._assert_matches(
            r"(identidad\s+de\s+argumentos|argument\s+identity).{0,120}(autorizaci[oó]n\s+del\s+host|host\s+authorization).{0,120}(relaci[oó]n\s+de\s+reintento|retry\s+relationship).{0,120}(sin\s+determinar|undetermined|indeterminad)",
            "SKILL.md must leave argument identity, host authorization, and retry relationship undetermined",
        )

    def test_traces_table_outcomes_integrity_and_errors(self) -> None:
        # Row 3: completed -> not_verified
        self.assertIn("not_verified", self.body)
        self._assert_matches(
            r"completed.{0,160}(retorn[oó]|returned).{0,120}not_verified",
            "SKILL.md must state tool_outcome completed means callable returned and external effect is not_verified",
        )
        # Row 4: error / unfinalized / unknown -> indeterminate + tool_error complete
        for token in ("unfinalized", "unknown", "indeterminate", "trace_integrity", "terminal", "tool_error"):
            self.assertIn(token, self.body, f"SKILL.md must reference {token!r}")
        self._assert_matches(
            r"tool_error.{0,140}(complete|completa)",
            "SKILL.md must note a run ending in tool_error can have trace_integrity complete",
        )
        # Row 5: partial -> partial_log
        self.assertIn("partial_log", self.body)
        self._assert_matches(
            r"partial.{0,180}(ausente|missing|faltante).{0,160}(conservar|preserv|hechos|facts)",
            "SKILL.md must explain partial traces identify missing evidence while preserving supported facts",
        )
        # Row 6: inconsistent_log
        self.assertIn("inconsistent_log", self.body)
        self._assert_matches(
            r"inconsistent_log.{0,180}(contradicci[oó]n|contradiction).{0,160}(coherentes|coherent)",
            "SKILL.md must explain inconsistent_log cites contradiction per run and separates coherent runs",
        )
        # Row 7: invalid_log / run_not_found / io_error
        for token in ("invalid_log", "run_not_found", "io_error"):
            self.assertIn(token, self.body, f"SKILL.md must reference {token!r}")
        self._assert_matches(
            r"run_not_found.{0,220}(otro\s+id|another\s+id|another\s+run\s+id).{0,120}(archivo\s+completo|full[- ]file|entire\s+file|whole\s+file)",
            "SKILL.md must ask for another ID or offer full-file review on run_not_found",
        )
        self._assert_matches(
            r"--run-id.{0,180}(todo\s+el\s+archivo|whole\s+file|entire\s+file|full\s+file)",
            "SKILL.md must note --run-id still validates format of the whole file",
        )

    def test_complete_integrity_disclaimer(self) -> None:
        self._assert_matches(
            r"complete.{0,120}(integridad\s+del\s+registro|log\s+integrity|trace\s+integrity)",
            "SKILL.md must clarify complete refers to log/trace integrity only",
        )
        self._assert_matches(
            r"(autorizaci[oó]n\s+efectiva|effective\s+authorization).{0,120}(entrega\s+externa|external\s+delivery).{0,120}([eé]xito\s+de\s+la\s+tarea|task\s+success)",
            "SKILL.md must state effective authorization, external delivery, and task success require additional host/destination evidence",
        )


class TestNotificationExampleTraces(unittest.TestCase):
    def _explain_preserving_bytes(self, trace_name: str, extra_args: list[str] | None = None) -> tuple[int, dict[str, object]]:
        trace_path = SKILL_EXAMPLES / trace_name
        self.assertTrue(trace_path.is_file(), f"Missing example trace at {trace_path}")
        before_digest = _sha256_bytes(trace_path)
        args = ["explain", str(trace_path), *(extra_args or []), "--json"]
        proc = _run_vogtcon(args)
        after_digest = _sha256_bytes(trace_path)
        self.assertEqual(before_digest, after_digest, f"{trace_path} bytes modified")
        self.assertEqual(proc.stderr, "", f"Unexpected stderr for {args}: {proc.stderr}")
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["output_version"], 1)
        self.assertEqual(payload["command"], "explain")
        return proc.returncode, payload

    def test_notification_recovery_trace(self) -> None:
        code, payload = self._explain_preserving_bytes(
            "notification_recovery.jsonl",
            ["--run-id", "wheel-recovery"],
        )
        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "ok")
        runs = payload["data"]["runs"]
        self.assertEqual(len(runs), 1)
        run = runs[0]
        self.assertEqual(run["run_id"], "wheel-recovery")
        self.assertEqual(run["trace_integrity"], "complete")
        self.assertEqual(run["terminal"], "post_execution")
        self.assertEqual(len(run["actions"]), 2)

        a1, a2 = run["actions"]
        self.assertEqual(a1["action_index"], 1)
        self.assertEqual(a1["decision"], "block")
        self.assertIn("sensitive_requires_approval", a1["violation_rules"])
        self.assertEqual(a1["tool_outcome"], "prevented")

        self.assertEqual(a2["action_index"], 2)
        self.assertEqual(a2["decision"], "allow")
        self.assertEqual(a2["prior_same_tool_block_action_index"], 1)
        self.assertEqual(a2["tool_outcome"], "completed")
        self.assertEqual(a2["effect_evidence"], "not_verified")

        missing_code, missing_payload = self._explain_preserving_bytes(
            "notification_recovery.jsonl",
            ["--run-id", "missing"],
        )
        self.assertEqual(missing_code, 2)
        self.assertEqual(missing_payload["status"], "run_not_found")
        self.assertIsNone(missing_payload["data"])
        self.assertEqual(missing_payload["diagnostics"][0]["code"], "run_not_found")

    def test_notification_tool_error_trace(self) -> None:
        code, payload = self._explain_preserving_bytes("notification_tool_error.jsonl")
        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "ok")
        runs = payload["data"]["runs"]
        self.assertGreaterEqual(len(runs), 1)
        run = runs[0]
        self.assertEqual(run["trace_integrity"], "complete")
        self.assertEqual(run["terminal"], "tool_error")
        self.assertTrue(
            any(
                a["tool_outcome"] == "error" and a["effect_evidence"] == "indeterminate"
                for a in run["actions"]
            ),
            f"Expected an action with tool_outcome='error' and effect_evidence='indeterminate': {run['actions']}",
        )

    def test_notification_partial_trace(self) -> None:
        code, payload = self._explain_preserving_bytes("notification_partial.jsonl")
        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "ok")
        diag_codes = [d["code"] for d in payload["diagnostics"]]
        self.assertIn("partial_log", diag_codes)
        runs = payload["data"]["runs"]
        self.assertGreaterEqual(len(runs), 1)
        run = runs[0]
        self.assertEqual(run["trace_integrity"], "partial")
        self.assertIsNone(run["terminal"])
        self.assertTrue(
            any(
                a["tool_outcome"] == "unfinalized" and a["effect_evidence"] == "indeterminate"
                for a in run["actions"]
            ),
            f"Expected an action with tool_outcome='unfinalized' and effect_evidence='indeterminate': {run['actions']}",
        )

    def test_notification_inconsistent_trace(self) -> None:
        code, payload = self._explain_preserving_bytes("notification_inconsistent.jsonl")
        self.assertEqual(code, 1)
        self.assertEqual(payload["status"], "inconsistent_log")
        diag_codes = [d["code"] for d in payload["diagnostics"]]
        self.assertIn("inconsistent_log", diag_codes)
        runs = payload["data"]["runs"]
        self.assertTrue(
            any(r["trace_integrity"] == "inconsistent" for r in runs),
            f"Expected at least one inconsistent run in {runs}",
        )
        self.assertTrue(
            any(r["trace_integrity"] in ("complete", "partial") for r in runs),
            f"Expected at least one coherent run preserved in {runs}",
        )


class TestCfdiExampleAndDocs(unittest.TestCase):
    def _read_doc_with_valid_links(self, doc_path: Path) -> str:
        self.assertTrue(doc_path.is_file(), f"Missing documentation file {doc_path}")
        text = doc_path.read_text(encoding="utf-8")
        self.assertTrue(text.strip(), f"Documentation file {doc_path} must be non-empty")
        broken = _find_broken_markdown_links(doc_path, text)
        self.assertEqual(broken, [], f"Broken relative markdown links in {doc_path}: {broken}")
        return text

    def test_cfdi_example_trace_and_contract_validation(self) -> None:
        from vogtcon import RunEvent

        cfdi_trace = SKILL_EXAMPLES / "cfdi_reconciliation.jsonl"
        self.assertTrue(cfdi_trace.is_file(), f"Missing CFDI example trace at {cfdi_trace}")

        lines = [line for line in cfdi_trace.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertGreaterEqual(len(lines), 4, "CFDI trace must contain RunEvent v1 JSONL records")
        events = [RunEvent.model_validate_json(line) for line in lines]
        self.assertTrue(all(ev.schema_version == 1 for ev in events))
        self.assertTrue(any(ev.tool_name == "mark_reconciled" for ev in events))

        trace_before = _sha256_bytes(cfdi_trace)
        explain_proc = _run_vogtcon(["explain", str(cfdi_trace), "--json"])
        trace_after = _sha256_bytes(cfdi_trace)
        self.assertEqual(trace_before, trace_after, f"{cfdi_trace} bytes modified")
        self.assertEqual(explain_proc.returncode, 0, explain_proc.stderr)
        self.assertEqual(explain_proc.stderr, "")

        explain_payload = json.loads(explain_proc.stdout)
        self.assertEqual(explain_payload["output_version"], 1)
        self.assertEqual(explain_payload["command"], "explain")
        self.assertEqual(explain_payload["status"], "ok")
        runs = explain_payload["data"]["runs"]
        self.assertGreaterEqual(len(runs), 1)
        run = runs[0]
        self.assertEqual(run["contract_id"], "example.cfdi_reconciliation")

        actions = run["actions"]
        blocked_actions = [
            a for a in actions
            if a["tool_name"] == "mark_reconciled"
            and a["decision"] == "block"
            and "cfdi.exact_match_required" in a["violation_rules"]
        ]
        self.assertTrue(blocked_actions, f"Expected mark_reconciled block citing cfdi.exact_match_required: {actions}")
        blocked_idx = blocked_actions[0]["action_index"]
        allowed_actions = [
            a for a in actions
            if a["tool_name"] == "mark_reconciled"
            and a["decision"] == "allow"
            and a["prior_same_tool_block_action_index"] == blocked_idx
            and a["tool_outcome"] == "completed"
            and a["effect_evidence"] == "not_verified"
        ]
        self.assertTrue(
            allowed_actions,
            f"Expected subsequent mark_reconciled allow with prior_same_tool_block_action_index={blocked_idx}: {actions}",
        )

        cfdi_contract = REPO_ROOT / "examples" / "cfdi_contract.yaml"
        contract_before = _sha256_bytes(cfdi_contract)
        validate_proc = _run_vogtcon(["validate", str(cfdi_contract), "--json"])
        contract_after = _sha256_bytes(cfdi_contract)
        self.assertEqual(contract_before, contract_after, f"{cfdi_contract} bytes modified")
        self.assertEqual(validate_proc.returncode, 2)
        self.assertEqual(validate_proc.stderr, "")
        validate_payload = json.loads(validate_proc.stdout)
        self.assertEqual(validate_payload["status"], "unsupported_rules")
        self.assertEqual(
            validate_payload["data"],
            {"field": "runtime_rules", "unsupported_ids": ["cfdi.exact_match_required"]},
        )

    def test_examples_readme_documents_provenance_and_links(self) -> None:
        text = self._read_doc_with_valid_links(SKILL_EXAMPLES / "README.md")
        for filename in (
            "notification_recovery.jsonl",
            "notification_tool_error.jsonl",
            "notification_partial.jsonl",
            "notification_inconsistent.jsonl",
            "cfdi_reconciliation.jsonl",
        ):
            self.assertIn(filename, text, f"examples/README.md must document {filename}")
        self.assertRegex(
            text,
            re.compile(r"(WorkflowController|wheel-recovery|controlador|controller)", re.IGNORECASE),
            "examples/README.md must document controller provenance for Notificaciones traces",
        )
        self.assertRegex(
            text,
            re.compile(r"(sint[eé]tic|synthetic|fictici|fictitious)", re.IGNORECASE),
            "examples/README.md must document synthetic/fictitious provenance for cfdi_reconciliation.jsonl",
        )

    def test_guide_markdown_exists_links_and_content(self) -> None:
        text = self._read_doc_with_valid_links(SKILL_DIR / "GUIDE.md")
        self.assertIn("0.4.0", text)
        self.assertRegex(
            text,
            re.compile(r"(consumidor|consumer|wheel)", re.IGNORECASE),
            "GUIDE.md must explain clean consumer wheel setup",
        )
        self.assertRegex(
            text,
            re.compile(r"(sin\s+importar|without\s+importing).{0,80}(checkout|repositorio|repo)|benchmark", re.IGNORECASE),
            "GUIDE.md must forbid importing repo checkout or installing benchmark",
        )
        for token in ("notification_contract", "notification_recovery.jsonl", "cfdi_contract.yaml", "cfdi_reconciliation.jsonl"):
            self.assertIn(token, text, f"GUIDE.md must cover walkthrough artifact {token!r}")

    def test_verification_markdown_exists_links_and_content(self) -> None:
        text = self._read_doc_with_valid_links(SKILL_DIR / "VERIFICATION.md")
        self.assertIn("0.4.0", text)
        self.assertIn("vogtcon validate", text)
        self.assertIn("vogtcon explain", text)
        self.assertRegex(
            text,
            re.compile(r"(solicitud|prompt|request)", re.IGNORECASE),
            "VERIFICATION.md must record user prompts/requests",
        )
        self.assertRegex(
            text,
            re.compile(r"(c[oó]digo\s+de\s+salida|exit\s+code)", re.IGNORECASE),
            "VERIFICATION.md must record exit codes",
        )
        self.assertRegex(
            text,
            re.compile(r"(esperad|expected).{0,200}(observad|observed)", re.IGNORECASE | re.DOTALL),
            "VERIFICATION.md must compare expected vs observed JSON facts",
        )
        self.assertRegex(
            text,
            re.compile(r"sha-?256", re.IGNORECASE),
            "VERIFICATION.md must record SHA-256 byte preservation",
        )
        self.assertRegex(
            text,
            re.compile(r"(solo\s+lectura|read[- ]only)", re.IGNORECASE),
            "VERIFICATION.md must confirm read-only behavior",
        )
        self.assertRegex(
            text,
            re.compile(r"(validador|validator|frontmatter|SKILL\.md)", re.IGNORECASE),
            "VERIFICATION.md must record skill format validation",
        )
        self.assertRegex(
            text,
            re.compile(r"(fase\s*3|phase\s*3).{0,120}\bmcp\b|\bmcp\b.{0,120}(fase\s*3|phase\s*3)", re.IGNORECASE | re.DOTALL),
            "VERIFICATION.md must document deferred cases including Phase 3 MCP",
        )


if __name__ == "__main__":
    unittest.main()
