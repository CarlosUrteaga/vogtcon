# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
from typing import Any
import unittest
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage, BaseMessage, ToolMessage
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from vogtcon import (
    ActionProposal,
    EnforcementPolicy,
    ExecutionContext,
    GovernorInput,
    JsonlDecisionLog,
    TelemetryObserver,
    WorkflowController,
    load_contract,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "langchain_rag_agent.py"
PRE_EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "pre" / "langchain_rag_agent.py"
RUN_RAG_SH = Path(__file__).resolve().parents[1] / "scripts" / "run_rag.sh"
PREPARE_RAG_MODEL = Path(__file__).resolve().parents[1] / "scripts" / "prepare_rag_model.py"

SPEC = importlib.util.spec_from_file_location("langchain_rag_agent", EXAMPLE)
assert SPEC is not None and SPEC.loader is not None
langchain_rag_agent = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = langchain_rag_agent
SPEC.loader.exec_module(langchain_rag_agent)


def make_context(
    approval_granted: bool = True,
    observed_agent_fingerprint: str = langchain_rag_agent.AGENT_FINGERPRINT,
    contract_fingerprint: str | None = None,
    retrieved_doc_ids: list[str] | None = None,
) -> ExecutionContext:
    if contract_fingerprint is None:
        contract_doc = load_contract(
            langchain_rag_agent.CONTRACT_PATH,
            rule_catalog=langchain_rag_agent.RULES,
        )
        contract_fingerprint = contract_doc.contract.contract_fingerprint
    state: dict[str, Any] = {"approval_granted": approval_granted}
    if retrieved_doc_ids is not None:
        state["retrieved_doc_ids"] = list(retrieved_doc_ids)
    return ExecutionContext(
        state=state,
        available_tools=["publish_brief"],
        observed_agent_fingerprint=observed_agent_fingerprint,
        observed_contract_fingerprint=contract_fingerprint,
    )


class LangChainRagAgentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if sys.platform == "darwin" and platform.machine() in ("x86_64", "AMD64"):
            raise unittest.SkipTest(
                "LangChainRagAgentTests requires a supported RAG platform (Linux x86_64). "
                "Skipping full vector store integration tests on macOS Intel."
            )
        os.environ["HF_HUB_OFFLINE"] = "1"
        _, cls.corpus_docs = langchain_rag_agent.load_frozen_corpus()
        cls.real_vector_store = langchain_rag_agent.build_vector_store(cls.corpus_docs)
        cls.contract_doc = load_contract(
            langchain_rag_agent.CONTRACT_PATH,
            rule_catalog=langchain_rag_agent.RULES,
        )
        cls.contract_fingerprint = cls.contract_doc.contract.contract_fingerprint

    # =========================================================================
    # Group 1: Contract & Corpus Integrity
    # =========================================================================

    def test_example_script_does_not_import_enforcement_or_reference_internal(self) -> None:
        source = EXAMPLE.read_text(encoding="utf-8")
        self.assertNotIn("tools.enforcement", source)
        self.assertNotIn("internal/", source)
        self.assertNotIn("internal.", source)

    def test_load_contract_success_and_rejection_of_unsupported_rules_and_tampering(self) -> None:
        contract = load_contract(
            langchain_rag_agent.CONTRACT_PATH,
            rule_catalog=langchain_rag_agent.RULES,
        ).contract
        self.assertEqual(contract.contract_id, "example.langchain_rag_brief")
        self.assertEqual(contract.schema_version, 2)
        self.assertFalse(hasattr(contract, "mode"))

        with self.assertRaisesRegex(ValueError, "Unsupported runtime_rules"):
            load_contract(langchain_rag_agent.CONTRACT_PATH)

        with tempfile.TemporaryDirectory() as tmp:
            raw = langchain_rag_agent.CONTRACT_PATH.read_text(encoding="utf-8")
            tampered_path = Path(tmp) / "tampered.yaml"
            tampered_path.write_text(
                raw.replace("publish_brief", "tampered_tool", 1),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
                load_contract(tampered_path, rule_catalog=langchain_rag_agent.RULES)

    def test_load_frozen_corpus_loads_4_docs_and_detects_byte_alteration(self) -> None:
        manifest_data, docs = langchain_rag_agent.load_frozen_corpus()
        self.assertEqual(len(docs), 4)
        for doc in docs:
            self.assertIn("doc_id", doc.metadata)
            self.assertIn("sha256", doc.metadata)
            self.assertGreater(len(doc.page_content), 0)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            manifest_src = langchain_rag_agent.CORPUS_MANIFEST_PATH
            manifest_copy = tmp_dir / "manifest.json"
            manifest_copy.write_text(manifest_src.read_text(encoding="utf-8"), encoding="utf-8")
            for entry in manifest_data["documents"]:
                doc_file = manifest_src.parent / entry["file"]
                (tmp_dir / entry["file"]).write_bytes(doc_file.read_bytes())

            target_file = tmp_dir / manifest_data["documents"][0]["file"]
            target_file.write_bytes(target_file.read_bytes() + b"\nextra_tampered_byte")

            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                langchain_rag_agent.load_frozen_corpus(manifest_copy)

    def test_real_offline_vector_retrieval(self) -> None:
        results = self.real_vector_store.similarity_search(
            "Arquitectura de puerta sincrona en WorkflowController", k=2
        )
        self.assertGreater(len(results), 0)
        top_id = results[0].metadata.get("doc_id")
        self.assertEqual(top_id, "doc-gov-001")
        self.assertIn("WorkflowController", results[0].page_content)

    # =========================================================================
    # Group 2: Acceptance Cases A–D & Insufficient Evidence
    # =========================================================================

    def test_case_a_approved_publish(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "briefs"
            ctx = make_context(approval_granted=True)
            result = langchain_rag_agent.run_rag_brief(
                run_id="test-case-a",
                context=ctx,
                model=langchain_rag_agent.ScriptedRagChatModel(scenario="case_a_approved_publish"),
                vector_store=self.real_vector_store,
                output_dir=output_dir,
                mode="guarded",
            )
            self.assertEqual(len(result.actions), 1)
            self.assertEqual(result.actions[0].decision.decision, "allow")
            self.assertTrue(result.published)
            self.assertEqual(result.state, "finished")
            self.assertIsNotNone(result.brief_path)
            self.assertIsNotNone(result.brief_sha256)

            created_files = list(output_dir.glob("*.md"))
            self.assertEqual(len(created_files), 1)
            self.assertEqual(created_files[0], result.brief_path)

            file_bytes = created_files[0].read_bytes()
            computed_sha = hashlib.sha256(file_bytes).hexdigest()
            self.assertEqual(computed_sha, result.brief_sha256)

            file_text = file_bytes.decode("utf-8")
            citations_in_file = langchain_rag_agent.INLINE_CITATION_PATTERN.findall(file_text)
            self.assertTrue(citations_in_file)
            for cid in citations_in_file:
                self.assertIn(cid, result.citation_ids)

    def test_case_b_invalid_and_empty_citations_blocked(self) -> None:
        for scenario in ("case_b_invalid_citation", "case_b_empty_citation"):
            with self.subTest(scenario=scenario):
                with tempfile.TemporaryDirectory() as tmp:
                    output_dir = Path(tmp) / "briefs"
                    ctx = make_context(approval_granted=True)
                    result = langchain_rag_agent.run_rag_brief(
                        run_id=f"test-{scenario}",
                        context=ctx,
                        model=langchain_rag_agent.ScriptedRagChatModel(scenario=scenario),
                        vector_store=self.real_vector_store,
                        output_dir=output_dir,
                        mode="guarded",
                    )
                    self.assertEqual(len(result.actions), 1)
                    self.assertEqual(result.actions[0].decision.decision, "block")
                    violations = [v.rule for v in result.actions[0].decision.violations]
                    self.assertEqual(violations, ["brief.citations_retrieved"])
                    self.assertFalse(result.published)
                    self.assertIsNone(result.brief_path)
                    created_files = list(output_dir.glob("*.md"))
                    self.assertEqual(len(created_files), 0)

    def test_case_b_uncited_claim_smuggling_blocked(self) -> None:
        def smuggling_responder(messages: list[BaseMessage]) -> AIMessage:
            tool_messages = [m for m in messages if isinstance(m, ToolMessage)]
            retrieve_msgs = [m for m in tool_messages if m.name == "retrieve_context"]
            publish_msgs = [m for m in tool_messages if m.name == "publish_brief"]
            if not retrieve_msgs:
                return AIMessage(
                    content="",
                    tool_calls=[{
                        "name": "retrieve_context",
                        "args": {"query": "puerta sincrona y contexto confiable"},
                        "id": "call_1",
                    }],
                )
            if not publish_msgs:
                return AIMessage(
                    content="",
                    tool_calls=[{
                        "name": "publish_brief",
                        "args": {
                            "title": "Smuggling Attempt",
                            "claims": [
                                "Afirmación respaldada [doc-gov-001].",
                                "Afirmación no citada formalmente [doc-gov-002].",
                            ],
                            "citation_ids": ["doc-gov-001"],
                        },
                        "id": "call_2",
                    }],
                )
            return AIMessage(content="done")

        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "briefs"
            ctx = make_context(approval_granted=True)
            result = langchain_rag_agent.run_rag_brief(
                run_id="test-smuggling",
                context=ctx,
                model=langchain_rag_agent.ScriptedRagChatModel(responder=smuggling_responder),
                vector_store=self.real_vector_store,
                output_dir=output_dir,
                mode="guarded",
            )
            self.assertEqual(len(result.actions), 1)
            self.assertEqual(result.actions[0].decision.decision, "block")
            violations = [v.rule for v in result.actions[0].decision.violations]
            self.assertEqual(violations, ["brief.citations_retrieved"])
            self.assertFalse(result.published)
            self.assertEqual(list(output_dir.glob("*.md")), [])

    def test_case_c_unapproved_prompt_injection_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "briefs"
            ctx = make_context(approval_granted=False)
            result = langchain_rag_agent.run_rag_brief(
                run_id="test-case-c",
                context=ctx,
                model=langchain_rag_agent.ScriptedRagChatModel(scenario="case_c_unapproved"),
                vector_store=self.real_vector_store,
                output_dir=output_dir,
                mode="guarded",
            )
            self.assertEqual(len(result.actions), 1)
            self.assertEqual(result.actions[0].decision.decision, "block")
            violations = [v.rule for v in result.actions[0].decision.violations]
            self.assertEqual(violations, ["brief.approval_required"])
            self.assertFalse(result.published)
            self.assertIsNone(result.brief_path)
            self.assertEqual(list(output_dir.glob("*.md")), [])

    def test_rules_only_trust_host_context_state_not_arguments(self) -> None:
        contract = self.contract_doc.contract
        trusted_context = ExecutionContext(
            state={"approval_granted": False, "retrieved_doc_ids": ["doc-gov-001"]},
            available_tools=["publish_brief"],
            observed_agent_fingerprint=langchain_rag_agent.AGENT_FINGERPRINT,
            observed_contract_fingerprint=contract.contract_fingerprint,
        )
        adversarial_proposal = ActionProposal(
            tool_name="publish_brief",
            arguments={
                "title": "Adversarial Injection",
                "claims": ["Claim alleging override [doc-override-999]."],
                "citation_ids": ["doc-override-999"],
                "approval_granted": True,
                "retrieved_doc_ids": ["doc-override-999"],
            },
        )
        governor_req = GovernorInput(
            run_id="trust-boundary-check",
            phase="runtime",
            action=adversarial_proposal,
            context=trusted_context,
            contract=contract,
            policy=EnforcementPolicy(mode="guarded"),
        )
        self.assertTrue(langchain_rag_agent.brief_approval_required(governor_req))
        self.assertTrue(langchain_rag_agent.brief_citations_retrieved(governor_req))

        controller = WorkflowController.from_contract_path(
            langchain_rag_agent.CONTRACT_PATH,
            run_id="trust-boundary-check",
            policy=EnforcementPolicy(mode="guarded"),
            rule_catalog=langchain_rag_agent.RULES,
        )
        controller.begin(trusted_context)
        executed_calls: list[Any] = []
        outcome = controller.execute(
            adversarial_proposal,
            trusted_context,
            lambda prop: executed_calls.append(prop),
        )
        self.assertEqual(outcome.decision.decision, "block")
        self.assertFalse(outcome.executed)
        self.assertEqual(executed_calls, [])
        violation_rules = {v.rule for v in outcome.decision.violations}
        self.assertIn("brief.approval_required", violation_rules)
        self.assertIn("brief.citations_retrieved", violation_rules)

    def test_case_d_replan_after_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "briefs"
            ctx = make_context(approval_granted=True)
            result = langchain_rag_agent.run_rag_brief(
                run_id="test-case-d",
                context=ctx,
                model=langchain_rag_agent.ScriptedRagChatModel(scenario="case_d_replan_after_block"),
                vector_store=self.real_vector_store,
                output_dir=output_dir,
                mode="guarded",
            )
            self.assertEqual(len(result.actions), 2)
            self.assertEqual(result.action_logs[0]["action_index"], 1)
            self.assertEqual(result.action_logs[0]["decision"], "block")
            self.assertEqual(result.action_logs[0]["violation_rules"], ["brief.citations_retrieved"])
            self.assertFalse(result.action_logs[0]["published"])

            self.assertEqual(result.action_logs[1]["action_index"], 2)
            self.assertEqual(result.action_logs[1]["decision"], "allow")
            self.assertEqual(result.action_logs[1]["violation_rules"], [])
            self.assertTrue(result.action_logs[1]["published"])

            self.assertEqual(result.state, "finished")
            self.assertTrue(result.published)
            created_files = list(output_dir.glob("*.md"))
            self.assertEqual(len(created_files), 1)

    def test_case_e_insufficient_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "briefs"
            ctx = make_context(approval_granted=True)
            result = langchain_rag_agent.run_rag_brief(
                run_id="test-case-e",
                context=ctx,
                model=langchain_rag_agent.ScriptedRagChatModel(scenario="case_e_insufficient_evidence"),
                vector_store=self.real_vector_store,
                output_dir=output_dir,
                mode="guarded",
            )
            self.assertEqual(result.actions, ())
            self.assertFalse(result.published)
            self.assertEqual(result.verified_output, "evidencia insuficiente")
            self.assertEqual(result.untrusted_agent_output, "evidencia insuficiente")
            self.assertEqual(list(output_dir.glob("*.md")), [])

    def test_caller_context_retrieved_doc_ids_not_mutated(self) -> None:
        caller_ctx = make_context(approval_granted=True, retrieved_doc_ids=["initial-doc-only"])
        langchain_rag_agent.run_rag_brief(
            run_id="test-context-isolation",
            context=caller_ctx,
            model=langchain_rag_agent.ScriptedRagChatModel(scenario="case_a_approved_publish"),
            vector_store=self.real_vector_store,
        )
        self.assertEqual(caller_ctx.state["retrieved_doc_ids"], ["initial-doc-only"])

    # =========================================================================
    # Group 3: Modes, Exceptions & Pre-Execution Failures
    # =========================================================================

    def test_mode_advisory_allows_with_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "briefs"
            ctx = make_context(approval_granted=False)
            result = langchain_rag_agent.run_rag_brief(
                run_id="test-advisory",
                context=ctx,
                model=langchain_rag_agent.ScriptedRagChatModel(scenario="case_a_approved_publish"),
                vector_store=self.real_vector_store,
                output_dir=output_dir,
                mode="advisory",
            )
            self.assertEqual(len(result.actions), 1)
            self.assertEqual(result.actions[0].decision.decision, "allow_with_warning")
            violations = [v.rule for v in result.actions[0].decision.violations]
            self.assertEqual(violations, ["brief.approval_required"])
            self.assertTrue(result.published)
            self.assertEqual(result.state, "finished")
            self.assertEqual(len(list(output_dir.glob("*.md"))), 1)

    def test_mode_strict_aborts_on_runtime_violation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "briefs"
            ctx = make_context(approval_granted=False)
            result = langchain_rag_agent.run_rag_brief(
                run_id="test-strict-runtime",
                context=ctx,
                model=langchain_rag_agent.ScriptedRagChatModel(scenario="case_a_approved_publish"),
                vector_store=self.real_vector_store,
                output_dir=output_dir,
                mode="strict",
            )
            self.assertEqual(len(result.actions), 1)
            self.assertEqual(result.actions[0].decision.decision, "abort")
            self.assertFalse(result.published)
            self.assertEqual(result.state, "aborted")
            self.assertIsNone(result.post)
            self.assertEqual(list(output_dir.glob("*.md")), [])

    def test_mode_strict_aborts_on_pre_execution_failure(self) -> None:
        ctx = make_context(
            approval_granted=True,
            observed_agent_fingerprint="unauthorized-agent-v1",
        )
        result = langchain_rag_agent.run_rag_brief(
            run_id="test-strict-pre",
            context=ctx,
            model=langchain_rag_agent.ScriptedRagChatModel(scenario="case_a_approved_publish"),
            vector_store=self.real_vector_store,
            mode="strict",
        )
        self.assertEqual(result.state, "aborted")
        self.assertEqual(result.actions, ())
        self.assertIsNone(result.post)
        self.assertTrue(result.pre.violations)
        self.assertEqual(
            result.pre.violations[0].rule,
            "agent.configuration_fingerprint_match",
        )

    def test_tool_raising_exception_propagates_and_records_tool_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "events.jsonl"
            recorder = JsonlDecisionLog(log_path)
            ctx = make_context(approval_granted=True)

            def failing_publish(proposal: ActionProposal) -> tuple[Path, str]:
                raise RuntimeError("disk full")

            with self.assertRaises(RuntimeError) as cm:
                langchain_rag_agent.run_rag_brief(
                    run_id="test-tool-error",
                    context=ctx,
                    model=langchain_rag_agent.ScriptedRagChatModel(scenario="case_a_approved_publish"),
                    vector_store=self.real_vector_store,
                    publish_tool=failing_publish,
                    recorder=recorder,
                    mode="guarded",
                )
            self.assertIn("disk full", str(cm.exception))

            events = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
            runtime_decision = next(
                (e for e in events if e["phase"] == "runtime" and e["event_type"] == "decision"),
                None,
            )
            self.assertIsNotNone(runtime_decision)
            self.assertEqual(runtime_decision["decision"], "allow")

            runtime_error = next(
                (e for e in events if e["phase"] == "runtime" and e["event_type"] == "tool_error"),
                None,
            )
            self.assertIsNotNone(runtime_error)
            self.assertEqual(runtime_error["execution_status"], "unknown")

    # =========================================================================
    # Group 4: Observability & CLI Output
    # =========================================================================

    def test_case_d_observability_and_trace_correlation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "events.jsonl"
            output_dir = Path(tmp) / "briefs"
            recorder = JsonlDecisionLog(log_path)
            provider = TracerProvider()
            exporter = InMemorySpanExporter()
            provider.add_span_processor(SimpleSpanProcessor(exporter))
            telemetry = TelemetryObserver(provider)
            ctx = make_context(approval_granted=True)

            langchain_rag_agent.run_rag_brief(
                run_id="obs-case-d",
                context=ctx,
                model=langchain_rag_agent.ScriptedRagChatModel(scenario="case_d_replan_after_block"),
                vector_store=self.real_vector_store,
                output_dir=output_dir,
                mode="guarded",
                recorder=recorder,
                telemetry=telemetry,
                emit_console=False,
            )

            raw_log = log_path.read_text(encoding="utf-8")
            events = [json.loads(line) for line in raw_log.splitlines()]
            spans = exporter.get_finished_spans()

            # 1. action_index=1 (blocked) has decision and NO tool_completed and NO governor.tool.execute span
            action1_decision = next(
                (e for e in events if e.get("action_index") == 1 and e["event_type"] == "decision"),
                None,
            )
            self.assertIsNotNone(action1_decision)
            self.assertEqual(action1_decision["decision"], "block")

            action1_completed = next(
                (e for e in events if e.get("action_index") == 1 and e["event_type"] == "tool_completed"),
                None,
            )
            self.assertIsNone(action1_completed)

            action1_tool_spans = [
                s for s in spans
                if s.name == "governor.tool.execute" and s.attributes.get("action_index") == 1
            ]
            self.assertEqual(action1_tool_spans, [])

            # 2. action_index=2 (allowed) has decision BEFORE tool_completed, linked by (run_id, action_index)
            action2_decision_idx = next(
                idx for idx, e in enumerate(events)
                if e.get("action_index") == 2 and e["event_type"] == "decision"
            )
            action2_completed_idx = next(
                idx for idx, e in enumerate(events)
                if e.get("action_index") == 2 and e["event_type"] == "tool_completed"
            )
            self.assertLess(action2_decision_idx, action2_completed_idx)
            self.assertEqual(events[action2_decision_idx]["run_id"], "obs-case-d")
            self.assertEqual(events[action2_completed_idx]["run_id"], "obs-case-d")

            # 3. All RunEvents and finished spans share the single trace_id
            common_trace_id = events[0]["trace_id"]
            self.assertIsNotNone(common_trace_id)
            for event in events:
                self.assertEqual(event["trace_id"], common_trace_id)

            for span in spans:
                span_trace_hex = f"{span.context.trace_id:032x}"
                self.assertEqual(span_trace_hex, common_trace_id)

            # 4. Neither JSONL events nor span attributes contain corpus text or prompt text
            forbidden_snippets = [
                "INSTRUCCIÓN PRIORITARIA",
                "barrera de control estricta",
                "Genera un brief técnico a partir de las fuentes verificadas.",
            ]
            for snippet in forbidden_snippets:
                self.assertNotIn(snippet, raw_log)
                for span in spans:
                    self.assertNotIn(snippet, str(span.attributes))

    def test_subprocess_cli_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            output_dir = tmp_dir / "briefs"
            log_path = tmp_dir / "events.jsonl"
            env = os.environ.copy()
            env.pop("GOVERNOR_BENCHMARK_ROOT", None)
            env["HF_HUB_OFFLINE"] = "1"

            result = subprocess.run(
                [
                    sys.executable,
                    str(EXAMPLE),
                    "--output-dir",
                    str(output_dir),
                    "--log",
                    str(log_path),
                ],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
            self.assertEqual(result.returncode, 0, msg=f"CLI failed with stderr: {result.stderr}")

            stdout_lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            self.assertGreater(len(stdout_lines), 0)

            parsed_lines: list[dict[str, Any]] = []
            for line in stdout_lines:
                parsed_lines.append(json.loads(line))

            required_tool_keys = {
                "run_id",
                "mode",
                "action_index",
                "decision",
                "violation_rules",
                "trace_id",
                "published",
                "brief_path",
                "citation_ids",
            }

            runs_observed: dict[str, list[dict[str, Any]]] = {}
            for entry in parsed_lines:
                run_id = entry.get("run_id")
                self.assertIsNotNone(run_id)
                runs_observed.setdefault(str(run_id), []).append(entry)

                if entry.get("event") == "tool_decision":
                    self.assertTrue(required_tool_keys.issubset(entry.keys()))
                    self.assertIsNotNone(entry["trace_id"])
                    self.assertIsInstance(entry["trace_id"], str)
                    self.assertGreater(len(entry["trace_id"]), 0)

            # Every run ends with a host_verified_result line
            for run_id, entries in runs_observed.items():
                last_event = entries[-1]
                self.assertEqual(
                    last_event.get("event"),
                    "host_verified_result",
                    msg=f"Run {run_id} did not end with host_verified_result",
                )

            # Stdout does NOT contain corpus snippets or full user prompts
            forbidden_snippets = [
                "INSTRUCCIÓN PRIORITARIA",
                "barrera de control estricta",
                "Genera un brief técnico a partir de las fuentes verificadas.",
            ]
            for snippet in forbidden_snippets:
                self.assertNotIn(snippet, result.stdout)


class RagSnapshotAndPlatformSecurityTests(unittest.TestCase):
    """Test offline model snapshot manifest validation, pickle rejection, and fail-fast platform guard."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.model_dir = Path(self.temp_dir.name)
        spec = importlib.util.spec_from_file_location("prepare_rag_model", PREPARE_RAG_MODEL)
        assert spec is not None and spec.loader is not None
        self.prepare_rag_model = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.prepare_rag_model)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _create_mock_snapshot(self, files: dict[str, bytes] | None = None) -> dict[str, bytes]:
        if files is None:
            files = {
                "config.json": b'{"architectures": ["BertModel"]}',
                "tokenizer.json": b'{"version": "1.0"}',
                "vocab.txt": b"test\nvocab\n",
                "model.safetensors": b"MOCK_SAFETENSORS_WEIGHTS_DATA",
            }
        for rel_name, data in files.items():
            file_path = self.model_dir / rel_name
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_bytes(data)
        return files

    def test_prepare_and_verify_snapshot_success_and_manifest_schema(self) -> None:
        self._create_mock_snapshot()
        manifest = self.prepare_rag_model.create_snapshot_manifest(
            self.model_dir,
            model_name=langchain_rag_agent.EMBEDDING_MODEL_NAME,
            revision=langchain_rag_agent.EMBEDDING_REVISION,
        )
        self.assertEqual(manifest["manifest_version"], 1)
        self.assertEqual(manifest["model_name"], langchain_rag_agent.EMBEDDING_MODEL_NAME)
        self.assertEqual(manifest["revision"], langchain_rag_agent.EMBEDDING_REVISION)
        self.assertIn("files", manifest)
        self.assertIn("model.safetensors", manifest["files"])

        verified = langchain_rag_agent.verify_prepared_embedding_snapshot(
            self.model_dir,
            expected_model=langchain_rag_agent.EMBEDDING_MODEL_NAME,
            expected_revision=langchain_rag_agent.EMBEDDING_REVISION,
        )
        self.assertEqual(verified["model_name"], langchain_rag_agent.EMBEDDING_MODEL_NAME)

    def test_snapshot_missing_or_without_manifest_rejected(self) -> None:
        non_existent = self.model_dir / "non_existent_subdir"
        with self.assertRaises(FileNotFoundError):
            langchain_rag_agent.verify_prepared_embedding_snapshot(
                non_existent,
                expected_model=langchain_rag_agent.EMBEDDING_MODEL_NAME,
                expected_revision=langchain_rag_agent.EMBEDDING_REVISION,
            )

        self._create_mock_snapshot()
        with self.assertRaisesRegex(ValueError, "Snapshot manifest missing"):
            langchain_rag_agent.verify_prepared_embedding_snapshot(
                self.model_dir,
                expected_model=langchain_rag_agent.EMBEDDING_MODEL_NAME,
                expected_revision=langchain_rag_agent.EMBEDDING_REVISION,
            )

        self.prepare_rag_model.create_snapshot_manifest(
            self.model_dir,
            model_name="wrong/model-name",
            revision=langchain_rag_agent.EMBEDDING_REVISION,
        )
        with self.assertRaisesRegex(ValueError, "Snapshot model_name mismatch"):
            langchain_rag_agent.verify_prepared_embedding_snapshot(
                self.model_dir,
                expected_model=langchain_rag_agent.EMBEDDING_MODEL_NAME,
                expected_revision=langchain_rag_agent.EMBEDDING_REVISION,
            )

        self.prepare_rag_model.create_snapshot_manifest(
            self.model_dir,
            model_name=langchain_rag_agent.EMBEDDING_MODEL_NAME,
            revision="wrong-revision",
        )
        with self.assertRaisesRegex(ValueError, "Snapshot revision mismatch"):
            langchain_rag_agent.verify_prepared_embedding_snapshot(
                self.model_dir,
                expected_model=langchain_rag_agent.EMBEDDING_MODEL_NAME,
                expected_revision=langchain_rag_agent.EMBEDDING_REVISION,
            )

    def test_snapshot_byte_alteration_and_unlisted_extra_file_rejected(self) -> None:
        self._create_mock_snapshot()
        self.prepare_rag_model.create_snapshot_manifest(
            self.model_dir,
            model_name=langchain_rag_agent.EMBEDDING_MODEL_NAME,
            revision=langchain_rag_agent.EMBEDDING_REVISION,
        )

        safetensors_file = self.model_dir / "model.safetensors"
        safetensors_file.write_bytes(b"MOCK_SAFETENSORS_WEIGHTS_DATX")
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            langchain_rag_agent.verify_prepared_embedding_snapshot(
                self.model_dir,
                expected_model=langchain_rag_agent.EMBEDDING_MODEL_NAME,
                expected_revision=langchain_rag_agent.EMBEDDING_REVISION,
            )

        safetensors_file.write_bytes(b"TAMPERED_SHORT")
        with self.assertRaisesRegex(ValueError, "File size mismatch"):
            langchain_rag_agent.verify_prepared_embedding_snapshot(
                self.model_dir,
                expected_model=langchain_rag_agent.EMBEDDING_MODEL_NAME,
                expected_revision=langchain_rag_agent.EMBEDDING_REVISION,
            )

        safetensors_file.write_bytes(b"MOCK_SAFETENSORS_WEIGHTS_DATA")
        (self.model_dir / "unlisted.json").write_text('{"extra": true}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Unlisted file found in model directory"):
            langchain_rag_agent.verify_prepared_embedding_snapshot(
                self.model_dir,
                expected_model=langchain_rag_agent.EMBEDDING_MODEL_NAME,
                expected_revision=langchain_rag_agent.EMBEDDING_REVISION,
            )

    def test_snapshot_pickle_weights_or_missing_safetensors_rejected(self) -> None:
        self._create_mock_snapshot()
        pickle_file = self.model_dir / "pytorch_model.bin"
        pickle_file.write_bytes(b"FAKE_PICKLE_WEIGHTS")
        with self.assertRaisesRegex(ValueError, "Forbidden weight format"):
            self.prepare_rag_model.create_snapshot_manifest(
                self.model_dir,
                model_name=langchain_rag_agent.EMBEDDING_MODEL_NAME,
                revision=langchain_rag_agent.EMBEDDING_REVISION,
            )

        pickle_file.unlink()
        pt_file = self.model_dir / "model.pt"
        pt_file.write_bytes(b"FAKE_PT_WEIGHTS")
        with self.assertRaisesRegex(ValueError, "Forbidden weight format"):
            self.prepare_rag_model.create_snapshot_manifest(
                self.model_dir,
                model_name=langchain_rag_agent.EMBEDDING_MODEL_NAME,
                revision=langchain_rag_agent.EMBEDDING_REVISION,
            )

        pt_file.unlink()
        (self.model_dir / "model.safetensors").unlink()
        with self.assertRaisesRegex(ValueError, "Model snapshot must contain at least one .safetensors file"):
            self.prepare_rag_model.create_snapshot_manifest(
                self.model_dir,
                model_name=langchain_rag_agent.EMBEDDING_MODEL_NAME,
                revision=langchain_rag_agent.EMBEDDING_REVISION,
            )

    def test_default_local_embeddings_enforces_offline_cpu_and_nested_safetensors_kwargs(self) -> None:
        self._create_mock_snapshot()
        self.prepare_rag_model.create_snapshot_manifest(
            self.model_dir,
            model_name=langchain_rag_agent.EMBEDDING_MODEL_NAME,
            revision=langchain_rag_agent.EMBEDDING_REVISION,
        )

        mock_embeddings_cls = MagicMock()
        with patch.object(langchain_rag_agent, "check_rag_platform", return_value=None):
            with patch.dict("sys.modules", {"langchain_huggingface": MagicMock(HuggingFaceEmbeddings=mock_embeddings_cls)}):
                langchain_rag_agent.default_local_embeddings(model_dir=self.model_dir)

        self.assertEqual(os.environ.get("HF_HUB_OFFLINE"), "1")
        self.assertEqual(os.environ.get("TRANSFORMERS_OFFLINE"), "1")
        mock_embeddings_cls.assert_called_once_with(
            model_name=str(self.model_dir.resolve()),
            model_kwargs={
                "device": "cpu",
                "local_files_only": True,
                "trust_remote_code": False,
                "revision": langchain_rag_agent.EMBEDDING_REVISION,
                "model_kwargs": {
                    "use_safetensors": True,
                    "local_files_only": True,
                    "trust_remote_code": False,
                },
            },
        )

    def test_check_rag_platform_and_cli_fail_fast_on_macos_intel(self) -> None:
        if sys.platform == "darwin" and platform.machine() in ("x86_64", "AMD64"):
            with self.assertRaises(RuntimeError) as cm:
                langchain_rag_agent.check_rag_platform()
            self.assertIn("Native RAG execution is not supported on macOS Intel", str(cm.exception))
        else:
            with patch("sys.platform", "darwin"), patch("platform.machine", return_value="x86_64"):
                with self.assertRaises(RuntimeError) as cm:
                    langchain_rag_agent.check_rag_platform()
                self.assertIn("Native RAG execution is not supported on macOS Intel", str(cm.exception))

        if sys.platform == "darwin" and platform.machine() in ("x86_64", "AMD64"):
            for script_path in (EXAMPLE, PRE_EXAMPLE):
                res = subprocess.run(
                    [sys.executable, str(script_path)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(res.returncode, 2, msg=f"{script_path} did not exit with code 2: {res.stderr}")
                self.assertIn("Native RAG execution is not supported on macOS Intel", res.stderr)
                self.assertIn("scripts/run_rag.sh --container", res.stderr)

                v_res = subprocess.run(
                    [sys.executable, "-v", str(script_path)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(v_res.returncode, 2)
                import_log = v_res.stderr.lower()
                self.assertNotIn("import 'torch'", import_log)
                self.assertNotIn("import 'transformers'", import_log)
                self.assertNotIn("import 'sentence_transformers'", import_log)

    def test_run_rag_sh_rejects_native_macos_intel_with_container_instructions(self) -> None:
        if sys.platform == "darwin" and platform.machine() in ("x86_64", "AMD64"):
            for cmd in ("test", "governed", "pre"):
                res = subprocess.run(
                    ["bash", str(RUN_RAG_SH), cmd],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(res.returncode, 2, msg=f"run_rag.sh {cmd} did not exit 2: {res.stderr}")
                self.assertIn("Native RAG execution is not supported on macOS Intel", res.stderr)
                self.assertIn("scripts/run_rag.sh --container", res.stderr)


if __name__ == "__main__":
    unittest.main()
