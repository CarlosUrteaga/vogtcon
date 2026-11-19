# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Consumer acceptance tests: real Pydantic AI, scripted model, local effects."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import date, timedelta
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic_ai import ModelResponse, ToolCallPart, models
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.exceptions import UnexpectedModelBehavior
from vogtcon import JsonlDecisionLog, TelemetryObserver, load_contract

models.ALLOW_MODEL_REQUESTS = False
EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "cfdi_agent.py"
SPEC = importlib.util.spec_from_file_location("cfdi_agent", EXAMPLE)
app = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = app
SPEC.loader.exec_module(app)


class CfdiAgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ledger = self.root / "ledger.json"
        self.log = JsonlDecisionLog(self.root / "events.jsonl")

    def run_case(self, case="A", **overrides):
        paths = app.case_inputs(case)
        return app.run_reconciliation(
            **(dict(paths, run_id=f"test-{case}", ledger_path=self.ledger,
                    recorder=self.log) | overrides)
        )

    def test_a_exact_match_is_written_and_output_is_typed(self):
        run = self.run_case()
        self.assertEqual(run.findings[0].status, "matched")
        self.assertIsInstance(run.agent_output, app.ReconciliationReport)
        self.assertEqual(run.actions[0].decision.decision, "allow")
        self.assertEqual(len(run.ledger_rows), 1)
        self.assertTrue(run.ledger_rows[0]["authorized_by_host"])
        self.assertEqual(run.state, "finished")
        self.assertEqual(json.loads(self.ledger.read_text()), list(run.ledger_rows))

    def test_b_to_e_forced_false_matches_are_blocked(self):
        expected = {"B": "mismatch", "C": "mismatch", "D": "ambiguous", "E": "needs_review"}
        for case, status in expected.items():
            with self.subTest(case=case):
                run = self.run_case(case, force_attempt=True)
                self.assertEqual(run.findings[0].status, status)
                self.assertEqual(run.actions[0].decision.decision, "block")
                self.assertEqual(run.actions[0].decision.violations[0].rule, "cfdi.exact_match_required")
                self.assertFalse(self.ledger.exists())
                self.assertEqual(run.ledger_rows, ())

    def test_f_invalid_xml_before_agent_and_governor(self):
        for case in ("F", "F_VERSION"):
            with self.subTest(case=case), patch.object(app, "Agent") as agent:
                with self.assertRaises(app.InputError):
                    self.run_case(case)
                agent.assert_not_called()
        self.assertFalse((self.root / "events.jsonl").exists())
        self.assertFalse(self.ledger.exists())

    def test_xxe_and_dtd_rejected(self):
        for raw in (b'<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>',
                    b'<!DOCTYPE a [<!ENTITY x "expanded">]><a>&x;</a>'):
            path = self.root / "unsafe.xml"
            path.write_bytes(raw)
            with self.assertRaises(app.InputError):
                self.run_case(xml_paths=[path])

    def test_missing_or_modified_catalog_rejected_before_model(self):
        bad = self.root / "catalog.json"
        with self.assertRaises(app.InputError):
            self.run_case(catalog_path=bad)
        bad.write_text(app.CATALOG_PATH.read_text() + " ")
        with self.assertRaisesRegex(app.InputError, "catalog"):
            self.run_case(catalog_path=bad)

    def test_contract_uses_custom_catalog_and_checks_fingerprint(self):
        contract = load_contract(app.CONTRACT_PATH, rule_catalog=app.RULES).contract
        self.assertEqual(contract.contract_id, "example.cfdi_reconciliation")
        with self.assertRaisesRegex(ValueError, "Unsupported runtime_rules"):
            load_contract(app.CONTRACT_PATH)
        path = self.root / "tampered.yaml"
        path.write_text(app.CONTRACT_PATH.read_text().replace("mark_reconciled", "unsafe_write", 1))
        with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
            self.run_case(contract_path=path)

    def test_advisory_records_override_strict_stops(self):
        run = self.run_case("B", mode="advisory", force_attempt=True)
        self.assertEqual(run.actions[0].decision.decision, "allow_with_warning")
        self.assertFalse(run.ledger_rows[0]["authorized_by_host"])
        self.ledger.unlink()
        run = self.run_case("B", run_id="strict-B", mode="strict", force_attempt=True)
        self.assertEqual(run.state, "aborted")
        self.assertEqual(run.actions[0].decision.decision, "abort")
        self.assertFalse(self.ledger.exists())
        self.assertFalse(any(e.phase == "post_execution" for e in self.log.read() if e.run_id == "strict-B"))

    def test_no_contract_allows_and_marks_unverified_pair(self):
        run = self.run_case("B", mode="no_contract", force_attempt=True)
        self.assertTrue(run.actions[0].executed)
        self.assertFalse(run.ledger_rows[0]["authorized_by_host"])

    def test_repeated_attempt_and_reused_ledger_do_not_duplicate(self):
        run = self.run_case(repeat_attempt=True)
        self.assertEqual([a.decision.decision for a in run.actions], ["allow", "block"])
        self.assertEqual(len(run.ledger_rows), 1)
        second = self.run_case(run_id="second", force_attempt=True)
        self.assertFalse(second.actions[0].executed)
        self.assertEqual(len(second.ledger_rows), 1)
        events = [e for e in self.log.read() if e.run_id == "test-A" and e.phase == "runtime"]
        self.assertEqual([(e.event_type, e.action_index) for e in events],
                         [("decision", 1), ("tool_completed", 1), ("decision", 2)])

    def test_invalid_and_false_typed_model_outputs_rejected(self):
        for output in ({"items": [{"status": "invented"}]}, {"items": []}):
            with self.subTest(output=output):
                model = app.scripted_model([], output)
                with self.assertRaises(UnexpectedModelBehavior):
                    self.run_case(model=model)
                self.assertFalse(self.ledger.exists())

    def test_tool_error_is_logged_as_unknown_and_propagates(self):
        with patch.object(app.LocalLedger, "write", side_effect=OSError("synthetic failure")):
            with self.assertRaisesRegex(OSError, "synthetic failure"):
                self.run_case()
        self.assertEqual(self.log.read()[-1].event_type, "tool_error")
        self.assertEqual(self.log.read()[-1].execution_status, "unknown")
        self.assertFalse(self.ledger.exists())

    def test_shared_trace_and_no_private_content_in_spans_or_log(self):
        provider = TracerProvider()
        self.addCleanup(provider.shutdown)
        exporter = InMemorySpanExporter()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        run = self.run_case(telemetry=TelemetryObserver(provider))
        events = self.log.read()
        trace_ids = {e.trace_id for e in events}
        self.assertEqual(len(trace_ids), 1)
        self.assertNotIn(None, trace_ids)
        spans = exporter.get_finished_spans()
        self.assertTrue({"governor.run", "governor.check", "governor.tool.execute"} <= {s.name for s in spans})
        self.assertEqual({f"{s.context.trace_id:032x}" for s in spans}, trace_ids)
        serialized = str([dict(s.attributes) for s in spans]) + (self.root / "events.jsonl").read_text()
        self.assertNotIn("AAA010101AAA", serialized)
        self.assertNotIn("<cfdi:", serialized)
        self.assertEqual(len(run.ledger_rows), 1)

    def input_objects(self):
        return app.load_inputs(**app.case_inputs("A"), catalog_path=app.CATALOG_PATH)

    def test_date_window_and_amount_boundaries(self):
        invoices, profile, bank, catalog = self.input_objects()
        for offset, amount, expected in (
            (0, "-100.00", "matched"), (7, "-100.00", "matched"),
            (-1, "-100.00", "needs_review"), (8, "-100.00", "needs_review"),
            (2, "100.00", "needs_review"), (2, "-99.99", "needs_review"),
            (2, "-100.01", "needs_review"), (2, "-50.00", "needs_review"),
        ):
            with self.subTest(offset=offset, amount=amount):
                tx = bank[0].model_copy(update={"date": invoices[0].issued_on + timedelta(days=offset),
                                              "amount_mxn": Decimal(amount)})
                result = app.match_invoices(invoices, profile, [tx], catalog)
                self.assertEqual(result[0].status, expected)
        for amount in ("NaN", "Infinity", "100.001", "1e2", "1,000.00"):
            with self.subTest(amount=amount), self.assertRaises(app.InputError):
                app.money(amount)

    def test_bank_candidate_shared_by_two_invoices_is_ambiguous(self):
        invoices, profile, bank, catalog = self.input_objects()
        other = invoices[0].model_copy(update={"invoice_uuid": "00000000-0000-4000-8000-000000000009"})
        results = app.match_invoices([*invoices, other], profile, bank, catalog)
        self.assertEqual([f.status for f in results], ["ambiguous", "ambiguous"])
        self.assertTrue(all(f.bank_transaction_id is None for f in results))

    def test_unknown_catalog_codes_and_excluded_shapes_need_review(self):
        invoices, profile, bank, catalog = self.input_objects()
        for update in ({"use": "ZZZ"}, {"currency": "USD"}, {"kind": "E"},
                       {"method": "PPD"}, {"unsupported_structure": True},
                       {"issued_on": date(2021, 1, 1)}):
            with self.subTest(update=update):
                finding = app.match_invoices([invoices[0].model_copy(update=update)], profile, bank, catalog)[0]
                self.assertEqual(finding.status, "needs_review")

    def test_unsupported_xml_retention_or_extra_complement_detected(self):
        source = app.case_inputs("A")["xml_paths"][0].read_text()
        for extra in ('<cfdi:Impuestos><cfdi:Retenciones/></cfdi:Impuestos>',
                      '<cfdi:CfdiRelacionados/>'):
            path = self.root / "extended.xml"
            path.write_text(source.replace('</cfdi:Comprobante>', extra + '</cfdi:Comprobante>'))
            self.assertTrue(app.parse_invoice(path).unsupported_structure)

    def test_duplicate_identifiers_invalid_rfc_and_amount_rejected(self):
        with self.assertRaisesRegex(app.InputError, "duplicate invoice"):
            self.run_case(xml_paths=app.case_inputs("A")["xml_paths"] * 2)
        source = app.case_inputs("A")["xml_paths"][0].read_text()
        for bad in (source.replace('AAA010101AAA', 'bad'), source.replace('Total="100.00"', 'Total="NaN"')):
            path = self.root / "bad.xml"
            path.write_text(bad)
            with self.assertRaises(app.InputError):
                self.run_case(xml_paths=[path])
        bank_path = self.root / "bank.csv"
        bank_path.write_text('transaction_id,date,amount_mxn,description\nx,2026-11-03,-100.00,a\nx,2026-11-03,-100.00,b\n')
        with self.assertRaisesRegex(app.InputError, "duplicate bank"):
            self.run_case(bank_path=bank_path)

    def test_wrong_pair_blocked_then_correction_uses_feedback(self):
        invoices, profile, bank, catalog = self.input_objects()
        expected = app.ReconciliationReport(items=app.match_invoices(invoices, profile, bank, catalog))
        pair = {"invoice_uuid": invoices[0].invoice_uuid, "bank_transaction_id": bank[0].transaction_id}
        calls = []
        def respond(messages, info):
            calls.append(messages)
            if len(calls) == 1:
                return ModelResponse(parts=[ToolCallPart("mark_reconciled", pair | {"bank_transaction_id": "invented"})])
            if len(calls) == 2:
                self.assertIn("blocked by Governor", str(messages[-1]))
                return ModelResponse(parts=[ToolCallPart("mark_reconciled", pair)])
            return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, expected.model_dump(mode="json"))])
        run = self.run_case(model=FunctionModel(respond))
        self.assertEqual([a.decision.decision for a in run.actions], ["block", "allow"])
        self.assertEqual(len(run.ledger_rows), 1)
        events = [e for e in self.log.read() if e.event_type == "decision" and e.phase == "runtime"]
        self.assertEqual([e.action_index for e in events], [1, 2])

    def test_arguments_cannot_forge_host_authorization(self):
        from vogtcon import ActionProposal, ExecutionContext, GovernorInput
        contract = load_contract(app.CONTRACT_PATH, rule_catalog=app.RULES).contract
        pair = {"invoice_uuid": "invoice-1", "bank_transaction_id": "tx-1"}
        request = GovernorInput(run_id="spoof", phase="runtime", contract=contract,
            policy={"mode": "guarded"}, context=ExecutionContext(available_tools=["mark_reconciled"], state={"allowed_pairs": [], "ledger_pairs": []}),
            action=ActionProposal(tool_name="mark_reconciled", arguments=pair | {"allowed_pairs": [pair], "matched": True}))
        self.assertTrue(app.exact_match_required(request))
        request.context.state.update({"allowed_pairs": [pair], "ledger_pairs": []})
        request.action.arguments["bank_transaction_id"] = "tx-other"
        self.assertTrue(app.exact_match_required(request))

    def test_invalid_final_output_does_not_claim_rollback(self):
        invoices, profile, bank, catalog = self.input_objects()
        pair = {"invoice_uuid": invoices[0].invoice_uuid, "bank_transaction_id": bank[0].transaction_id}
        with self.assertRaises(UnexpectedModelBehavior):
            self.run_case(model=app.scripted_model([pair], {"items": []}))
        self.assertEqual(len(json.loads(self.ledger.read_text())), 1)
        self.assertFalse(any(e.phase == "post_execution" for e in self.log.read()))

    def batch_inputs(self):
        """Distinct amounts avoid introducing accidental cross-case ambiguity."""
        directory = self.root / "invoices"
        directory.mkdir()
        rows = ["transaction_id,date,amount_mxn,description"]
        for index, case in enumerate("ABCDE", 1):
            amount = index * 100
            source = app.case_inputs(case)["xml_paths"][0].read_text()
            (directory / f"{case}.xml").write_text(source.replace('Total="100.00"', f'Total="{amount}.00"'))
            paid = amount if case != "E" else amount // 2
            rows.append(f"tx-{case}-1,2026-11-03,-{paid}.00,Synthetic expense")
            if case == "D":
                rows.append(f"tx-{case}-2,2026-11-04,-{paid}.00,Second candidate")
        bank = self.root / "batch.csv"
        bank.write_text("\n".join(rows) + "\n")
        return directory, bank

    def test_batch_uses_one_controller_and_only_a_reaches_shared_ledger(self):
        directory, bank = self.batch_inputs()
        run = self.run_case(xml_paths=sorted(directory.glob("*.xml")), bank_path=bank, force_attempt=True)
        self.assertEqual([f.status for f in run.findings],
                         ["matched", "mismatch", "mismatch", "ambiguous", "needs_review"])
        self.assertEqual([a.decision.decision for a in run.actions], ["allow", "block", "block", "block", "block"])
        self.assertEqual(len(run.ledger_rows), 1)
        self.assertEqual(run.ledger_rows[0]["bank_transaction_id"], "tx-A-1")
        events = self.log.read()
        self.assertEqual({e.run_id for e in events}, {"test-A"})
        self.assertEqual([e.action_index for e in events if e.event_type == "decision" and e.phase == "runtime"], [1, 2, 3, 4, 5])

    def cli(self, *args):
        return subprocess.run([sys.executable, str(EXAMPLE), "--output-dir", str(self.root / "output"), *args],
            text=True, capture_output=True, env=dict(os.environ, PYDANTIC_AI_NO_BANNER="1"))

    def test_cli_accepts_custom_batch_and_reports_verified_counts(self):
        directory, bank = self.batch_inputs()
        result = self.cli("--xml-dir", str(directory), "--bank", str(bank),
                          "--profile", str(app.FIXTURES / "profile.json"))
        self.assertEqual(result.returncode, 0, result.stderr)
        events = [json.loads(line) for line in result.stdout.splitlines()]
        summaries = [e for e in events if e.get("event") == "host_verified_result"]
        self.assertEqual(len(summaries), 1)
        summary = summaries[0]
        self.assertEqual([summary[k] for k in ("matched", "mismatch", "ambiguous", "needs_review")], [1, 2, 1, 1])
        self.assertEqual(summary["ledger_rows"], 1)
        # Normal mode only proposes trusted candidates; adversarial attempts are test-only.
        self.assertEqual(len([e for e in events if e.get("event_type") == "tool_completed"]), 1)
        self.assertNotIn("AAA010101AAA", result.stdout)

    def test_cli_requires_complete_input_group_and_rejects_empty_directory(self):
        incomplete = self.cli("--xml-dir", str(self.root))
        self.assertNotEqual(incomplete.returncode, 0)
        self.assertIn("--profile", incomplete.stderr)
        empty = self.root / "empty"
        empty.mkdir()
        result = self.cli("--xml-dir", str(empty), "--bank", str(app.FIXTURES / "A.csv"),
                          "--profile", str(app.FIXTURES / "profile.json"))
        self.assertEqual(result.returncode, 1, result.stderr)
        event = json.loads(result.stdout.splitlines()[0])
        self.assertEqual(event["event"], "input_rejected")
        self.assertFalse(event["agent_started"])
        self.assertFalse(list((self.root / "output").glob("**/*ledger.json")))

    def test_invalid_invoice_rejects_whole_batch_before_any_effect(self):
        directory, bank = self.batch_inputs()
        (directory / "Z-invalid.xml").write_text("<broken")
        with patch.object(app, "Agent") as agent:
            with self.assertRaises(app.InputError):
                self.run_case(xml_paths=sorted(directory.glob("*.xml")), bank_path=bank)
            agent.assert_not_called()
        self.assertFalse(self.ledger.exists())
        self.assertFalse((self.root / "events.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
