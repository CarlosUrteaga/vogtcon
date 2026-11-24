# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Identity and deterministic contract runs for the notification comparison."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from importlib.metadata import version
from pathlib import Path
from unittest.mock import patch

import yaml

from vogtcon import load_contract
from vogtcon.models import ContractRulesV2


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATHS = {
    "A": Path("pilots/contracts/notification_without_approval_v2.yaml"),
    "B": Path("examples/notification_contract_v2.yaml"),
}
FINGERPRINTS = {
    "A": "sha256:ec00757eba141427b274f01800c9179c15f6e261f763b4d553027068f7d24667",
    "B": "sha256:ad61db75c5b4ba43868b51cf287180e7b79adf846a012611178ff6382c692cff",
}
MANIFEST_PATH = ROOT / "pilots/contracts/notification_contract_ab_manifest.json"


class NotificationContractIdentityTests(unittest.TestCase):
    def test_both_variants_load_as_v2_with_original_values_preserved(self):
        for variant, relative_path in CONTRACT_PATHS.items():
            with self.subTest(variant=variant):
                path = ROOT / relative_path
                original = yaml.safe_load(path.read_text(encoding="utf-8"))
                document = load_contract(path)
                self.assertIsInstance(document.contract, ContractRulesV2)
                self.assertEqual(document.original, original)
                self.assertEqual(document.contract.contract_id, "example.notification")
                self.assertNotIn("metadata", document.original)

    def test_variants_differ_only_by_approval_rule_and_fingerprint(self):
        baseline = load_contract(ROOT / CONTRACT_PATHS["B"]).original
        without_approval = load_contract(ROOT / CONTRACT_PATHS["A"]).original
        self.assertEqual(
            baseline["runtime_rules"],
            ["tool.declared_only", "sensitive_requires_approval"],
        )
        self.assertEqual(without_approval["runtime_rules"], ["tool.declared_only"])
        baseline.pop("contract_fingerprint")
        without_approval.pop("contract_fingerprint")
        baseline["runtime_rules"].remove("sensitive_requires_approval")
        self.assertEqual(without_approval, baseline)

    def test_fingerprints_match_sdd_and_canonical_original_payload(self):
        for variant, relative_path in CONTRACT_PATHS.items():
            with self.subTest(variant=variant):
                original = yaml.safe_load(
                    (ROOT / relative_path).read_text(encoding="utf-8")
                )
                declared = original.pop("contract_fingerprint")
                canonical = json.dumps(original, sort_keys=True, separators=(",", ":"))
                recomputed = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                self.assertEqual(declared, FINGERPRINTS[variant])
                self.assertEqual(declared, recomputed)

    def test_static_manifest_binds_each_variant_to_actual_contract_bytes(self):
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["pilot_id"], "notification-contract-ab")
        self.assertEqual(manifest["pilot_revision"], 1)
        self.assertEqual(manifest["policy"], {"mode": "guarded"})
        self.assertEqual(set(manifest["variants"]), set(CONTRACT_PATHS))
        for variant, relative_path in CONTRACT_PATHS.items():
            with self.subTest(variant=variant):
                identity = manifest["variants"][variant]
                self.assertEqual(identity["contract_path"], relative_path.as_posix())
                path = ROOT / identity["contract_path"]
                contract = load_contract(path).contract
                self.assertEqual(identity["schema_version"], contract.schema_version)
                self.assertEqual(identity["contract_id"], contract.contract_id)
                self.assertEqual(identity["contract_fingerprint"], contract.contract_fingerprint)
                self.assertEqual(identity["file_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_removing_approval_rule_with_old_fingerprint_is_rejected(self):
        original = load_contract(ROOT / CONTRACT_PATHS["B"]).original
        original["runtime_rules"].remove("sensitive_requires_approval")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tampered.json"
            path.write_text(json.dumps(original), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Contract fingerprint mismatch"):
                load_contract(path)

    def test_other_payload_change_with_old_fingerprint_is_rejected(self):
        for variant, relative_path in CONTRACT_PATHS.items():
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                original = load_contract(ROOT / relative_path).original
                original["response_schema"]["required_fields"].append("receipt")
                path = Path(directory) / "tampered.json"
                path.write_text(json.dumps(original), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "Contract fingerprint mismatch"):
                    load_contract(path)


def pilot_module():
    module_name = "notification_contract_ab_test_pilot"
    if module_name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            module_name, ROOT / "pilots/notification_contract_ab.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            del sys.modules[module_name]
            raise
    return sys.modules[module_name]


class NotificationContractCaseTests(unittest.TestCase):
    def test_real_case_matrix_observes_each_attempt_and_destination(self):
        pilot = pilot_module()
        cases = {
            "C1": ("A", ["allow"], [False], [("Aviso piloto",)], 0),
            "C2": ("B", ["block", "block"], [False, False], [(), ()], 0),
            "C3": ("B", ["block", "allow"], [False, True], [(), ("Aviso piloto",)], 1),
            "C4": ("A", ["allow"], [False], [("Aviso piloto",)], 0),
            "C5": ("B", ["allow"], [True], [("Aviso piloto",)], 0),
            "C6": ("B", ["allow"], [False], [("Aviso piloto",)], 0),
        }
        for case_id, (variant, decisions, approvals, destinations, grants) in cases.items():
            with self.subTest(case_id=case_id):
                result = pilot.run_case(case_id, run_id=f"matrix-{case_id}")
                self.assertEqual(result.variant, variant)
                self.assertEqual(result.contract_fingerprint, FINGERPRINTS[variant])
                self.assertEqual([a.decision for a in result.attempts], decisions)
                self.assertEqual([a.executed for a in result.attempts], [d == "allow" for d in decisions])
                self.assertEqual([a.context.state["approval_granted"] for a in result.attempts], approvals)
                self.assertEqual([a.sent_after for a in result.attempts], destinations)
                self.assertEqual([a.action_index for a in result.attempts], list(range(1, len(decisions) + 1)))
                self.assertEqual(result.destination, destinations[-1])
                self.assertEqual(result.approval_grants, grants)
                self.assertEqual(result.callback_calls, int(len(decisions) == 2))
                self.assertEqual(result.run.state, "finished")
                self.assertEqual(result.run.pre.violations, [])
                self.assertEqual(result.run.post.violations, [])
                self.assertTrue(all(event.run_id == result.run_id for event in result.events))
                self.assertTrue(all(event.mode == "guarded" for event in result.events))
                completed = [event for event in result.events if event.event_type == "tool_completed"]
                self.assertEqual(len(completed), int(decisions[-1] == "allow"))
                if completed:
                    self.assertEqual(completed[0].action_index, len(decisions))
                    self.assertEqual(result.invoked_proposals, (result.attempts[-1].proposal,))
                else:
                    self.assertEqual(result.invoked_proposals, ())
                for attempt in result.attempts:
                    self.assertEqual(attempt.proposal.tool_name, "send_notification")
                    self.assertEqual(attempt.proposal.arguments["message"], "Aviso piloto")
                    self.assertIs(attempt.proposal.arguments["sensitive"], case_id != "C6")
                    self.assertEqual(attempt.context.observed_contract_fingerprint, result.contract_fingerprint)
                    self.assertEqual(attempt.context.observed_agent_fingerprint, "notification-agent-v1")

    def test_agent_claim_is_observed_on_both_attempts_without_host_authority(self):
        result = pilot_module().run_case("C2", agent_approval_claim=True)
        self.assertEqual([a.decision for a in result.attempts], ["block", "block"])
        self.assertEqual([a.proposal.arguments["approval_granted"] for a in result.attempts], [True, True])
        self.assertEqual([a.context.state["approval_granted"] for a in result.attempts], [False, False])
        self.assertEqual(result.destination, ())
        self.assertEqual(result.approval_grants, 0)

    def test_c3_captures_identical_real_proposals_and_independent_context_snapshots(self):
        result = pilot_module().run_case("C3")
        first, second = result.attempts
        self.assertEqual(first.proposal, second.proposal)
        self.assertIsNot(first.proposal, second.proposal)
        self.assertIsNot(first.context, second.context)
        second.context.state["approval_granted"] = False
        second.proposal.arguments["message"] = "mutated observation"
        self.assertFalse(first.context.state["approval_granted"])
        self.assertEqual(first.proposal.arguments["message"], "Aviso piloto")
        self.assertEqual(result.invoked_proposals[0].arguments["message"], "Aviso piloto")
        self.assertEqual(first.sent_after, ())
        self.assertEqual(result.destination, ("Aviso piloto",))

    def test_repeated_runs_have_fresh_ids_destinations_and_observations(self):
        pilot = pilot_module()
        first = pilot.run_case("C3")
        second = pilot.run_case("C2")
        third = pilot.run_case("C3")
        self.assertEqual(len({first.run_id, second.run_id, third.run_id}), 3)
        self.assertEqual(first.destination, ("Aviso piloto",))
        self.assertEqual(second.destination, ())
        self.assertEqual(third.destination, ("Aviso piloto",))
        first.attempts[-1].proposal.arguments["message"] = "changed"
        self.assertEqual(third.attempts[-1].proposal.arguments["message"], "Aviso piloto")

    def test_loader_and_runner_do_not_depend_on_working_directory(self):
        pilot_module()
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(ROOT), str(ROOT / "src")]))
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, "-c", "from pilots.notification_contract_ab import run_case; assert run_case('C3').destination == ('Aviso piloto',)"],
                cwd=directory, env=env, capture_output=True, text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_case_and_run_id_rejected_before_example_starts(self):
        pilot = pilot_module()
        with patch.object(pilot, "run_notification") as execute:
            for args in (("unknown", {}), ("C1", {"run_id": ""})):
                with self.subTest(args=args), self.assertRaises(ValueError):
                    pilot.run_case(args[0], **args[1])
            execute.assert_not_called()

    def test_tampered_manifest_and_extra_contract_change_rejected_before_run(self):
        pilot = pilot_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative_path in CONTRACT_PATHS.values():
                (root / relative_path).parent.mkdir(parents=True, exist_ok=True)
                (root / relative_path).write_bytes((ROOT / relative_path).read_bytes())
            manifest_path = root / MANIFEST_PATH.relative_to(ROOT)
            original_manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
            for field, value in (("file_sha256", "0" * 64), ("contract_id", "wrong-id"), ("contract_path", "../outside.yaml")):
                with self.subTest(field=field):
                    manifest = json.loads(json.dumps(original_manifest))
                    manifest["variants"]["A"][field] = value
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        pilot.load_contract_variants(root=root)
            manifest = json.loads(json.dumps(original_manifest))
            a_path = root / CONTRACT_PATHS["A"]
            data = yaml.safe_load(a_path.read_text(encoding="utf-8"))
            data["response_schema"]["required_fields"].append("receipt")
            data.pop("contract_fingerprint")
            canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
            data["contract_fingerprint"] = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
            a_path.write_text(yaml.safe_dump(data), encoding="utf-8")
            manifest["variants"]["A"]["contract_fingerprint"] = data["contract_fingerprint"]
            manifest["variants"]["A"]["file_sha256"] = hashlib.sha256(a_path.read_bytes()).hexdigest()
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "single|only|differ"):
                pilot.load_contract_variants(root=root)

    def test_example_uses_injected_agent_for_first_proposal(self):
        pilot = pilot_module()

        class DistinctiveAgent(pilot.NotificationAgent):
            def __init__(self):
                self.calls = 0

            def propose(self, message, *, sensitive):
                self.calls += 1
                return super().propose("injected message", sensitive=sensitive)

        contract = load_contract(ROOT / CONTRACT_PATHS["A"]).contract
        agent = DistinctiveAgent()
        tool = pilot.InMemoryNotificationTool()
        result = pilot.run_notification(
            run_id="injected-agent", context=pilot.ExecutionContext(
                state={"approval_granted": False}, available_tools=["send_notification"],
                observed_agent_fingerprint="notification-agent-v1",
                observed_contract_fingerprint=contract.contract_fingerprint,
            ), message="ignored", sensitive=True, tool=tool, contract=contract,
            policy=pilot.EnforcementPolicy(mode="guarded"), agent=agent,
        )
        self.assertEqual(agent.calls, 1)
        self.assertEqual(tool.sent, ["injected message"])
        self.assertTrue(result.runtime.executed)


class NotificationContractEvidenceTests(unittest.TestCase):
    @staticmethod
    def read_jsonl(path):
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    def test_manifest_and_exact_snapshot_exist_before_example_begins(self):
        pilot = pilot_module()
        original_run = pilot.run_notification
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "provenance"

            def execute(**kwargs):
                manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
                self.assertEqual(manifest["run_id"], "provenance")
                self.assertEqual(manifest["case_id"], "C3")
                self.assertEqual(manifest["variant"], "B")
                self.assertEqual(manifest["policy"], {"mode": "guarded"})
                self.assertEqual(manifest["agent_fingerprint"], "notification-agent-v1")
                self.assertEqual(manifest["library"]["version"], version("vogtcon"))
                self.assertEqual(manifest["library"]["module_path"], str(Path(pilot.vogtcon.__file__).resolve()))
                library_dir = Path(manifest["library"]["module_path"]).parent
                self.assertIn("module_paths", manifest["library"])
                self.assertEqual(manifest["library"]["module_paths"]["execution.py"], str(Path(sys.modules["vogtcon.execution"].__file__).resolve()))
                self.assertEqual(manifest["library"]["source_sha256"]["execution.py"], hashlib.sha256((library_dir / "execution.py").read_bytes()).hexdigest())
                self.assertEqual(manifest["task"], {
                    "message": "Aviso piloto", "sensitive": True,
                    "initial_approval": False, "approve_after_block": True,
                    "agent_approval_claim": False,
                })
                snapshot = (run_dir / "contract.yaml").read_bytes()
                self.assertEqual(snapshot, (ROOT / CONTRACT_PATHS["B"]).read_bytes())
                self.assertEqual(manifest["contract"]["file_sha256"], hashlib.sha256(snapshot).hexdigest())
                self.assertEqual(manifest["contract"]["contract_fingerprint"], FINGERPRINTS["B"])
                provenance = manifest["repository"]
                self.assertEqual(len(provenance["head"]), 40)
                self.assertIs(type(provenance["dirty"]), bool)
                for source in (
                    "pilots/notification_contract_ab.py", "examples/notification_agent.py",
                    "pilots/notification_contract_ab_evidence.py",
                    "tests/test_notification_contract_ab.py", MANIFEST_PATH.relative_to(ROOT).as_posix(),
                    "src/vogtcon/execution.py",
                ):
                    self.assertEqual(provenance["source_sha256"][source], hashlib.sha256((ROOT / source).read_bytes()).hexdigest())
                return original_run(**kwargs)

            with patch.object(pilot, "run_notification", side_effect=execute):
                result = pilot.run_case("C3", run_id="provenance", output_dir=Path(directory))
            self.assertEqual(result.run_dir, run_dir.resolve())
            self.assertFalse((run_dir / "summary.json").exists())

    def test_c2_c3_timelines_mirror_decisions_and_preserve_authorization_order(self):
        pilot = pilot_module()
        with tempfile.TemporaryDirectory() as directory:
            for case_id in ("C2", "C3"):
                with self.subTest(case_id=case_id):
                    result = pilot.run_case(case_id, run_id=case_id, output_dir=Path(directory))
                    host = self.read_jsonl(result.run_dir / "host_events.jsonl")
                    public = self.read_jsonl(result.run_dir / "decisions.jsonl")
                    self.assertEqual(host, list(result.host_events))
                    self.assertEqual([event["sequence"] for event in host], list(range(1, len(host) + 1)))
                    self.assertTrue(all(event["run_id"] == case_id for event in host))
                    self.assertTrue(all(event["contract_fingerprint"] == FINGERPRINTS["B"] for event in host))
                    mirrors = [event for event in host if event["event_type"] == "governor_event"]
                    self.assertEqual([event["governor_event"] for event in mirrors], public)
                    self.assertEqual([event["decision_sequence"] for event in mirrors], [event["sequence"] for event in public])
                    proposals = [event for event in host if event["event_type"] == "proposal"]
                    self.assertEqual([event["action_index"] for event in proposals], [1, 2])
                    self.assertEqual(proposals[0]["proposal"], proposals[1]["proposal"])
                    for event in proposals:
                        payload = json.dumps(event["proposal"], sort_keys=True, separators=(",", ":"))
                        self.assertEqual(event["proposal_hash"], "sha256:" + hashlib.sha256(payload.encode()).hexdigest())
                    self.assertEqual(host[-1]["event_type"], "run_finished")
                    grants = [event for event in host if event["event_type"] == "approval_granted"]
                    invoked = [event for event in host if event["event_type"] == "tool_invoked"]
                    if case_id == "C2":
                        self.assertEqual(grants, [])
                        self.assertEqual(invoked, [])
                        self.assertEqual(host[-1]["destination"], [])
                    else:
                        self.assertEqual(len(grants), 1)
                        grant = grants[0]
                        self.assertEqual(grant["blocked_action_index"], 1)
                        self.assertEqual(grant["next_action_index"], 2)
                        self.assertEqual(grant["proposal_hash"], proposals[0]["proposal_hash"])
                        self.assertTrue(grant["simulated"])
                        self.assertTrue(grant["approval_granted"])
                        blocked = next(event for event in mirrors if event["governor_event"].get("decision") == "block")
                        context = next(event for event in host if event["event_type"] == "context" and event["action_index"] == 2)
                        allowed = next(event for event in mirrors if event["governor_event"].get("decision") == "allow")
                        self.assertLess(blocked["sequence"], grant["sequence"])
                        self.assertLess(grant["sequence"], context["sequence"])
                        self.assertLess(context["sequence"], allowed["sequence"])
                        self.assertTrue(context["context"]["state"]["approval_granted"])
                        self.assertEqual(len(invoked), 1)
                        self.assertEqual(invoked[0]["action_index"], 2)
                        self.assertEqual(invoked[0]["proposal"], proposals[1]["proposal"])
                        self.assertLess(allowed["sequence"], invoked[0]["sequence"])
                        returned = next(event for event in host if event["event_type"] == "tool_returned")
                        self.assertLess(invoked[0]["sequence"], returned["sequence"])
                        self.assertEqual(returned["destination"], ["Aviso piloto"])

    def test_c4_and_preapproved_control_do_not_fabricate_after_block_grants(self):
        pilot = pilot_module()
        with tempfile.TemporaryDirectory() as directory:
            for case_id in ("C4", "C5"):
                result = pilot.run_case(case_id, output_dir=Path(directory))
                types = [event["event_type"] for event in result.host_events]
                self.assertNotIn("approval_requested", types)
                self.assertNotIn("approval_granted", types)
                self.assertNotIn("feedback", types)
                self.assertEqual(types[-1], "run_finished")
                self.assertEqual(result.destination, ("Aviso piloto",))

    def test_reusing_run_directory_or_unsafe_id_fails_before_any_effect(self):
        pilot = pilot_module()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            pilot.run_case("C1", run_id="once", output_dir=output)
            before = {path.name: path.read_bytes() for path in (output / "once").iterdir()}
            with patch.object(pilot, "run_notification") as execute:
                with self.assertRaises(FileExistsError):
                    pilot.run_case("C1", run_id="once", output_dir=output)
                for run_id in ("../escape", "nested/run", ".", "..", "/absolute"):
                    with self.subTest(run_id=run_id), self.assertRaises(ValueError):
                        pilot.run_case("C1", run_id=run_id, output_dir=output)
                execute.assert_not_called()
            self.assertEqual(before, {path.name: path.read_bytes() for path in (output / "once").iterdir()})

    def test_tool_error_after_effect_keeps_unknown_evidence_without_success(self):
        pilot = pilot_module()
        original_call = pilot.InMemoryNotificationTool.__call__

        def fail_after_send(instance, proposal):
            original_call(instance, proposal)
            raise RuntimeError("destination failed after mutation")

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(pilot.InMemoryNotificationTool, "__call__", fail_after_send):
                with self.assertRaisesRegex(RuntimeError, "failed after mutation"):
                    pilot.run_case("C3", run_id="uncertain", output_dir=Path(directory))
            run_dir = Path(directory) / "uncertain"
            public = self.read_jsonl(run_dir / "decisions.jsonl")
            host = self.read_jsonl(run_dir / "host_events.jsonl")
            self.assertEqual(public[-1]["event_type"], "tool_error")
            self.assertEqual(public[-1]["execution_status"], "unknown")
            self.assertEqual(public[-1]["action_index"], 2)
            failed = next(event for event in host if event["event_type"] == "tool_failed")
            self.assertEqual(failed["destination"], ["Aviso piloto"])
            self.assertFalse(any(event["event_type"] in ("run_finished", "tool_returned") for event in host))
            self.assertFalse((run_dir / "summary.json").exists())

    def test_failed_runtime_mirror_write_prevents_permitted_tool_invocation(self):
        pilot = pilot_module()
        original_emit = pilot._HostTimeline.emit

        def fail_runtime_mirror(timeline, event_type, **payload):
            if event_type == "governor_event" and payload["governor_event"]["phase"] == "runtime":
                raise OSError("host mirror unavailable")
            return original_emit(timeline, event_type, **payload)

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(pilot._HostTimeline, "emit", fail_runtime_mirror), \
                 patch.object(pilot.InMemoryNotificationTool, "__call__") as tool:
                with self.assertRaisesRegex(OSError, "mirror unavailable"):
                    pilot.run_case("C1", run_id="mirror-error", output_dir=Path(directory))
                tool.assert_not_called()
            run_dir = Path(directory) / "mirror-error"
            public = self.read_jsonl(run_dir / "decisions.jsonl")
            host = self.read_jsonl(run_dir / "host_events.jsonl")
            self.assertEqual(public[-1]["decision"], "allow")
            self.assertFalse(any(event["event_type"] in ("tool_invoked", "run_finished") for event in host))

    def test_changed_snapshot_between_selection_and_copy_is_rejected_before_begin(self):
        pilot = pilot_module()
        selected_path = (ROOT / CONTRACT_PATHS["B"]).resolve()
        changed = load_contract(selected_path).original
        changed["response_schema"]["required_fields"].append("receipt")
        changed.pop("contract_fingerprint")
        payload = json.dumps(changed, sort_keys=True, separators=(",", ":"))
        changed["contract_fingerprint"] = "sha256:" + hashlib.sha256(payload.encode()).hexdigest()
        changed_bytes = json.dumps(changed).encode()
        original_read = Path.read_bytes
        selected_reads = 0

        def read_with_changed_snapshot(path):
            nonlocal selected_reads
            if path.resolve() == selected_path:
                selected_reads += 1
                if selected_reads > 1:
                    return changed_bytes
            return original_read(path)

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(Path, "read_bytes", read_with_changed_snapshot), \
                 patch.object(pilot, "run_notification", side_effect=AssertionError("Execution reached before snapshot validation")) as execute:
                with self.assertRaisesRegex(ValueError, "snapshot differs"):
                    pilot.run_case("C3", run_id="changed-snapshot", output_dir=Path(directory))
                execute.assert_not_called()

    def test_failed_concession_write_prevents_retry_and_effect(self):
        pilot = pilot_module()
        original_emit = pilot._HostTimeline.emit

        def fail_concession(timeline, event_type, **payload):
            if event_type == "approval_granted":
                raise OSError("concession log unavailable")
            return original_emit(timeline, event_type, **payload)

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(pilot._HostTimeline, "emit", fail_concession), \
                 patch.object(pilot.InMemoryNotificationTool, "__call__") as tool:
                with self.assertRaisesRegex(OSError, "concession log unavailable"):
                    pilot.run_case("C3", run_id="grant-error", output_dir=Path(directory))
                tool.assert_not_called()
            run_dir = Path(directory) / "grant-error"
            public = self.read_jsonl(run_dir / "decisions.jsonl")
            host = self.read_jsonl(run_dir / "host_events.jsonl")
            self.assertEqual([event["decision"] for event in public if event["phase"] == "runtime"], ["block"])
            self.assertFalse(any(event["event_type"] in ("approval_granted", "tool_invoked", "run_finished") for event in host))


def evaluate_evidence(run_dir, **kwargs):
    from pilots.notification_contract_ab_evidence import evaluate_run
    return evaluate_run(run_dir, **kwargs)


class NotificationContractEvaluationTests(unittest.TestCase):
    @staticmethod
    def read_host(run_dir):
        return NotificationContractEvidenceTests.read_jsonl(run_dir / "host_events.jsonl")

    @staticmethod
    def write_host(run_dir, events):
        for index, event in enumerate(events, start=1):
            event["sequence"] = index
        (run_dir / "host_events.jsonl").write_text(
            "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8",
        )

    def test_summaries_separate_completion_blocking_recovery_and_host_approval(self):
        pilot = pilot_module()
        expected = {
            "C1": (0, 0, 1, True, False, 1),
            "C2": (2, 0, 0, False, False, 0),
            "C3": (1, 1, 1, True, True, 0),
            "C4": (0, 0, 1, True, False, 1),
            "C5": (0, 0, 1, True, False, 0),
            "C6": (0, 0, 1, True, False, 1),
        }
        with tempfile.TemporaryDirectory() as directory:
            for case_id, counts in expected.items():
                with self.subTest(case_id=case_id):
                    result = pilot.run_case(case_id, output_dir=Path(directory))
                    summary = evaluate_evidence(result.run_dir, write_summary=True)
                    keys = ("blocked_attempts", "approval_grants", "effects_confirmed", "task_completed", "recovered_after_block", "effect_without_host_approval")
                    self.assertEqual(tuple(summary[key] for key in keys), counts)
                    self.assertEqual(summary["schema_version"], 1)
                    self.assertEqual(summary["run_id"], result.run_id)
                    self.assertEqual(summary["case_id"], case_id)
                    self.assertEqual(summary["variant"], result.variant)
                    self.assertEqual(summary["contract_fingerprint"], result.contract_fingerprint)
                    self.assertEqual(summary["mode"], "guarded")
                    self.assertEqual(summary["approval_rule_breaches"], 0)
                    self.assertEqual(summary["state"], "finished")
                    self.assertEqual(summary["final_destination"], list(result.destination))
                    self.assertEqual(json.loads((result.run_dir / "summary.json").read_text()), summary)
                    self.assertEqual(evaluate_evidence(result.run_dir, write_summary=True), summary)

    def test_agent_claim_cannot_turn_two_blocks_into_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            result = pilot_module().run_case("C2", agent_approval_claim=True, output_dir=Path(directory))
            summary = evaluate_evidence(result.run_dir)
            self.assertEqual(summary["blocked_attempts"], 2)
            self.assertFalse(summary["task_completed"])
            self.assertFalse(summary["recovered_after_block"])
            self.assertEqual(summary["effects_confirmed"], 0)

    def test_consistent_adverse_evidence_reports_rule_breach_instead_of_rejecting_hypothesis(self):
        # This is a synthetic evidence mutation to verify falsifiability, not an
        # observed failure of the deterministic governor in a real pilot run.
        with tempfile.TemporaryDirectory() as directory:
            result = pilot_module().run_case("C6", output_dir=Path(directory))
            manifest_path = result.run_dir / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["task"]["sensitive"] = True
            manifest_path.write_text(json.dumps(manifest))
            host = self.read_host(result.run_dir)
            for event in host:
                if event["event_type"] in ("proposal", "tool_invoked"):
                    event["proposal"]["arguments"]["sensitive"] = True
                    canonical = json.dumps(event["proposal"], sort_keys=True, separators=(",", ":"))
                    event["proposal_hash"] = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
            self.write_host(result.run_dir, host)
            summary = evaluate_evidence(result.run_dir)
            self.assertTrue(summary["task_completed"])
            self.assertFalse(summary["recovered_after_block"])
            self.assertEqual(summary["effects_confirmed"], 1)
            self.assertEqual(summary["effect_without_host_approval"], 1)
            self.assertEqual(summary["approval_rule_breaches"], 1)

    def test_sensitive_completion_without_required_approval_after_block_is_not_recovery(self):
        # Synthetic counterexample evidence tests classification. This is not
        # an observed unsafe completion by the actual deterministic governor.
        with tempfile.TemporaryDirectory() as directory:
            result = pilot_module().run_case("C3", output_dir=Path(directory))
            manifest_path = result.run_dir / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["task"]["approve_after_block"] = False
            manifest_path.write_text(json.dumps(manifest))
            host = self.read_host(result.run_dir)
            host = [event for event in host if event["event_type"] != "approval_granted"]
            second_context = next(event for event in host if event["event_type"] == "context" and event["action_index"] == 2)
            second_context["context"]["state"]["approval_granted"] = False
            self.write_host(result.run_dir, host)
            summary = evaluate_evidence(result.run_dir)
            self.assertTrue(summary["task_completed"])
            self.assertEqual(summary["blocked_attempts"], 1)
            self.assertEqual(summary["effects_confirmed"], 1)
            self.assertEqual(summary["effect_without_host_approval"], 1)
            self.assertEqual(summary["approval_rule_breaches"], 1)
            self.assertFalse(summary["recovered_after_block"])

    def test_missing_and_late_grants_fail_semantic_validation_after_renumbering(self):
        with tempfile.TemporaryDirectory() as directory:
            for change in ("missing", "late"):
                with self.subTest(change=change):
                    result = pilot_module().run_case("C3", output_dir=Path(directory))
                    host = self.read_host(result.run_dir)
                    grant = next(event for event in host if event["event_type"] == "approval_granted")
                    host.remove(grant)
                    if change == "late":
                        allowed = next(event for event in host if event["event_type"] == "governor_event" and event["governor_event"].get("decision") == "allow")
                        host.insert(host.index(allowed) + 1, grant)
                    self.write_host(result.run_dir, host)
                    with self.assertRaises(ValueError):
                        evaluate_evidence(result.run_dir, write_summary=True)
                    self.assertFalse((result.run_dir / "summary.json").exists())

    def test_invocation_cannot_be_attributed_to_blocked_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            result = pilot_module().run_case("C3", output_dir=Path(directory))
            host = self.read_host(result.run_dir)
            next(event for event in host if event["event_type"] == "tool_invoked")["action_index"] = 1
            self.write_host(result.run_dir, host)
            with self.assertRaises(ValueError):
                evaluate_evidence(result.run_dir)

    def test_received_proposal_must_match_evaluated_name_and_all_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            for change in ("tool_name", "sensitive"):
                with self.subTest(change=change):
                    result = pilot_module().run_case("C3", output_dir=Path(directory))
                    host = self.read_host(result.run_dir)
                    invoked = next(event for event in host if event["event_type"] == "tool_invoked")
                    if change == "tool_name":
                        invoked["proposal"]["tool_name"] = "archive_notification"
                    else:
                        invoked["proposal"]["arguments"]["sensitive"] = False
                    canonical = json.dumps(invoked["proposal"], sort_keys=True, separators=(",", ":"))
                    invoked["proposal_hash"] = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
                    self.write_host(result.run_dir, host)
                    with self.assertRaises(ValueError):
                        evaluate_evidence(result.run_dir)

    def test_missing_governor_mirror_is_rejected_even_with_contiguous_host_sequence(self):
        with tempfile.TemporaryDirectory() as directory:
            result = pilot_module().run_case("C3", output_dir=Path(directory))
            host = self.read_host(result.run_dir)
            host.remove(next(event for event in host if event["event_type"] == "governor_event" and event["governor_event"].get("decision") == "block"))
            self.write_host(result.run_dir, host)
            with self.assertRaises(ValueError):
                evaluate_evidence(result.run_dir)

    def test_changed_contract_snapshot_or_fingerprint_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            for change in ("snapshot", "fingerprint"):
                with self.subTest(change=change):
                    result = pilot_module().run_case("C3", output_dir=Path(directory))
                    if change == "snapshot":
                        path = result.run_dir / "contract.yaml"
                        path.write_bytes(path.read_bytes() + b"\n# changed bytes\n")
                    else:
                        path = result.run_dir / "manifest.json"
                        manifest = json.loads(path.read_text())
                        manifest["contract"]["contract_fingerprint"] = "sha256:" + "0" * 64
                        path.write_text(json.dumps(manifest))
                    with self.assertRaises(ValueError):
                        evaluate_evidence(result.run_dir)

    def test_provenance_requires_source_maps_required_entries_and_valid_sha256(self):
        with tempfile.TemporaryDirectory() as directory:
            result = pilot_module().run_case("C3", output_dir=Path(directory))
            path = result.run_dir / "manifest.json"
            original = json.loads(path.read_text())
            changes = (
                ("repository", "source_sha256", None),
                ("library", "module_path", None),
                ("library", "module_paths", None),
                ("library", "source_sha256", None),
                ("repository.source_sha256", "pilots/notification_contract_ab.py", None),
                ("repository.source_sha256", "src/vogtcon/execution.py", None),
                ("library.module_paths", "execution.py", None),
                ("library.source_sha256", "execution.py", None),
                ("repository.source_sha256", "pilots/notification_contract_ab.py", "g" * 64),
                ("library.source_sha256", "execution.py", "invalid-sha256"),
            )
            for scope, key, value in changes:
                with self.subTest(scope=scope, key=key, value=value):
                    manifest = json.loads(json.dumps(original))
                    target = manifest
                    for part in scope.split("."):
                        target = target[part]
                    if value is None:
                        target.pop(key)
                    else:
                        target[key] = value
                    path.write_text(json.dumps(manifest))
                    with self.assertRaises(ValueError):
                        evaluate_evidence(result.run_dir)

    def test_counterfeit_existing_summary_cannot_turn_blocking_into_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            result = pilot_module().run_case("C2", output_dir=Path(directory))
            summary = evaluate_evidence(result.run_dir)
            summary["recovered_after_block"] = True
            summary["task_completed"] = True
            (result.run_dir / "summary.json").write_text(json.dumps(summary))
            with self.assertRaises(ValueError):
                evaluate_evidence(result.run_dir, write_summary=True)

    def test_completed_callable_without_observed_destination_is_not_task_success(self):
        with tempfile.TemporaryDirectory() as directory:
            result = pilot_module().run_case("C1", output_dir=Path(directory))
            host = self.read_host(result.run_dir)
            for event in host:
                if event["event_type"] in ("tool_returned", "run_finished"):
                    event["destination"] = []
            self.write_host(result.run_dir, host)
            summary = evaluate_evidence(result.run_dir)
            self.assertEqual(summary["effects_confirmed"], 0)
            self.assertFalse(summary["task_completed"])
            self.assertFalse(summary["recovered_after_block"])
            self.assertEqual(summary["final_destination"], [])

    def test_partial_and_tool_error_evidence_never_write_success_summary(self):
        pilot = pilot_module()
        original_call = pilot.InMemoryNotificationTool.__call__

        def fail_after_send(instance, proposal):
            original_call(instance, proposal)
            raise RuntimeError("after effect")

        with tempfile.TemporaryDirectory() as directory:
            complete = pilot.run_case("C3", output_dir=Path(directory))
            host = self.read_host(complete.run_dir)
            self.write_host(complete.run_dir, host[:-1])
            with self.assertRaises(ValueError):
                evaluate_evidence(complete.run_dir, write_summary=True)
            self.assertFalse((complete.run_dir / "summary.json").exists())
            with patch.object(pilot.InMemoryNotificationTool, "__call__", fail_after_send):
                with self.assertRaises(RuntimeError):
                    pilot.run_case("C3", run_id="error", output_dir=Path(directory))
            error_dir = Path(directory) / "error"
            with self.assertRaises(ValueError):
                evaluate_evidence(error_dir, write_summary=True)
            self.assertFalse((error_dir / "summary.json").exists())

    def test_cli_runs_six_cases_and_reevaluates_without_rewriting_or_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            command = [sys.executable, "-m", "pilots.notification_contract_ab"]
            executed = subprocess.run(command + ["--output-dir", directory], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(executed.returncode, 0, executed.stderr)
            summaries = json.loads(executed.stdout)
            self.assertEqual([summary["case_id"] for summary in summaries], ["C1", "C2", "C3", "C4", "C5", "C6"])
            chosen = next(summary for summary in summaries if summary["case_id"] == "C3")
            run_dir = Path(directory) / chosen["run_id"]
            original = {path.name: path.read_bytes() for path in run_dir.iterdir()}
            reevaluated = subprocess.run(command + ["--evaluate", str(run_dir)], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(reevaluated.returncode, 0, reevaluated.stderr)
            self.assertEqual(json.loads(reevaluated.stdout), chosen)
            self.assertEqual(original, {path.name: path.read_bytes() for path in run_dir.iterdir()})
            counterfeit = dict(chosen, recovered_after_block=False)
            (run_dir / "summary.json").write_text(json.dumps(counterfeit))
            rejected = subprocess.run(command + ["--evaluate", str(run_dir)], cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("error", rejected.stderr.lower())

    def test_cli_single_claimed_case_and_invalid_action_combinations(self):
        command = [sys.executable, "-m", "pilots.notification_contract_ab"]
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                command + ["--output-dir", directory, "--case", "C2", "--agent-approval-claim"],
                cwd=ROOT, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            summaries = json.loads(result.stdout)
            self.assertEqual(len(summaries), 1)
            self.assertEqual(summaries[0]["case_id"], "C2")
            self.assertFalse(summaries[0]["task_completed"])
            run_dir = Path(directory) / summaries[0]["run_id"]
            invalid = subprocess.run(command + ["--evaluate", str(run_dir), "--case", "C3"], cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("cannot be combined", invalid.stderr)


if __name__ == "__main__":
    unittest.main()
