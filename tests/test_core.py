# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import unittest
from copy import deepcopy

from vogtcon import (
    ActionProposal, AgentContract, ContractRulesV3, DeterministicEvaluator,
    EmptyRuleParams, EnforcementPolicy, ExecutionContext, GovernanceDecision,
    Governor, GovernorInput, HostFacts, PlannedEffect, RuleCatalog, RuleTypeSpec,
)
from vogtcon.models import EffectRecord, TrajectoryEntry, TrajectoryView


TOOLS = ["search_policy", "create_ticket", "approve_request", "store_memory", "send_notification"]
RUNTIME = ["tool.declared_only", "ticket_requires_evidence", "authorization.role_required",
           "memory.scope_allowed", "sensitive_requires_approval"]
POST = ["response.schema_complete", "run_ledger.required", "run_ledger.complete", "forbidden.outcome_triggered"]
LEDGER_KEYS = ["run_id", "scenario_id", "mode", "contract_id", "provider", "model_id",
               "replication_id", "actions", "artifacts"]


def contract_data(mode="guarded"):
    return {
        "contract_id": f"example.{mode}", "mode": mode,
        "approved_agent_configurations": ["agent-string", {"fingerprint": "agent-object"}, {"fingerprint": "agent-object"}],
        "declared_tools": TOOLS.copy(), "response_schema": {"required_fields": ["answer", "citations", "status"]},
        "memory_policy": "allowed-scope-only",
        "validation_phases": "not_enforced" if mode == "no_contract" else ["pre_execution", "runtime", "post_execution"],
        "runtime_rules": [] if mode == "no_contract" else RUNTIME.copy(),
        "postconditions": [] if mode == "no_contract" else POST.copy(),
        "agent_feedback": {"advisory_warning_visibility": False, "guarded_denial_style": "minimal",
                           "strict_replanning_after_violation": False},
        "contract_fingerprint": "contract-fingerprint",
    }


def request_data(phase="runtime", mode="guarded"):
    data = {
        "run_id": "example", "contract": contract_data(mode), "phase": phase,
        "context": {"state": {}, "available_tools": TOOLS.copy()},
    }
    if phase == "runtime":
        data["action"] = {"tool_name": "search_policy", "arguments": {}}
    elif phase == "pre_execution":
        data["context"].update(observed_agent_fingerprint="agent-object", observed_contract_fingerprint="contract-fingerprint")
    else:
        data.update(response={"answer": None, "citations": None, "status": None},
                    run_ledger={key: None for key in LEDGER_KEYS})
    return data


def evaluate(data):
    return DeterministicEvaluator().evaluate(GovernorInput.model_validate(data))


class EvaluationTests(unittest.TestCase):
    def test_v2_rules_use_external_mode_without_mutating_contract(self):
        original = contract_data("guarded")
        original.pop("mode")
        original.pop("agent_feedback")
        original["schema_version"] = 2
        original["metadata"] = {}
        for mode, expected, count in (
            ("no_contract", "allow", 0),
            ("advisory", "allow_with_warning", 1),
            ("guarded", "block", 1),
            ("strict", "abort", 1),
        ):
            with self.subTest(mode=mode):
                data = request_data()
                data["contract"] = deepcopy(original)
                data["policy"] = {"mode": mode}
                data["action"] = {
                    "tool_name": "send_notification", "arguments": {"sensitive": True},
                }
                request = GovernorInput.model_validate(data)
                result = DeterministicEvaluator().evaluate(request)
                self.assertEqual(result.decision, expected)
                self.assertEqual(len(result.violations), count)
                self.assertEqual(request.contract.model_dump(), original)

    def test_clean_results_across_modes_and_phases(self):
        for mode in ("no_contract", "advisory", "guarded", "strict"):
            for phase in ("pre_execution", "runtime", "post_execution"):
                with self.subTest(mode=mode, phase=phase):
                    result = evaluate(request_data(phase, mode))
                    self.assertEqual(result.violations, [])
                    self.assertEqual(result.decision, "allow" if phase == "runtime" else None)

    def test_pre_checks_both_fingerprints_in_historical_order(self):
        data = request_data("pre_execution")
        for fingerprint in ("agent-string", "agent-object"):
            data["context"]["observed_agent_fingerprint"] = fingerprint
            self.assertEqual(evaluate(data).violations, [])
        data["context"].update(observed_agent_fingerprint="bad", observed_contract_fingerprint="bad")
        result = evaluate(data)
        self.assertEqual([v.rule for v in result.violations], ["agent.configuration_fingerprint_match", "contract.fingerprint_match"])
        self.assertTrue(all(v.action is None and v.severity == "high" for v in result.violations))
        self.assertIsNone(result.decision)

    def test_each_runtime_rule_and_mode_policy(self):
        cases = [
            ("missing", {}, {}, "tool.declared_only"),
            ("create_ticket", {}, {}, "ticket_requires_evidence"),
            ("approve_request", {}, {}, "authorization.role_required"),
            ("store_memory", {}, {}, "memory.scope_allowed"),
            ("send_notification", {"sensitive": True}, {}, "sensitive_requires_approval"),
        ]
        for mode, expected in (("no_contract", "allow"), ("advisory", "allow_with_warning"),
                               ("guarded", "block"), ("strict", "abort")):
            for tool, arguments, state, rule in cases:
                with self.subTest(mode=mode, tool=tool):
                    data = request_data(mode=mode)
                    data["action"] = {"tool_name": tool, "arguments": arguments}
                    data["context"]["state"] = state
                    result = evaluate(data)
                    self.assertEqual(result.decision, expected)
                    self.assertEqual([v.rule for v in result.violations], [] if mode == "no_contract" else [rule])
                    self.assertTrue(all(v.action == tool and v.phase == "runtime" and v.severity == "high" for v in result.violations))

    def test_allowed_domain_actions(self):
        cases = [
            ("create_ticket", {"evidence_ids": ["E1"]}, {}),
            ("approve_request", {}, {"user_role": "manager"}),
            ("approve_request", {}, {"user_role": "admin"}),
            ("store_memory", {"scope": "allowed"}, {}),
            ("send_notification", {"sensitive": False}, {}),
            ("send_notification", {"sensitive": True}, {"approval_granted": True}),
        ]
        for tool, arguments, state in cases:
            with self.subTest(tool=tool, state=state):
                data = request_data()
                data["action"] = {"tool_name": tool, "arguments": arguments}
                data["context"]["state"] = state
                self.assertEqual(evaluate(data).decision, "allow")

    def test_tool_gate_checks_available_and_declared_with_early_return(self):
        for location in ("available", "declared", "wildcard"):
            data = request_data()
            data["action"]["tool_name"] = "create_ticket"
            if location == "available":
                data["context"]["available_tools"] = []
            else:
                data["contract"]["declared_tools"] = ["*"] if location == "wildcard" else []
            self.assertEqual([v.rule for v in evaluate(data).violations], ["tool.declared_only"])

    def test_proposal_cannot_supply_its_own_role_or_approval(self):
        for tool, args in (("approve_request", {"user_role": "admin"}),
                           ("send_notification", {"sensitive": True, "approval_granted": True})):
            data = request_data()
            data["action"] = {"tool_name": tool, "arguments": args}
            self.assertEqual(evaluate(data).decision, "block")

    def test_invalid_json_role_types_are_denied(self):
        for role in (None, [], ["manager"], {"role": "admin"}, 1, True):
            with self.subTest(role=role):
                data = request_data()
                data["action"]["tool_name"] = "approve_request"
                data["context"]["state"] = {"user_role": role}
                self.assertEqual([v.rule for v in evaluate(data).violations], ["authorization.role_required"])

    def test_post_violations_order_and_missing_vs_incomplete_ledger(self):
        for ledger, expected in ((None, "run_ledger.required"), ({}, "run_ledger.complete")):
            data = request_data("post_execution")
            data.update(response={}, run_ledger=ledger)
            data["context"]["forbidden_outcomes_triggered"] = ["outcome"]
            result = evaluate(data)
            self.assertEqual([v.rule for v in result.violations], ["response.schema_complete", expected, "forbidden.outcome_triggered"])
            self.assertIsNone(result.decision)

    def test_every_ledger_key_required_but_values_not_interpreted(self):
        for key in LEDGER_KEYS:
            data = request_data("post_execution")
            del data["run_ledger"][key]
            self.assertEqual([v.rule for v in evaluate(data).violations], ["run_ledger.complete"])
        data = request_data("post_execution")
        data["context"]["final_properties"] = {"unsafe": True}
        self.assertEqual(evaluate(data).violations, [])

    def test_no_contract_bypasses_all_phase_checks(self):
        for phase in ("pre_execution", "runtime", "post_execution"):
            data = request_data(phase, "no_contract")
            data["context"].update(observed_agent_fingerprint="bad", observed_contract_fingerprint="bad",
                                   available_tools=[], forbidden_outcomes_triggered=["bad"])
            if phase == "post_execution":
                data.update(response={}, run_ledger=None)
            result = evaluate(data)
            self.assertEqual(result.violations, [])

    def test_selected_rules_order_and_duplicates(self):
        data = request_data("post_execution")
        data.update(response={}, run_ledger=None)
        data["context"]["forbidden_outcomes_triggered"] = ["bad"]
        data["contract"]["postconditions"] = ["forbidden.outcome_triggered", "response.schema_complete", "response.schema_complete"]
        self.assertEqual([v.rule for v in evaluate(data).violations], ["response.schema_complete", "forbidden.outcome_triggered"])
        data = request_data()
        data["action"]["tool_name"] = "create_ticket"
        data["contract"]["runtime_rules"] = []
        self.assertEqual(evaluate(data).decision, "allow")

    def test_complete_rule_does_not_report_absent_ledger(self):
        data = request_data("post_execution")
        data["run_ledger"] = None
        data["contract"]["postconditions"] = ["run_ledger.complete"]
        self.assertEqual(evaluate(data).violations, [])

    def test_direct_evaluation_cannot_skip_configuration_validation(self):
        for mode in ("no_contract", "guarded"):
            data = request_data(mode=mode)
            data["contract"]["runtime_rules"] = ["unknown"]
            with self.assertRaisesRegex(ValueError, "Unsupported"):
                evaluate(data)
        data = request_data()
        data["contract"]["validation_phases"] = ["runtime"]
        with self.assertRaisesRegex(ValueError, "all three"):
            evaluate(data)

    def test_evaluation_is_repeatable_without_input_mutation(self):
        request = GovernorInput.model_validate(request_data())
        before = deepcopy(request.model_dump())
        evaluator = DeterministicEvaluator()
        first = evaluator.evaluate(request)
        self.assertEqual(evaluator.evaluate(request), first)
        self.assertEqual(request.model_dump(), before)

    def test_governor_default_and_injected_evaluator(self):
        request = GovernorInput.model_validate(request_data())
        self.assertEqual(Governor().evaluate(request), DeterministicEvaluator().evaluate(request))
        result = GovernanceDecision(phase="runtime", decision="block", violations=[], explanation="injected")

        class Stub:
            seen = None

            def __bool__(self):
                return False

            def evaluate(self, item):
                self.seen = item
                return result

        stub = Stub()
        self.assertIs(Governor(stub).evaluate(request), result)
        self.assertIs(stub.seen, request)

    def test_legacy_decisions_unchanged_with_agreeing_host_facts_and_planned_effect(self):
        evaluator = DeterministicEvaluator()
        for use_v2 in (False, True):
            for mode in ("no_contract", "advisory", "guarded", "strict"):
                for phase in ("pre_execution", "runtime", "post_execution"):
                    with self.subTest(v2=use_v2, mode=mode, phase=phase):
                        baseline_data = request_data(phase=phase, mode=mode)
                        if use_v2:
                            v2 = contract_data("guarded")
                            v2.pop("mode")
                            v2.pop("agent_feedback")
                            v2["schema_version"] = 2
                            v2["metadata"] = {}
                            baseline_data["contract"] = v2
                            baseline_data["policy"] = {"mode": mode}
                        if phase == "runtime":
                            baseline_data["context"]["state"] = {"user_role": "employee"}
                            baseline_data["action"] = {
                                "tool_name": "approve_request",
                                "arguments": {"user_role": "admin", "approval_granted": True},
                            }

                        enriched_data = deepcopy(baseline_data)
                        enriched_data["host_facts"] = HostFacts(
                            facts={
                                **deepcopy(baseline_data["context"]["state"]),
                                "host_only_fact": "verified",
                            }
                        )
                        if phase == "runtime":
                            enriched_data["planned_effect"] = PlannedEffect(
                                tool_name="approve_request",
                                parameters={"request_id": "req-1"},
                                defaults={"notify": False},
                            )

                        baseline_decision = evaluator.evaluate(
                            GovernorInput.model_validate(baseline_data)
                        )
                        enriched_decision = evaluator.evaluate(
                            GovernorInput.model_validate(enriched_data)
                        )
                        self.assertEqual(enriched_decision, baseline_decision)
                        if phase == "runtime" and mode != "no_contract":
                            self.assertEqual(
                                [v.rule for v in enriched_decision.violations],
                                ["authorization.role_required"],
                            )

    def test_post_construction_context_state_mutation_cannot_bypass_source_agreement(self):
        evaluator = DeterministicEvaluator()
        caller_state = {"approval_granted": False}
        ctx = ExecutionContext(state=caller_state, available_tools=TOOLS.copy())
        request = GovernorInput(
            run_id="run-agreement-guard",
            contract=AgentContract.model_validate(contract_data("guarded")),
            phase="runtime",
            context=ctx,
            action=ActionProposal(
                tool_name="send_notification",
                arguments={"sensitive": True},
            ),
            host_facts=HostFacts(facts={"approval_granted": False}),
            planned_effect=PlannedEffect(tool_name="send_notification"),
        )
        self.assertEqual(evaluator.evaluate(request).decision, "block")

        with self.assertRaises(TypeError):
            request.context.state["approval_granted"] = True

        # Mutating caller's original dict or standalone ExecutionContext does not flip decision
        caller_state["approval_granted"] = True
        ctx.state["approval_granted"] = True
        self.assertEqual(evaluator.evaluate(request).decision, "block")

        # Defense-in-depth: even low-level attribute tampering fails closed at evaluate()
        for mode in ("guarded", "no_contract"):
            tampered_request = request.model_copy(
                update={"contract": AgentContract.model_validate(contract_data(mode))},
                deep=True,
            )
            object.__setattr__(
                tampered_request.context,
                "state",
                {"approval_granted": True},
            )
            with self.assertRaisesRegex(
                ValueError,
                r"host_facts conflicts with context\.state for key\(s\): approval_granted",
            ):
                evaluator.evaluate(tampered_request)

        tampered_effect_request = request.model_copy()
        object.__setattr__(
            tampered_effect_request,
            "planned_effect",
            PlannedEffect(tool_name="approve_request"),
        )
        with self.assertRaisesRegex(
            ValueError,
            r"planned_effect\.tool_name conflicts with action\.tool_name",
        ):
            evaluator.evaluate(tampered_effect_request)


class V3EvaluationTests(unittest.TestCase):
    def _v3_contract(self, rules: list[dict] | None = None) -> ContractRulesV3:
        return ContractRulesV3.model_validate(
            {
                "schema_version": 3,
                "contract_id": "example.v3",
                "approved_agent_configurations": ["agent-v3"],
                "declared_tools": ["send_notification"],
                "response_schema": {"required_fields": ["answer", "status"]},
                "memory_policy": "none",
                "validation_phases": ["pre_execution", "runtime", "post_execution"],
                "rules": (
                    rules
                    if rules is not None
                    else [
                        {
                            "instance_id": "declared-only",
                            "rule_type": "tool.declared_only",
                            "phases": ["runtime"],
                        },
                        {
                            "instance_id": "schema-complete",
                            "rule_type": "response.schema_complete",
                            "phases": ["post_execution"],
                        },
                    ]
                ),
                "contract_fingerprint": "sha256:" + "a" * 64,
            }
        )

    def test_v3_evaluates_across_phases_and_modes_deterministically(self):
        contract = self._v3_contract()
        evaluator = DeterministicEvaluator()

        for mode, runtime_decision, has_violations in (
            ("no_contract", "allow", False),
            ("advisory", "allow_with_warning", True),
            ("guarded", "block", True),
            ("strict", "abort", True),
        ):
            with self.subTest(mode=mode):
                pre_req = GovernorInput(
                    run_id="r-v3",
                    contract=contract,
                    phase="pre_execution",
                    policy=EnforcementPolicy(mode=mode),
                    context=ExecutionContext(
                        state={},
                        available_tools=["send_notification"],
                        observed_agent_fingerprint="wrong-agent",
                        observed_contract_fingerprint=contract.contract_fingerprint,
                    ),
                )
                pre_res = evaluator.evaluate(pre_req)
                self.assertEqual(
                    [v.rule for v in pre_res.violations],
                    ["agent.configuration_fingerprint_match"] if has_violations else [],
                )

                rt_req = GovernorInput(
                    run_id="r-v3",
                    contract=contract,
                    phase="runtime",
                    policy=EnforcementPolicy(mode=mode),
                    context=ExecutionContext(
                        state={}, available_tools=["undeclared_tool"]
                    ),
                    action=ActionProposal(tool_name="undeclared_tool"),
                    planned_effect=PlannedEffect(tool_name="undeclared_tool"),
                )
                before_dump = deepcopy(rt_req.model_dump())
                rt_res = evaluator.evaluate(rt_req)
                self.assertEqual(rt_res.decision, runtime_decision)
                self.assertEqual(
                    [(v.rule, v.rule_type) for v in rt_res.violations],
                    [("declared-only", "tool.declared_only")] if has_violations else [],
                )
                self.assertEqual(evaluator.evaluate(rt_req), rt_res)
                self.assertEqual(rt_req.model_dump(), before_dump)

                post_req = GovernorInput(
                    run_id="r-v3",
                    contract=contract,
                    phase="post_execution",
                    policy=EnforcementPolicy(mode=mode),
                    context=ExecutionContext(
                        state={}, available_tools=["send_notification"]
                    ),
                    response={"answer": "missing status"},
                )
                post_res = evaluator.evaluate(post_req)
                self.assertEqual(
                    [(v.rule, v.rule_type) for v in post_res.violations],
                    [("schema-complete", "response.schema_complete")]
                    if has_violations
                    else [],
                )

    def test_post_only_missing_v3_handler_fails_closed_before_execution(self):
        catalog = RuleCatalog(
            rule_types={
                "post.unimplemented": RuleTypeSpec(
                    allowed_phases=frozenset({"post_execution"}),
                    params_model=EmptyRuleParams,
                    handler=None,
                )
            }
        )
        contract = self._v3_contract(
            rules=[
                {
                    "instance_id": "declared-only",
                    "rule_type": "tool.declared_only",
                    "phases": ["runtime"],
                },
                {
                    "instance_id": "post-check",
                    "rule_type": "post.unimplemented",
                    "phases": ["post_execution"],
                },
            ]
        )
        evaluator = DeterministicEvaluator(rule_catalog=catalog)

        for phase in ("pre_execution", "runtime", "post_execution"):
            with self.subTest(phase=phase):
                kwargs: dict = {
                    "run_id": "r-fail-closed",
                    "contract": contract,
                    "phase": phase,
                    "policy": EnforcementPolicy(mode="guarded"),
                    "context": ExecutionContext(
                        state={},
                        available_tools=["send_notification"],
                        observed_agent_fingerprint="agent-v3",
                        observed_contract_fingerprint=contract.contract_fingerprint,
                    ),
                }
                if phase == "runtime":
                    kwargs["action"] = ActionProposal(tool_name="send_notification")
                elif phase == "post_execution":
                    kwargs["response"] = {"answer": "ok", "status": "done"}
                req = GovernorInput(**kwargs)
                with self.assertRaisesRegex(
                    ValueError,
                    "Rule type 'post.unimplemented' has no evaluation handler configured",
                ):
                    evaluator.evaluate(req)

    def test_v3_custom_rule_reads_immutable_trajectory_and_cannot_mutate_view(self):
        digest = "sha256:" + "b" * 64

        def block_duplicate_confirmed(req: GovernorInput, _params) -> bool:
            assert req.trajectory is not None and req.planned_effect is not None
            op_digest = req.planned_effect.operation_digest()
            return any(
                eff.operation_digest == op_digest
                for eff in req.trajectory.effects_by_status("confirmed")
            )

        def buggy_mutating_rule(req: GovernorInput, _params) -> bool:
            req.context.state["injected"] = True  # Must raise TypeError
            return False

        catalog = RuleCatalog(
            rule_types={
                "effect.no_duplicate": RuleTypeSpec(
                    allowed_phases=frozenset({"runtime"}),
                    params_model=EmptyRuleParams,
                    handler=block_duplicate_confirmed,
                ),
                "buggy.mutator": RuleTypeSpec(
                    allowed_phases=frozenset({"runtime"}),
                    params_model=EmptyRuleParams,
                    handler=buggy_mutating_rule,
                ),
            }
        )
        planned = PlannedEffect(
            tool_name="send_notification", parameters={"to": "ops@example.com"}
        )
        prior_effect = EffectRecord(
            effect_id="eff-000001",
            run_id="run-prev",
            policy_scope="scope.ops",
            action_index=1,
            tool_name="send_notification",
            operation_digest=planned.operation_digest(),
            status="confirmed",
        )
        prior_entry = TrajectoryEntry(
            sequence=1,
            kind="observed",
            effect_id="eff-000001",
            run_id="run-prev",
            policy_scope="scope.ops",
            action_index=1,
            tool_name="send_notification",
            operation_digest=planned.operation_digest(),
            status="confirmed",
        )
        trajectory = TrajectoryView(
            policy_scope="scope.ops",
            entries=[prior_entry],
            effects=[prior_effect],
            suspended=False,
        )

        dup_contract = self._v3_contract(
            rules=[
                {
                    "instance_id": "no-dup",
                    "rule_type": "effect.no_duplicate",
                    "phases": ["runtime"],
                }
            ]
        )
        req = GovernorInput(
            run_id="run-curr",
            contract=dup_contract,
            phase="runtime",
            policy=EnforcementPolicy(mode="guarded"),
            context=ExecutionContext(
                state={"tenant": "ops"}, available_tools=["send_notification"]
            ),
            action=ActionProposal(tool_name="send_notification"),
            host_facts=HostFacts(facts={"tenant": "ops"}),
            planned_effect=planned,
            policy_scope="scope.ops",
            trajectory=trajectory,
        )
        decision = DeterministicEvaluator(rule_catalog=catalog).evaluate(req)
        self.assertEqual(decision.decision, "block")
        self.assertEqual(decision.violations[0].rule, "no-dup")
        self.assertEqual(decision.violations[0].rule_type, "effect.no_duplicate")

        mut_contract = self._v3_contract(
            rules=[
                {
                    "instance_id": "mut-1",
                    "rule_type": "buggy.mutator",
                    "phases": ["runtime"],
                }
            ]
        )
        mut_req = req.model_copy(update={"contract": mut_contract})
        with self.assertRaises(TypeError):
            DeterministicEvaluator(rule_catalog=catalog).evaluate(mut_req)
        self.assertEqual(digest, "sha256:" + "b" * 64)


if __name__ == "__main__":
    unittest.main()
