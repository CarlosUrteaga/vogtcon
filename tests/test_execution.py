# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path

from vogtcon import (
    ActionProposal,
    AgentContract,
    ApprovalReuseError,
    CompensationRecord,
    ConcurrencyError,
    ContractRulesV2,
    ContractRulesV3,
    EffectGovernanceConfig,
    EffectObservationError,
    EffectResolutionError,
    EmptyRuleParams,
    EnforcementPolicy,
    ExecutionContext,
    GovernedToolExecutor,
    Governor,
    GovernorInput,
    GovernanceDecision,
    HostApproval,
    HostFacts,
    InMemoryEffectStore,
    JsonlDecisionLog,
    ObservationInput,
    ObservedEffect,
    PlannedEffect,
    ReconciliationError,
    ReconciliationRecord,
    RecordedEvent,
    ResolvedAction,
    RetrievedEvidence,
    RuleCatalog,
    RuleTypeSpec,
    RunEvent,
    RunEventV2,
    ScopeSuspendedError,
    Violation,
    WorkflowController,
    compute_v3_contract_fingerprint,
)

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def contract(mode: str = "guarded") -> AgentContract:
    return AgentContract.model_validate({
        "contract_id": "test.notify", "mode": mode,
        "approved_agent_configurations": ["agent-v1"],
        "declared_tools": ["send_notification"],
        "response_schema": {"required_fields": ["status"]},
        "memory_policy": "none",
        "validation_phases": "not_enforced" if mode == "no_contract" else ["pre_execution", "runtime", "post_execution"],
        "runtime_rules": ["tool.declared_only", "sensitive_requires_approval"],
        "postconditions": ["response.schema_complete"],
        "agent_feedback": {
            "advisory_warning_visibility": False,
            "guarded_denial_style": "minimal",
            "strict_replanning_after_violation": False,
        },
        "contract_fingerprint": "contract-v1",
    })


def v2_contract() -> ContractRulesV2:
    data = contract().model_dump()
    data.pop("mode")
    data.pop("agent_feedback")
    data["schema_version"] = 2
    return ContractRulesV2.model_validate(data)


def v3_contract() -> ContractRulesV3:
    draft = ContractRulesV3.model_validate({
        "schema_version": 3,
        "contract_id": "test.notify.v3",
        "approved_agent_configurations": ["agent-v1"],
        "declared_tools": ["send_notification"],
        "response_schema": {"required_fields": ["status"]},
        "memory_policy": "none",
        "validation_phases": ["pre_execution", "runtime", "post_execution"],
        "rules": [
            {
                "instance_id": "declared-tools",
                "rule_type": "tool.declared_only",
                "phases": ["runtime"],
            },
            {
                "instance_id": "response-schema",
                "rule_type": "response.schema_complete",
                "phases": ["post_execution"],
            },
        ],
        "contract_fingerprint": "sha256:placeholder",
    })
    fingerprint = compute_v3_contract_fingerprint(draft)
    return draft.model_copy(update={"contract_fingerprint": fingerprint})


def context(*, approval: bool = False, agent_fp: str = "agent-v1") -> ExecutionContext:
    return ExecutionContext.model_validate({
        "state": {"approval_granted": approval},
        "available_tools": ["send_notification"],
        "observed_agent_fingerprint": agent_fp,
        "observed_contract_fingerprint": "contract-v1",
    })


def action(*, sensitive: bool = True) -> ActionProposal:
    return ActionProposal(tool_name="send_notification", arguments={"sensitive": sensitive})


class ExecutorTests(unittest.TestCase):
    def test_gate_has_side_effect_only_for_allow_and_warning(self):
        for mode, expected, executed in (
            ("no_contract", "allow", True),
            ("advisory", "allow_with_warning", True),
            ("guarded", "block", False),
            ("strict", "abort", False),
        ):
            with self.subTest(mode=mode):
                calls = []
                request = GovernorInput(
                    run_id="run", contract=contract(mode), phase="runtime",
                    context=context(), action=action(),
                )
                outcome = GovernedToolExecutor(Governor()).execute(
                    request, lambda proposal: calls.append(proposal.tool_name) or "sent"
                )
                self.assertEqual(outcome.decision.decision, expected)
                self.assertEqual(outcome.executed, executed)
                self.assertEqual(calls, ["send_notification"] if executed else [])
                self.assertEqual(outcome.result, "sent" if executed else None)

    def test_evaluator_error_and_wrong_phase_never_call_tool(self):
        calls = []

        class BrokenEvaluator:
            def evaluate(self, _request):
                raise TimeoutError("judge timeout")

        gate = GovernedToolExecutor(Governor(evaluator=BrokenEvaluator()))
        runtime = GovernorInput(
            run_id="run", contract=contract(), phase="runtime",
            context=context(), action=action(),
        )
        with self.assertRaisesRegex(TimeoutError, "judge timeout"):
            gate.execute(runtime, lambda _proposal: calls.append("sent"))
        pre = GovernorInput(
            run_id="run", contract=contract(), phase="pre_execution", context=context()
        )
        with self.assertRaisesRegex(ValueError, "runtime action"):
            gate.execute(pre, lambda _proposal: calls.append("sent"))
        self.assertEqual(calls, [])

    def test_evaluator_cannot_mutate_executed_proposal_or_allow_violation(self):
        class MutatingEvaluator:
            def evaluate(self, request):
                request.action.arguments["sensitive"] = False
                return Governor().evaluate(request)

        request = GovernorInput(
            run_id="run", contract=contract(), phase="runtime",
            context=context(), action=action(),
        )
        seen = []
        with self.assertRaisesRegex(ValueError, "mutated the action"):
            GovernedToolExecutor(Governor(evaluator=MutatingEvaluator())).execute(
                request, lambda proposal: seen.append(proposal.arguments["sensitive"])
            )
        self.assertEqual(seen, [])
        self.assertEqual(request.action.arguments["sensitive"], True)

        class InconsistentEvaluator:
            def evaluate(self, request):
                real = Governor().evaluate(request)
                return real.model_copy(update={"decision": "allow"})

        with self.assertRaisesRegex(ValueError, "allowed a violating action"):
            GovernedToolExecutor(Governor(evaluator=InconsistentEvaluator())).execute(
                request, lambda _proposal: seen.append("sent")
            )
        self.assertEqual(seen, [])

    def test_governed_tool_executor_rejects_v3_contracts_while_standalone_governor_evaluates(self):
        v3 = v3_contract()
        ctx = _v3_context(v3)
        v3_request = GovernorInput(
            run_id="run-v3-legacy-exec",
            contract=v3,
            phase="runtime",
            policy=EnforcementPolicy(mode="guarded"),
            context=ctx,
            action=action(sensitive=False),
        )
        calls: list[str] = []
        with self.assertRaisesRegex(
            ValueError,
            "v3 contracts cannot be executed directly via GovernedToolExecutor",
        ):
            GovernedToolExecutor(Governor()).execute(
                v3_request, lambda _proposal: calls.append("sent")
            )
        self.assertEqual(calls, [])

        # Standalone Governor.evaluate() for v3 remains intact
        allowed = Governor().evaluate(v3_request)
        self.assertEqual(allowed.decision, "allow")
        self.assertEqual(allowed.violations, [])

        blocked_req = GovernorInput(
            run_id="run-v3-legacy-exec-block",
            contract=v3,
            phase="runtime",
            policy=EnforcementPolicy(mode="guarded"),
            context=ctx,
            action=ActionProposal(tool_name="undeclared_tool"),
        )
        blocked = Governor().evaluate(blocked_req)
        self.assertEqual(blocked.decision, "block")
        self.assertEqual([v.rule for v in blocked.violations], ["declared-tools"])


class ControllerTests(unittest.TestCase):
    def test_factory_loads_v1_and_v2_with_the_same_gate(self):
        for filename, policy in (
            ("notification_contract.yaml", None),
            ("notification_contract_v2.yaml", EnforcementPolicy(mode="guarded")),
        ):
            with self.subTest(filename=filename):
                controller = WorkflowController.from_contract_path(
                    EXAMPLES / filename, "factory-run", policy=policy,
                )
                trusted = ExecutionContext(
                    state={"approval_granted": False},
                    available_tools=["send_notification"],
                    observed_agent_fingerprint="notification-agent-v1",
                    observed_contract_fingerprint=controller.contract.contract_fingerprint,
                )
                self.assertEqual(controller.begin(trusted).violations, [])
                effects = []
                outcome = controller.execute(
                    ActionProposal(
                        tool_name="send_notification",
                        arguments={"message": "hello", "sensitive": True},
                    ), trusted, lambda _proposal: effects.append("sent"),
                )
                self.assertEqual(outcome.decision.decision, "block")
                self.assertFalse(outcome.executed)
                self.assertEqual(effects, [])
                self.assertEqual(controller.finish(trusted, {"status": "blocked"}).violations, [])

    def test_factory_preserves_configuration_errors(self):
        with self.assertRaisesRegex(ValueError, "require an enforcement policy"):
            WorkflowController.from_contract_path(
                EXAMPLES / "notification_contract_v2.yaml", "run",
            )
        with self.assertRaisesRegex(ValueError, "conflicts with legacy"):
            WorkflowController.from_contract_path(
                EXAMPLES / "notification_contract.yaml", "run",
                policy=EnforcementPolicy(mode="advisory"),
            )
        with self.assertRaisesRegex(ValueError, "run_id must be nonempty"):
            WorkflowController.from_contract_path(
                EXAMPLES / "notification_contract_v2.yaml", "",
                policy=EnforcementPolicy(mode="guarded"),
            )
        with self.assertRaises(FileNotFoundError):
            WorkflowController.from_contract_path(
                EXAMPLES / "absent.yaml", "run",
                policy=EnforcementPolicy(mode="guarded"),
            )
        with self.assertRaisesRegex(ValueError, "Unsupported runtime_rules"):
            WorkflowController.from_contract_path(
                EXAMPLES / "custom_contract.yaml", "run",
                policy=EnforcementPolicy(mode="guarded"),
            )

    def test_factory_uses_custom_rule_for_loading_and_evaluation(self):
        catalog = RuleCatalog(runtime_rules={
            "note.public_requires_approval": lambda request: (
                request.action is not None
                and request.action.arguments.get("public") is True
                and request.context.state.get("approval_granted") is not True
            ),
        })
        controller = WorkflowController.from_contract_path(
            EXAMPLES / "custom_contract.yaml", "custom-rule",
            policy=EnforcementPolicy(mode="guarded"), rule_catalog=catalog,
        )
        trusted = ExecutionContext(
            state={"approval_granted": False}, available_tools=["save_note"],
            observed_agent_fingerprint="pydantic-note-agent-v1",
            observed_contract_fingerprint=controller.contract.contract_fingerprint,
        )
        self.assertEqual(controller.begin(trusted).violations, [])
        effects = []
        outcome = controller.execute(
            ActionProposal(tool_name="save_note", arguments={"text": "note", "public": True}),
            trusted, lambda _proposal: effects.append("saved"),
        )
        self.assertEqual(outcome.decision.decision, "block")
        self.assertEqual(
            [violation.rule for violation in outcome.decision.violations],
            ["note.public_requires_approval"],
        )
        self.assertEqual(effects, [])

    def test_v2_requires_policy_and_legacy_rejects_conflict(self):
        with self.assertRaisesRegex(ValueError, "require an enforcement policy"):
            WorkflowController(Governor(), "run", v2_contract())
        with self.assertRaisesRegex(ValueError, "conflicts with legacy"):
            WorkflowController(
                Governor(), "run", contract(),
                policy=EnforcementPolicy(mode="advisory"),
            )
        versioned_legacy = AgentContract.model_validate({
            **contract().model_dump(), "schema_version": 2,
        })
        with self.assertRaisesRegex(ValueError, "schema_version"):
            WorkflowController(Governor(), "run", versioned_legacy)

    def test_v2_policy_controls_gate_and_run_state(self):
        for mode, expected, executed in (
            ("no_contract", "allow", True),
            ("advisory", "allow_with_warning", True),
            ("guarded", "block", False),
            ("strict", "abort", False),
        ):
            with self.subTest(mode=mode):
                controller = WorkflowController(
                    Governor(), "run", v2_contract(),
                    policy=EnforcementPolicy(mode=mode),
                )
                self.assertEqual(controller.begin(context()).violations, [])
                effects = []
                outcome = controller.execute(
                    action(), context(), lambda _a: effects.append("sent"),
                )
                self.assertEqual(outcome.decision.decision, expected)
                self.assertEqual(outcome.executed, executed)
                self.assertEqual(effects, ["sent"] if executed else [])
                self.assertEqual(controller.state, "aborted" if mode == "strict" else "active")
                if mode != "strict":
                    self.assertEqual(controller.finish(context(), {"status": "ok"}).violations, [])
                    self.assertEqual(controller.state, "finished")

    def test_v2_strict_pre_and_post_violations_change_run_state(self):
        policy = EnforcementPolicy(mode="strict")
        pre = WorkflowController(Governor(), "pre", v2_contract(), policy=policy)
        self.assertEqual(
            [v.rule for v in pre.begin(context(agent_fp="other")).violations],
            ["agent.configuration_fingerprint_match"],
        )
        self.assertEqual(pre.state, "aborted")
        post = WorkflowController(Governor(), "post", v2_contract(), policy=policy)
        post.begin(context())
        self.assertEqual(
            [v.rule for v in post.finish(context(), {}).violations],
            ["response.schema_complete"],
        )
        self.assertEqual(post.state, "failed_post")

    def test_guarded_replan_and_post_check(self):
        controller = WorkflowController(Governor(), "run-1", contract())
        self.assertEqual(controller.state, "new")
        self.assertEqual(controller.begin(context()).violations, [])
        effects = []
        blocked = controller.execute(action(), context(), lambda _a: effects.append("sent"))
        self.assertEqual(blocked.decision.decision, "block")
        self.assertFalse(blocked.executed)
        self.assertEqual(controller.state, "active")
        allowed = controller.execute(
            action(), context(approval=True), lambda _a: effects.append("sent")
        )
        self.assertTrue(allowed.executed)
        self.assertEqual(effects, ["sent"])
        post = controller.finish(context(approval=True), {"status": "ok"})
        self.assertEqual(post.violations, [])
        self.assertEqual(controller.state, "finished")
        with self.assertRaises(RuntimeError):
            controller.execute(action(), context(), lambda _a: effects.append("again"))
        self.assertEqual(effects, ["sent"])

    def test_strict_pre_and_runtime_abort(self):
        pre_controller = WorkflowController(Governor(), "pre", contract("strict"))
        pre = pre_controller.begin(context(agent_fp="other"))
        self.assertEqual([v.rule for v in pre.violations], ["agent.configuration_fingerprint_match"])
        self.assertEqual(pre_controller.state, "aborted")
        with self.assertRaises(RuntimeError):
            pre_controller.execute(action(), context(), lambda _a: None)

        runtime_controller = WorkflowController(Governor(), "runtime", contract("strict"))
        runtime_controller.begin(context())
        calls = []
        runtime = runtime_controller.execute(action(), context(), lambda _a: calls.append("sent"))
        self.assertEqual(runtime.decision.decision, "abort")
        self.assertFalse(runtime.executed)
        self.assertEqual(runtime_controller.state, "aborted")
        self.assertEqual(calls, [])

    def test_strict_stops_after_external_evaluator_blocks_with_violation(self):
        class BlockingEvaluator:
            def evaluate(self, request):
                if request.phase == "runtime":
                    return GovernanceDecision(
                        phase="runtime", decision="block",
                        violations=[Violation(
                            rule="custom.block", phase="runtime",
                            action=request.action.tool_name,
                        )],
                    )
                return GovernanceDecision(phase=request.phase, violations=[])

        controller = WorkflowController(
            Governor(evaluator=BlockingEvaluator()), "run", contract("strict")
        )
        controller.begin(context())
        effects = []
        outcome = controller.execute(action(), context(), lambda _a: effects.append("sent"))
        self.assertEqual(outcome.decision.decision, "block")
        self.assertFalse(outcome.executed)
        self.assertEqual(controller.state, "aborted")
        with self.assertRaisesRegex(RuntimeError, "Run is not active"):
            controller.execute(action(), context(), lambda _a: effects.append("again"))
        self.assertEqual(effects, [])

    def test_contract_snapshot_and_post_failure_do_not_undo_effects(self):
        source = contract("strict")
        controller = WorkflowController(Governor(), "run", source)
        source.declared_tools.clear()
        controller.contract.declared_tools.clear()
        controller.begin(context())
        effects = []
        self.assertTrue(controller.execute(
            action(sensitive=False), context(), lambda _a: effects.append("sent")
        ).executed)
        post = controller.finish(context(), {})
        self.assertEqual([v.rule for v in post.violations], ["response.schema_complete"])
        self.assertEqual(controller.state, "failed_post")
        self.assertEqual(effects, ["sent"])

    def test_phase_order_and_evaluator_error_fail_closed(self):
        controller = WorkflowController(Governor(), "run", contract())
        with self.assertRaises(RuntimeError):
            controller.execute(action(), context(), lambda _a: None)
        with self.assertRaises(RuntimeError):
            controller.finish(context(), {"status": "ok"})

        class BrokenEvaluator:
            def evaluate(self, request):
                if request.phase == "runtime":
                    raise TimeoutError("cannot evaluate")
                return Governor().evaluate(request)

        controller = WorkflowController(Governor(evaluator=BrokenEvaluator()), "run", contract())
        controller.begin(context())
        effects = []
        with self.assertRaises(TimeoutError):
            controller.execute(action(), context(), lambda _a: effects.append("sent"))
        self.assertEqual(controller.state, "aborted")
        self.assertEqual(effects, [])

    def test_v3_contracts_require_policy_and_effect_governance(self):
        recorded: list[RecordedEvent] = []
        effects: list[str] = []

        class ListRecorder:
            def record(self, event: RecordedEvent) -> None:
                recorded.append(event)

        class SimpleResolver:
            def resolve(
                self, proposal: ActionProposal, ctx: ExecutionContext
            ) -> ResolvedAction:
                return ResolvedAction(
                    planned_effect=PlannedEffect(
                        tool_name=proposal.tool_name,
                        parameters=dict(proposal.arguments),
                    ),
                    host_facts=HostFacts(facts=dict(ctx.state)),
                )

        class SimpleObserver:
            def observe(
                self, observation: ObservationInput, *, tool_result=None
            ) -> ObservedEffect:
                return ObservedEffect(status="confirmed", evidence_ref="evt-1")

        v3 = v3_contract()
        recorder = ListRecorder()

        with self.assertRaisesRegex(ValueError, "v3 contracts require an enforcement policy"):
            WorkflowController(Governor(), "run-v3-no-policy", v3, recorder=recorder)

        with self.assertRaisesRegex(
            ValueError,
            "v3 contracts require explicit effect_governance configuration",
        ):
            WorkflowController(
                Governor(),
                "run-v3-no-eg",
                v3,
                recorder=recorder,
                policy=EnforcementPolicy(mode="guarded"),
            )

        with self.assertRaisesRegex(
            TypeError, "effect_governance must be an EffectGovernanceConfig or None"
        ):
            WorkflowController(
                Governor(),
                "run-v3-bad-eg",
                v3,
                policy=EnforcementPolicy(mode="guarded"),
                effect_governance="invalid",  # type: ignore[arg-type]
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            v3_path = Path(tmpdir) / "contract_v3.json"
            v3_path.write_text(json.dumps(v3.model_dump(mode="json")), encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError,
                "v3 contracts require explicit effect_governance configuration",
            ):
                WorkflowController.from_contract_path(
                    v3_path,
                    "run-v3-path",
                    policy=EnforcementPolicy(mode="guarded"),
                    recorder=recorder,
                )

            self.assertEqual(recorded, [])
            self.assertEqual(effects, [])

            store = InMemoryEffectStore()
            cfg = EffectGovernanceConfig(
                store=store,
                resolver=SimpleResolver(),
                observer=SimpleObserver(),
                policy_scope="scope.v3",
            )
            controller = WorkflowController.from_contract_path(
                v3_path,
                "run-v3-ok",
                policy=EnforcementPolicy(mode="guarded"),
                recorder=recorder,
                effect_governance=cfg,
            )
            ctx = ExecutionContext(
                state={"approval_granted": True},
                available_tools=["send_notification"],
                observed_agent_fingerprint="agent-v1",
                observed_contract_fingerprint=v3.contract_fingerprint,
            )
            self.assertEqual(controller.begin(ctx).violations, [])
            outcome = controller.execute(
                action(sensitive=False),
                ctx,
                lambda _p: effects.append("sent") or "ok",
            )
            self.assertTrue(outcome.executed)
            self.assertEqual(outcome.result, "ok")
            self.assertIsNotNone(outcome.effect)
            assert outcome.effect is not None
            self.assertEqual(outcome.effect.status, "confirmed")
            self.assertEqual(controller.finish(ctx, {"status": "ok"}).violations, [])
            self.assertEqual(controller.state, "finished")
            self.assertEqual(effects, ["sent"])
            self.assertTrue(all(isinstance(ev, RunEventV2) for ev in recorded))


class _CallbackResolver:
    def __init__(self, fn):
        self._fn = fn

    def resolve(self, proposal: ActionProposal, ctx: ExecutionContext) -> ResolvedAction:
        return self._fn(proposal, ctx)


class _CallbackObserver:
    def __init__(self, fn):
        self._fn = fn

    def observe(self, observation: ObservationInput, *, tool_result=None) -> ObservedEffect:
        return self._fn(observation, tool_result)


def _v3_context(v3: ContractRulesV3, *, state: dict | None = None) -> ExecutionContext:
    return ExecutionContext(
        state=state if state is not None else {"approval_granted": True},
        available_tools=["send_notification"],
        observed_agent_fingerprint="agent-v1",
        observed_contract_fingerprint=v3.contract_fingerprint,
    )


class GovernedEffectExecutionTests(unittest.TestCase):
    def _default_resolver(self, *, policy_scope: str | None = None):
        return _CallbackResolver(
            lambda proposal, ctx: ResolvedAction(
                planned_effect=PlannedEffect(
                    tool_name=proposal.tool_name,
                    parameters={"recipient": "ops@example.com"},
                    defaults={"channel": "email"},
                ),
                host_facts=HostFacts(facts=dict(ctx.state)),
                policy_scope=policy_scope,
            )
        )

    def test_nominal_v3_and_v2_governed_runs_record_all_observed_statuses(self):
        v3 = v3_contract()
        v2 = v2_contract()
        for label, ctr, ctx_fp in (
            ("v3", v3, v3.contract_fingerprint),
            ("v2", v2, v2.contract_fingerprint),
        ):
            for obs_status in ("confirmed", "confirmed_absent", "uncertain"):
                with self.subTest(contract=label, status=obs_status):
                    store = InMemoryEffectStore()
                    with tempfile.TemporaryDirectory() as tmpdir:
                        log = JsonlDecisionLog(Path(tmpdir) / "events.jsonl")
                        cfg = EffectGovernanceConfig(
                            store=store,
                            resolver=self._default_resolver(),
                            observer=_CallbackObserver(
                                lambda _in, _res, st=obs_status: ObservedEffect(
                                    status=st, evidence_ref=f"ref-{st}"
                                )
                            ),
                            policy_scope="scope.nominal",
                        )
                        controller = WorkflowController(
                            Governor(),
                            f"run-{label}-{obs_status}",
                            ctr,
                            recorder=log,
                            policy=EnforcementPolicy(mode="guarded"),
                            effect_governance=cfg,
                        )
                        ctx = ExecutionContext(
                            state={"approval_granted": True},
                            available_tools=["send_notification"],
                            observed_agent_fingerprint="agent-v1",
                            observed_contract_fingerprint=ctx_fp,
                        )
                        self.assertEqual(controller.begin(ctx).violations, [])
                        outcome = controller.execute(
                            action(sensitive=False), ctx, lambda _p: "sent"
                        )
                        self.assertTrue(outcome.executed)
                        self.assertIsNotNone(outcome.effect)
                        assert outcome.effect is not None
                        self.assertEqual(outcome.effect.status, obs_status)
                        self.assertEqual(outcome.effect.evidence_ref, f"ref-{obs_status}")
                        self.assertEqual(
                            store.is_scope_suspended("scope.nominal"),
                            obs_status == "uncertain",
                        )
                        self.assertEqual(controller.state, "active")
                        events = log.read()
                        self.assertEqual(
                            [ev.event_type for ev in events],
                            ["decision", "decision", "tool_completed", "effect_observed"],
                        )
                        self.assertTrue(all(isinstance(ev, RunEventV2) for ev in events))

    def test_failure_point_matrix_fail_closed_and_secret_free(self):
        v3 = v3_contract()
        ctx = _v3_context(v3)
        secret_resolver = "SECRET_RESOLVER_VALUE_901"
        secret_observer = "SECRET_OBSERVER_VALUE_902"

        # 1. Resolver exception -> EffectResolutionError (secret suppressed), aborted, no call
        store = InMemoryEffectStore()
        calls: list[str] = []
        controller = WorkflowController(
            Governor(),
            "run-res-err",
            v3,
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=EffectGovernanceConfig(
                store=store,
                resolver=_CallbackResolver(
                    lambda _a, _c: (_ for _ in ()).throw(RuntimeError(secret_resolver))
                ),
                observer=_CallbackObserver(lambda _i, _r: ObservedEffect(status="confirmed")),
                policy_scope="scope.f1",
            ),
        )
        controller.begin(ctx)
        with self.assertRaises(EffectResolutionError) as err_ctx:
            controller.execute(action(), ctx, lambda _a: calls.append("called"))
        self.assertNotIn(secret_resolver, str(err_ctx.exception))
        self.assertIsNone(err_ctx.exception.__cause__)
        self.assertTrue(err_ctx.exception.__suppress_context__)
        self.assertEqual(controller.state, "aborted")
        self.assertEqual(calls, [])
        self.assertEqual(store.snapshot("scope.f1").entries, ())

        # 2. Resolver returns invalid non-ResolvedAction -> EffectResolutionError, aborted
        controller = WorkflowController(
            Governor(),
            "run-res-bad",
            v3,
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=EffectGovernanceConfig(
                store=InMemoryEffectStore(),
                resolver=_CallbackResolver(lambda _a, _c: {"not": "resolved"}),
                observer=_CallbackObserver(lambda _i, _r: ObservedEffect(status="confirmed")),
            ),
        )
        controller.begin(ctx)
        with self.assertRaisesRegex(EffectResolutionError, "invalid output"):
            controller.execute(action(), ctx, lambda _a: calls.append("called"))
        self.assertEqual(controller.state, "aborted")
        self.assertEqual(calls, [])

        # 3. Scope conflict between config and resolver -> ValueError, aborted
        controller = WorkflowController(
            Governor(),
            "run-scope-conflict",
            v3,
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=EffectGovernanceConfig(
                store=InMemoryEffectStore(),
                resolver=self._default_resolver(policy_scope="scope.other"),
                observer=_CallbackObserver(lambda _i, _r: ObservedEffect(status="confirmed")),
                policy_scope="scope.cfg",
            ),
        )
        controller.begin(ctx)
        with self.assertRaisesRegex(ValueError, "Resolved policy_scope conflicts"):
            controller.execute(action(), ctx, lambda _a: calls.append("called"))
        self.assertEqual(controller.state, "aborted")
        self.assertEqual(calls, [])

        # 4. Evaluator block (guarded) and abort (strict): no reservation, no tool call
        for mode, expected_decision, expected_state in (
            ("guarded", "block", "active"),
            ("strict", "abort", "aborted"),
        ):
            with self.subTest(mode=mode):
                store = InMemoryEffectStore()
                recorded: list[RecordedEvent] = []

                class Rec:
                    def record(self, ev: RecordedEvent) -> None:
                        recorded.append(ev)

                controller = WorkflowController(
                    Governor(),
                    f"run-deny-{mode}",
                    v3,
                    recorder=Rec(),
                    policy=EnforcementPolicy(mode=mode),
                    effect_governance=EffectGovernanceConfig(
                        store=store,
                        resolver=self._default_resolver(),
                        observer=_CallbackObserver(lambda _i, _r: ObservedEffect(status="confirmed")),
                        policy_scope="scope.deny",
                    ),
                )
                controller.begin(ctx)
                outcome = controller.execute(
                    ActionProposal(tool_name="undeclared_tool"),
                    ctx,
                    lambda _a: calls.append("called"),
                )
                self.assertFalse(outcome.executed)
                self.assertIsNone(outcome.effect)
                self.assertEqual(outcome.decision.decision, expected_decision)
                self.assertEqual(controller.state, expected_state)
                self.assertEqual(store.snapshot("scope.deny").entries, ())
                self.assertEqual(calls, [])
                self.assertEqual(len(recorded), 2)
                self.assertIsNone(recorded[1].effect_id)

        # 5. Pre-invocation recorder failure -> marks confirmed_absent, aborts, tool NEVER called
        store = InMemoryEffectStore()
        rec_calls = 0

        class FailSecondRecorder:
            def record(self, _ev: RecordedEvent) -> None:
                nonlocal rec_calls
                rec_calls += 1
                if rec_calls == 2:
                    raise OSError("disk full")

        controller = WorkflowController(
            Governor(),
            "run-pre-rec-fail",
            v3,
            recorder=FailSecondRecorder(),
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=EffectGovernanceConfig(
                store=store,
                resolver=self._default_resolver(),
                observer=_CallbackObserver(lambda _i, _r: ObservedEffect(status="confirmed")),
                policy_scope="scope.recfail",
            ),
        )
        controller.begin(ctx)
        with self.assertRaisesRegex(OSError, "disk full"):
            controller.execute(action(), ctx, lambda _a: calls.append("called"))
        self.assertEqual(calls, [])
        self.assertEqual(controller.state, "aborted")
        snap = store.snapshot("scope.recfail")
        self.assertEqual(len(snap.effects), 1)
        self.assertEqual(snap.effects[0].status, "confirmed_absent")
        self.assertEqual(snap.effects[0].evidence_ref, "pre_invocation_record_failed")
        self.assertFalse(snap.suspended)

        # 6 & 7. Tool exception + observer uncertain vs confirmed_absent
        for obs_status, expected_suspended in (
            ("uncertain", True),
            ("confirmed_absent", False),
        ):
            with self.subTest(tool_error_obs=obs_status):
                store = InMemoryEffectStore()
                recorded: list[RecordedEvent] = []

                class Rec:
                    def record(self, ev: RecordedEvent) -> None:
                        recorded.append(ev)

                controller = WorkflowController(
                    Governor(),
                    f"run-tool-err-{obs_status}",
                    v3,
                    recorder=Rec(),
                    policy=EnforcementPolicy(mode="guarded"),
                    effect_governance=EffectGovernanceConfig(
                        store=store,
                        resolver=self._default_resolver(),
                        observer=_CallbackObserver(
                            lambda obs_in, _res, st=obs_status: (
                                self.assertEqual(obs_in.invocation_outcome, "raised")
                                or self.assertEqual(obs_in.error_type, "RuntimeError")
                                or ObservedEffect(status=st, evidence_ref="err-check")
                            )
                        ),
                        policy_scope="scope.toolerr",
                    ),
                )
                controller.begin(ctx)
                with self.assertRaisesRegex(RuntimeError, "network timeout"):
                    controller.execute(
                        action(),
                        ctx,
                        lambda _a: (_ for _ in ()).throw(RuntimeError("network timeout")),
                    )
                self.assertEqual(
                    store.is_scope_suspended("scope.toolerr"), expected_suspended
                )
                self.assertEqual(controller.state, "active")
                self.assertEqual(
                    [ev.event_type for ev in recorded],
                    ["decision", "decision", "tool_error", "effect_observed"],
                )

        # 8. Tool exception + observer raises -> forces uncertain, re-raises tool error
        store = InMemoryEffectStore()
        controller = WorkflowController(
            Governor(),
            "run-tool-and-obs-err",
            v3,
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=EffectGovernanceConfig(
                store=store,
                resolver=self._default_resolver(),
                observer=_CallbackObserver(
                    lambda _i, _r: (_ for _ in ()).throw(ValueError(secret_observer))
                ),
                policy_scope="scope.botherr",
            ),
        )
        controller.begin(ctx)
        with self.assertRaisesRegex(RuntimeError, "downstream boom"):
            controller.execute(
                action(),
                ctx,
                lambda _a: (_ for _ in ()).throw(RuntimeError("downstream boom")),
            )
        self.assertTrue(store.is_scope_suspended("scope.botherr"))
        self.assertEqual(store.snapshot("scope.botherr").effects[0].evidence_ref, "observer_error")

        # 9. Tool returns + observer raises -> marks uncertain, suspends, EffectObservationError secret-free
        store = InMemoryEffectStore()
        recorded = []

        class Rec2:
            def record(self, ev: RecordedEvent) -> None:
                recorded.append(ev)

        controller = WorkflowController(
            Governor(),
            "run-obs-err",
            v3,
            recorder=Rec2(),
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=EffectGovernanceConfig(
                store=store,
                resolver=self._default_resolver(),
                observer=_CallbackObserver(
                    lambda _i, _r: (_ for _ in ()).throw(RuntimeError(secret_observer))
                ),
                policy_scope="scope.obserr",
            ),
        )
        controller.begin(ctx)
        with self.assertRaises(EffectObservationError) as obs_err_ctx:
            controller.execute(action(), ctx, lambda _a: "returned-ok")
        self.assertNotIn(secret_observer, str(obs_err_ctx.exception))
        self.assertIsNone(obs_err_ctx.exception.__cause__)
        self.assertTrue(obs_err_ctx.exception.__suppress_context__)
        self.assertTrue(store.is_scope_suspended("scope.obserr"))
        self.assertEqual(
            [ev.event_type for ev in recorded],
            ["decision", "decision", "tool_completed", "effect_observed"],
        )

        # 10. Post-invocation recorder failure -> store keeps confirmed record, aborts
        store = InMemoryEffectStore()
        post_calls = 0

        class FailThirdRecorder:
            def record(self, _ev: RecordedEvent) -> None:
                nonlocal post_calls
                post_calls += 1
                if post_calls == 3:
                    raise OSError("post-record fail")

        controller = WorkflowController(
            Governor(),
            "run-post-rec-fail",
            v3,
            recorder=FailThirdRecorder(),
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=EffectGovernanceConfig(
                store=store,
                resolver=self._default_resolver(),
                observer=_CallbackObserver(
                    lambda _i, _r: ObservedEffect(status="confirmed", evidence_ref="ok-1")
                ),
                policy_scope="scope.postrec",
            ),
        )
        controller.begin(ctx)
        with self.assertRaisesRegex(OSError, "post-record fail"):
            controller.execute(action(), ctx, lambda _a: "done")
        self.assertEqual(controller.state, "aborted")
        self.assertEqual(store.snapshot("scope.postrec").effects[0].status, "confirmed")

    def test_advisory_mode_preserves_warning_semantics_and_distinct_scope_suspension(self):
        v3 = v3_contract()
        ctx = _v3_context(v3)
        store = InMemoryEffectStore()
        statuses = iter(["uncertain", "confirmed"])
        controller = WorkflowController(
            Governor(),
            "run-advisory",
            v3,
            policy=EnforcementPolicy(mode="advisory"),
            effect_governance=EffectGovernanceConfig(
                store=store,
                resolver=self._default_resolver(),
                observer=_CallbackObserver(
                    lambda _i, _r: ObservedEffect(status=next(statuses))
                ),
                policy_scope="scope.adv",
            ),
        )
        controller.begin(ctx)
        # Undeclared tool triggers advisory allow_with_warning and still executes
        outcome = controller.execute(
            ActionProposal(tool_name="undeclared_tool"), ctx, lambda _a: "warned"
        )
        self.assertTrue(outcome.executed)
        self.assertEqual(outcome.decision.decision, "allow_with_warning")
        self.assertEqual([v.rule for v in outcome.decision.violations], ["declared-tools"])
        assert outcome.effect is not None
        self.assertEqual(outcome.effect.status, "uncertain")

        # Subsequent call in the suspended scope raises ScopeSuspendedError even in advisory mode
        with self.assertRaises(ScopeSuspendedError) as susp:
            controller.execute(action(), ctx, lambda _a: "should-not-run")
        self.assertEqual(susp.exception.policy_scope, "scope.adv")
        self.assertEqual(susp.exception.uncertain_effect_ids, (outcome.effect.effect_id,))

    def test_reentrant_calls_raise_concurrency_error_without_corrupting_outer_op(self):
        v3 = v3_contract()
        ctx = _v3_context(v3)
        store = InMemoryEffectStore()
        reentrant_errors: list[str] = []
        controller_ref: list[WorkflowController] = []

        def resolver_fn(proposal: ActionProposal, c: ExecutionContext) -> ResolvedAction:
            try:
                controller_ref[0].execute(proposal, c, lambda _a: "nested")
            except ConcurrencyError:
                reentrant_errors.append("resolver")
            return ResolvedAction(
                planned_effect=PlannedEffect(tool_name=proposal.tool_name),
                host_facts=HostFacts(facts=dict(c.state)),
            )

        def observer_fn(_in: ObservationInput, _res) -> ObservedEffect:
            try:
                controller_ref[0].finish(ctx, {"status": "nested"})
            except ConcurrencyError:
                reentrant_errors.append("observer")
            return ObservedEffect(status="confirmed", evidence_ref="ok")

        controller = WorkflowController(
            Governor(),
            "run-reentrant",
            v3,
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=EffectGovernanceConfig(
                store=store,
                resolver=_CallbackResolver(resolver_fn),
                observer=_CallbackObserver(observer_fn),
                policy_scope="scope.seq",
            ),
        )
        controller_ref.append(controller)
        controller.begin(ctx)

        def tool_fn(_p: ActionProposal) -> str:
            try:
                controller.execute(action(), ctx, lambda _a: "nested-tool")
            except ConcurrencyError:
                reentrant_errors.append("tool")
            return "outer-ok"

        outcome = controller.execute(action(), ctx, tool_fn)
        self.assertTrue(outcome.executed)
        self.assertEqual(outcome.result, "outer-ok")
        self.assertEqual(reentrant_errors, ["resolver", "tool", "observer"])
        self.assertEqual(controller.finish(ctx, {"status": "ok"}).violations, [])
        self.assertEqual(controller.state, "finished")


class ScopeSuspensionTests(unittest.TestCase):
    def test_scoped_suspension_isolates_scopes_and_persists_across_runs(self):
        v3 = v3_contract()
        ctx = _v3_context(v3)
        store = InMemoryEffectStore()

        def resolve_by_arg(proposal: ActionProposal, c: ExecutionContext) -> ResolvedAction:
            scope = proposal.arguments.get("scope")
            assert isinstance(scope, str)
            return ResolvedAction(
                planned_effect=PlannedEffect(
                    tool_name=proposal.tool_name,
                    parameters={"scope": scope},
                ),
                host_facts=HostFacts(facts=dict(c.state)),
                policy_scope=scope,
            )

        observe_outcomes = {"scope.a": "uncertain", "scope.b": "confirmed"}
        cfg = EffectGovernanceConfig(
            store=store,
            resolver=_CallbackResolver(resolve_by_arg),
            observer=_CallbackObserver(
                lambda obs_in, _res: ObservedEffect(
                    status=observe_outcomes[obs_in.policy_scope or "scope.a"],
                    evidence_ref=f"obs-{obs_in.policy_scope}",
                )
            ),
        )
        c1 = WorkflowController(
            Governor(),
            "run-1",
            v3,
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=cfg,
        )
        c1.begin(ctx)

        out_a = c1.execute(
            ActionProposal(tool_name="send_notification", arguments={"scope": "scope.a"}),
            ctx,
            lambda _p: "a",
        )
        assert out_a.effect is not None
        self.assertEqual(out_a.effect.status, "uncertain")
        self.assertEqual(c1.state, "active")

        # Scope A is suspended
        with self.assertRaises(ScopeSuspendedError) as exc_a:
            c1.execute(
                ActionProposal(tool_name="send_notification", arguments={"scope": "scope.a"}),
                ctx,
                lambda _p: "a2",
            )
        self.assertEqual(exc_a.exception.policy_scope, "scope.a")

        # Scope B is unaffected and executes cleanly
        out_b = c1.execute(
            ActionProposal(tool_name="send_notification", arguments={"scope": "scope.b"}),
            ctx,
            lambda _p: "b",
        )
        self.assertTrue(out_b.executed)
        assert out_b.effect is not None
        self.assertEqual(out_b.effect.status, "confirmed")

        # Second controller with a different run_id sharing store sees Scope A suspended (INV-11)
        observed_trajectories: list[int] = []
        catalog = RuleCatalog(
            rule_types={
                "custom.count_check": RuleTypeSpec(
                    allowed_phases=frozenset({"runtime"}),
                    params_model=EmptyRuleParams,
                    handler=lambda req, _params: (
                        observed_trajectories.append(
                            len(req.trajectory.effects) if req.trajectory is not None else -1
                        )
                        and False
                    ),
                )
            }
        )
        draft_v3 = ContractRulesV3.model_validate({
            **v3.model_dump(mode="json"),
            "rules": [
                {
                    "instance_id": "declared-tools",
                    "rule_type": "tool.declared_only",
                    "phases": ["runtime"],
                },
                {
                    "instance_id": "traj-observer",
                    "rule_type": "custom.count_check",
                    "phases": ["runtime"],
                },
                {
                    "instance_id": "response-schema",
                    "rule_type": "response.schema_complete",
                    "phases": ["post_execution"],
                },
            ],
            "contract_fingerprint": "sha256:placeholder",
        })
        custom_v3 = draft_v3.model_copy(
            update={
                "contract_fingerprint": compute_v3_contract_fingerprint(
                    draft_v3, rule_catalog=catalog
                )
            }
        )
        c2 = WorkflowController(
            Governor(rule_catalog=catalog),
            "run-2",
            custom_v3,
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=EffectGovernanceConfig(
                store=store,
                resolver=_CallbackResolver(resolve_by_arg),
                observer=_CallbackObserver(
                    lambda _in, _res: ObservedEffect(status="confirmed", evidence_ref="obs-2")
                ),
            ),
        )
        c2_ctx = _v3_context(custom_v3)
        c2.begin(c2_ctx)
        with self.assertRaises(ScopeSuspendedError):
            c2.execute(
                ActionProposal(tool_name="send_notification", arguments={"scope": "scope.a"}),
                c2_ctx,
                lambda _p: "blocked-by-suspension",
            )

        # Host reconciles Scope A via c2; Scope A recovers and c2 sees Scope A history
        reconciled = c2.reconcile(
            ReconciliationRecord(
                effect_id=out_a.effect.effect_id,
                resolved_status="confirmed",
                evidence_ref="host-audit-a",
                policy_scope="scope.a",
            )
        )
        self.assertEqual(reconciled.status, "confirmed")
        out_a2 = c2.execute(
            ActionProposal(tool_name="send_notification", arguments={"scope": "scope.a"}),
            c2_ctx,
            lambda _p: "a-recovered",
        )
        self.assertTrue(out_a2.executed)
        self.assertEqual(observed_trajectories, [1])

    def test_undelimited_uncertainty_suspends_controller_until_reconcile(self):
        v3 = v3_contract()
        ctx = _v3_context(v3)
        store = InMemoryEffectStore()
        controller = WorkflowController(
            Governor(),
            "run-undelimited",
            v3,
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=EffectGovernanceConfig(
                store=store,
                resolver=_CallbackResolver(
                    lambda proposal, c: ResolvedAction(
                        planned_effect=PlannedEffect(tool_name=proposal.tool_name),
                        host_facts=HostFacts(facts=dict(c.state)),
                    )
                ),
                observer=_CallbackObserver(
                    lambda _in, _res: ObservedEffect(status="uncertain")
                ),
                policy_scope=None,
            ),
        )
        controller.begin(ctx)
        out = controller.execute(action(), ctx, lambda _p: "maybe")
        assert out.effect is not None
        self.assertEqual(controller.state, "suspended")

        with self.assertRaises(ScopeSuspendedError):
            controller.execute(action(), ctx, lambda _p: "blocked")
        with self.assertRaises(ScopeSuspendedError):
            controller.finish(ctx, {"status": "blocked"})

        reconciled = controller.reconcile(
            ReconciliationRecord(
                effect_id=out.effect.effect_id,
                resolved_status="confirmed_absent",
                evidence_ref="gateway-log-absent",
            )
        )
        self.assertEqual(reconciled.status, "confirmed_absent")
        self.assertEqual(controller.state, "active")
        self.assertEqual(controller.finish(ctx, {"status": "ok"}).violations, [])
        self.assertEqual(controller.state, "finished")


class ReconciliationWorkflowTests(unittest.TestCase):
    def test_reconcile_and_compensation_lifecycle_guards_and_scope_agreement(self):
        v3 = v3_contract()
        ctx = _v3_context(v3)
        store = InMemoryEffectStore()

        # Legacy controller without effect_governance rejects reconcile & record_compensation
        legacy = WorkflowController(Governor(), "run-legacy", contract())
        legacy.begin(context())
        with self.assertRaisesRegex(RuntimeError, "Effect governance is not configured"):
            legacy.reconcile(
                ReconciliationRecord(
                    effect_id="eff-000001",
                    resolved_status="confirmed",
                    evidence_ref="ref-1",
                )
            )
        with self.assertRaisesRegex(RuntimeError, "Effect governance is not configured"):
            legacy.record_compensation(
                CompensationRecord(
                    compensates_effect_id="eff-000001",
                    tool_name="refund_notification",
                    operation_digest=PlannedEffect(tool_name="refund_notification").operation_digest(),
                    evidence_ref="comp-1",
                )
            )

        # Seed an uncertain effect and a confirmed effect in scope.other directly in store
        other_uncertain = store.reserve(
            run_id="other-run",
            policy_scope="scope.other",
            action_index=1,
            tool_name="send_notification",
            operation_digest=PlannedEffect(tool_name="send_notification").operation_digest(),
        )
        store.record_observation(effect_id=other_uncertain.effect_id, status="uncertain")
        other_confirmed = store.reserve(
            run_id="other-run",
            policy_scope="scope.other2",
            action_index=1,
            tool_name="send_notification",
            operation_digest=PlannedEffect(tool_name="send_notification").operation_digest(),
        )
        store.record_observation(effect_id=other_confirmed.effect_id, status="confirmed")

        recorded: list[RecordedEvent] = []

        class ListRec:
            def record(self, ev: RecordedEvent) -> None:
                recorded.append(ev)

        controller = WorkflowController(
            Governor(),
            "run-scoped",
            v3,
            recorder=ListRec(),
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=EffectGovernanceConfig(
                store=store,
                resolver=_CallbackResolver(
                    lambda proposal, c: ResolvedAction(
                        planned_effect=PlannedEffect(tool_name=proposal.tool_name),
                        host_facts=HostFacts(facts=dict(c.state)),
                    )
                ),
                observer=_CallbackObserver(
                    lambda _in, _res: ObservedEffect(status="confirmed", evidence_ref="ok-main")
                ),
                policy_scope="scope.main",
            ),
        )

        # Before begin() (state == "new") -> RuntimeError
        with self.assertRaisesRegex(RuntimeError, "Run is not active or suspended"):
            controller.reconcile(
                ReconciliationRecord(
                    effect_id=other_uncertain.effect_id,
                    resolved_status="confirmed",
                    evidence_ref="too-early",
                )
            )
        with self.assertRaisesRegex(RuntimeError, "Run is not active or suspended"):
            controller.record_compensation(
                CompensationRecord(
                    compensates_effect_id=other_confirmed.effect_id,
                    tool_name="cancel_notification",
                    operation_digest=PlannedEffect(tool_name="cancel_notification").operation_digest(),
                    evidence_ref="too-early",
                )
            )

        controller.begin(ctx)

        # Scope conflict rejected pre-mutation (both explicit conflict and omitted record.policy_scope targeting other scope)
        with self.assertRaisesRegex(
            ReconciliationError,
            "Reconciliation policy_scope conflicts with effect_governance.policy_scope",
        ):
            controller.reconcile(
                ReconciliationRecord(
                    effect_id=other_uncertain.effect_id,
                    resolved_status="confirmed",
                    evidence_ref="wrong-scope",
                    policy_scope="scope.other",
                )
            )
        with self.assertRaisesRegex(
            ReconciliationError,
            "Reconciliation policy_scope does not match target effect",
        ):
            controller.reconcile(
                ReconciliationRecord(
                    effect_id=other_uncertain.effect_id,
                    resolved_status="confirmed",
                    evidence_ref="sneaky-none-scope",
                    policy_scope=None,
                )
            )
        self.assertTrue(store.is_scope_suspended("scope.other"))

        with self.assertRaisesRegex(
            ReconciliationError,
            "Compensation policy_scope conflicts with effect_governance.policy_scope",
        ):
            controller.record_compensation(
                CompensationRecord(
                    compensates_effect_id=other_confirmed.effect_id,
                    tool_name="cancel_notification",
                    operation_digest=PlannedEffect(tool_name="cancel_notification").operation_digest(),
                    evidence_ref="wrong-scope",
                    policy_scope="scope.other2",
                )
            )
        with self.assertRaisesRegex(
            ReconciliationError,
            "Compensation policy_scope does not match target effect",
        ):
            controller.record_compensation(
                CompensationRecord(
                    compensates_effect_id=other_confirmed.effect_id,
                    tool_name="cancel_notification",
                    operation_digest=PlannedEffect(tool_name="cancel_notification").operation_digest(),
                    evidence_ref="sneaky-none-scope",
                    policy_scope=None,
                )
            )

        # Valid execution + compensation in scope.main preserves original confirmed effect (INV-07)
        outcome = controller.execute(action(), ctx, lambda _p: "sent")
        assert outcome.effect is not None
        comp_digest = PlannedEffect(
            tool_name="cancel_notification", parameters={"target": outcome.effect.effect_id}
        ).operation_digest()
        comp = controller.record_compensation(
            CompensationRecord(
                compensates_effect_id=outcome.effect.effect_id,
                tool_name="cancel_notification",
                operation_digest=comp_digest,
                evidence_ref="comp-ticket-42",
            )
        )
        self.assertNotEqual(comp.effect_id, outcome.effect.effect_id)
        self.assertEqual(comp.compensates_effect_id, outcome.effect.effect_id)
        self.assertEqual(comp.status, "confirmed")
        snap = store.snapshot("scope.main")
        self.assertEqual(snap.effect_by_id(outcome.effect.effect_id).status, "confirmed")
        self.assertEqual(
            [e.kind for e in snap.entries], ["reserved", "observed", "compensated"]
        )
        self.assertEqual(recorded[-1].event_type, "effect_compensated")

        # After terminal finished -> RuntimeError
        controller.finish(ctx, {"status": "ok"})
        self.assertEqual(controller.state, "finished")
        with self.assertRaisesRegex(RuntimeError, "Run is not active or suspended"):
            controller.reconcile(
                ReconciliationRecord(
                    effect_id=other_uncertain.effect_id,
                    resolved_status="confirmed",
                    evidence_ref="too-late",
                )
            )
        with self.assertRaisesRegex(RuntimeError, "Run is not active or suspended"):
            controller.record_compensation(
                CompensationRecord(
                    compensates_effect_id=outcome.effect.effect_id,
                    tool_name="cancel_notification",
                    operation_digest=comp_digest,
                    evidence_ref="too-late",
                )
            )

    def test_toctou_between_evaluation_and_reservation_rejected_deterministically(self):
        catalog = RuleCatalog(
            rule_types={
                "custom.single_effect": RuleTypeSpec(
                    allowed_phases=frozenset({"runtime"}),
                    params_model=EmptyRuleParams,
                    handler=lambda req, _params: (
                        req.trajectory is not None and len(req.trajectory.effects) > 0
                    ),
                )
            }
        )
        base_v3 = v3_contract()
        draft = ContractRulesV3.model_validate({
            **base_v3.model_dump(mode="json"),
            "rules": [
                {
                    "instance_id": "declared-tools",
                    "rule_type": "tool.declared_only",
                    "phases": ["runtime"],
                },
                {
                    "instance_id": "single-effect",
                    "rule_type": "custom.single_effect",
                    "phases": ["runtime"],
                },
                {
                    "instance_id": "response-schema",
                    "rule_type": "response.schema_complete",
                    "phases": ["post_execution"],
                },
            ],
            "contract_fingerprint": "sha256:placeholder",
        })
        single_v3 = draft.model_copy(
            update={
                "contract_fingerprint": compute_v3_contract_fingerprint(
                    draft, rule_catalog=catalog
                )
            }
        )
        ctx = _v3_context(single_v3)
        store = InMemoryEffectStore()

        def make_cfg() -> EffectGovernanceConfig:
            return EffectGovernanceConfig(
                store=store,
                resolver=_CallbackResolver(
                    lambda proposal, c: ResolvedAction(
                        planned_effect=PlannedEffect(tool_name=proposal.tool_name),
                        host_facts=HostFacts(facts=dict(c.state)),
                    )
                ),
                observer=_CallbackObserver(
                    lambda _in, _res: ObservedEffect(status="confirmed", evidence_ref="ok")
                ),
                policy_scope="scope.toctou",
            )

        calls_a: list[str] = []
        calls_b: list[str] = []
        recorded_a: list[RecordedEvent] = []

        class ListRec:
            def record(self, ev: RecordedEvent) -> None:
                recorded_a.append(ev)

        controller_b = WorkflowController(
            Governor(rule_catalog=catalog),
            "run-b",
            single_v3,
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=make_cfg(),
        )
        controller_b.begin(ctx)

        base_gov = Governor(rule_catalog=catalog)
        interleaved_once = False

        class InterleavingEvaluator:
            def evaluate(self, request: GovernorInput) -> GovernanceDecision:
                nonlocal interleaved_once
                decision = base_gov.evaluate(request)
                if request.phase == "runtime" and not interleaved_once:
                    interleaved_once = True
                    # Controller B runs start-to-finish while A's snapshot is open
                    out_b = controller_b.execute(
                        action(sensitive=False),
                        ctx,
                        lambda _p: calls_b.append("b") or "b-done",
                    )
                    assert out_b.executed and out_b.effect is not None
                return decision

        controller_a = WorkflowController(
            Governor(evaluator=InterleavingEvaluator()),
            "run-a",
            single_v3,
            recorder=ListRec(),
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=make_cfg(),
        )
        controller_a.begin(ctx)

        with self.assertRaisesRegex(
            ConcurrencyError,
            "Policy scope trajectory changed between evaluation and reservation",
        ):
            controller_a.execute(
                action(sensitive=False),
                ctx,
                lambda _p: calls_a.append("a") or "a-done",
            )

        self.assertEqual(calls_a, [])
        self.assertEqual(calls_b, ["b"])
        self.assertEqual(len(calls_a) + len(calls_b), 1)
        self.assertEqual(controller_a.state, "active")

        # Retrying on controller_a sees the updated trajectory, blocks cleanly, and uses action_index=1 (no gap)
        retry = controller_a.execute(
            action(sensitive=False),
            ctx,
            lambda _p: calls_a.append("a-retry") or "a-retry",
        )
        self.assertFalse(retry.executed)
        self.assertEqual(retry.decision.decision, "block")
        self.assertEqual([v.rule for v in retry.decision.violations], ["single-effect"])
        self.assertEqual(calls_a, [])
        runtime_events = [ev for ev in recorded_a if ev.phase == "runtime"]
        self.assertEqual(len(runtime_events), 1)
        self.assertEqual(runtime_events[0].action_index, 1)

    def test_multithread_barrier_concurrent_controllers_at_most_one_executes(self):
        catalog = RuleCatalog(
            rule_types={
                "custom.single_effect": RuleTypeSpec(
                    allowed_phases=frozenset({"runtime"}),
                    params_model=EmptyRuleParams,
                    handler=lambda req, _params: (
                        req.trajectory is not None and len(req.trajectory.effects) > 0
                    ),
                )
            }
        )
        base_v3 = v3_contract()
        draft = ContractRulesV3.model_validate({
            **base_v3.model_dump(mode="json"),
            "rules": [
                {
                    "instance_id": "declared-tools",
                    "rule_type": "tool.declared_only",
                    "phases": ["runtime"],
                },
                {
                    "instance_id": "single-effect",
                    "rule_type": "custom.single_effect",
                    "phases": ["runtime"],
                },
                {
                    "instance_id": "response-schema",
                    "rule_type": "response.schema_complete",
                    "phases": ["post_execution"],
                },
            ],
            "contract_fingerprint": "sha256:placeholder",
        })
        single_v3 = draft.model_copy(
            update={
                "contract_fingerprint": compute_v3_contract_fingerprint(
                    draft, rule_catalog=catalog
                )
            }
        )
        ctx = _v3_context(single_v3)
        store = InMemoryEffectStore()
        barrier = threading.Barrier(2, timeout=5.0)
        base_gov = Governor(rule_catalog=catalog)

        class BarrierEvaluator:
            def evaluate(self, request: GovernorInput) -> GovernanceDecision:
                decision = base_gov.evaluate(request)
                if request.phase == "runtime":
                    barrier.wait()
                return decision

        invocations: list[str] = []
        inv_lock = threading.Lock()
        outcomes: list[tuple[str, str]] = []
        controllers: list[WorkflowController] = []

        for label in ("t1", "t2"):
            c = WorkflowController(
                Governor(evaluator=BarrierEvaluator()),
                f"run-{label}",
                single_v3,
                policy=EnforcementPolicy(mode="guarded"),
                effect_governance=EffectGovernanceConfig(
                    store=store,
                    resolver=_CallbackResolver(
                        lambda proposal, c_ctx: ResolvedAction(
                            planned_effect=PlannedEffect(tool_name=proposal.tool_name),
                            host_facts=HostFacts(facts=dict(c_ctx.state)),
                        )
                    ),
                    observer=_CallbackObserver(
                        lambda _in, _res: ObservedEffect(status="confirmed", evidence_ref="ok")
                    ),
                    policy_scope="scope.barrier",
                ),
            )
            c.begin(ctx)
            controllers.append(c)

        def worker(label: str, ctrl: WorkflowController) -> None:
            try:
                out = ctrl.execute(
                    action(sensitive=False),
                    ctx,
                    lambda _p: (inv_lock.acquire(), invocations.append(label), inv_lock.release()) and label,
                )
                assert out.executed and out.effect is not None
                with inv_lock:
                    outcomes.append((label, "executed"))
            except ConcurrencyError:
                with inv_lock:
                    outcomes.append((label, "concurrency_error"))

        threads = [
            threading.Thread(target=worker, args=(lbl, ctrl))
            for lbl, ctrl in zip(("t1", "t2"), controllers)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10.0)
            self.assertFalse(t.is_alive())

        statuses = sorted(status for _, status in outcomes)
        self.assertEqual(statuses, ["concurrency_error", "executed"])
        self.assertEqual(len(invocations), 1)
        self.assertEqual(len(store.snapshot("scope.barrier").effects), 1)
        self.assertTrue(all(ctrl.state == "active" for ctrl in controllers))


class BoundAuthorizationExecutionTests(unittest.TestCase):
    def _auth_v3_contract(
        self,
        *,
        allow_retry_after_confirmed_absent: bool = True,
        extra_approval_binding: dict | None = None,
    ) -> ContractRulesV3:
        rules: list[dict] = [
            {
                "instance_id": "declared-tools",
                "rule_type": "tool.declared_only",
                "phases": ["runtime"],
                "params": {},
            },
            {
                "instance_id": "dest-allow",
                "rule_type": "destination.allowlist",
                "phases": ["runtime"],
                "params": {
                    "tools": ["send_notification"],
                    "allowed_destinations": ["ops@example.com", "alerts@example.com"],
                    "destination_param": "recipient",
                    "source": "planned_effect",
                },
            },
            {
                "instance_id": "bound-approval",
                "rule_type": "approval.bound_required",
                "phases": ["runtime"],
                "params": {
                    "tools": ["send_notification"],
                    "required_authorities": ["notification_approver"],
                    "authority_match": "any",
                    "sensitivity_fact_key": "sensitive",
                    "allow_self_approval": False,
                    "require_single_use": True,
                    "allow_retry_after_confirmed_absent": allow_retry_after_confirmed_absent,
                },
            },
            {
                "instance_id": "evidence-check",
                "rule_type": "evidence.retrieved_required",
                "phases": ["runtime"],
                "params": {
                    "tools": ["send_notification"],
                    "min_count": 1,
                    "allowed_sources": ["policy_kb"],
                    "require_content_digest": True,
                    "claim_param": "evidence_ids",
                },
            },
            {
                "instance_id": "response-schema",
                "rule_type": "response.schema_complete",
                "phases": ["post_execution"],
                "params": {},
            },
        ]
        if extra_approval_binding is not None:
            rules.insert(3, extra_approval_binding)
        draft = ContractRulesV3.model_validate({
            "schema_version": 3,
            "contract_id": "test.bound.auth.v3",
            "approved_agent_configurations": ["agent-v1"],
            "declared_tools": ["send_notification"],
            "response_schema": {"required_fields": ["status"]},
            "memory_policy": "none",
            "validation_phases": ["pre_execution", "runtime", "post_execution"],
            "rules": rules,
            "contract_fingerprint": "sha256:placeholder",
        })
        return draft.model_copy(
            update={"contract_fingerprint": compute_v3_contract_fingerprint(draft)}
        )

    def _evidence(self, evidence_id: str = "ev-001") -> tuple[RetrievedEvidence, ...]:
        return (
            RetrievedEvidence(
                evidence_id=evidence_id,
                source="policy_kb",
                content_digest="sha256:" + ("a" * 64),
                retrieved_at="2026-06-01T10:00:00Z",
            ),
        )

    def _planned(
        self,
        *,
        recipient: str = "alerts@example.com",
        evidence_ids: list[str] | None = None,
    ) -> PlannedEffect:
        return PlannedEffect(
            tool_name="send_notification",
            parameters={
                "recipient": recipient,
                "evidence_ids": evidence_ids if evidence_ids is not None else ["ev-001"],
            },
            defaults={"channel": "email"},
        )

    def _approval(
        self,
        planned: PlannedEffect,
        *,
        approval_id: str = "appr-001",
        policy_scope: str = "scope.auth",
        requester_id: str = "req-1",
        approver_id: str = "mgr-1",
        approver_authorities: tuple[str, ...] = ("notification_approver",),
        issued_at: str = "2026-06-01T10:00:00Z",
        expires_at: str = "2026-06-01T11:00:00Z",
        status: str = "active",
        single_use: bool = True,
    ) -> HostApproval:
        return HostApproval(
            approval_id=approval_id,
            operation_digest=planned.operation_digest(),
            policy_scope=policy_scope,
            requester_id=requester_id,
            approver_id=approver_id,
            approver_authorities=list(approver_authorities),
            issued_at=issued_at,
            expires_at=expires_at,
            status=status,  # type: ignore[arg-type]
            single_use=single_use,
        )

    def test_legitimate_bound_flow_consumes_approval_and_records_approval_id(self):
        v3 = self._auth_v3_contract()
        ctx = _v3_context(v3, state={})
        planned = self._planned()
        approval = self._approval(planned)
        store = InMemoryEffectStore()
        calls: list[str] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            log = JsonlDecisionLog(Path(tmpdir) / "bound.jsonl")
            controller = WorkflowController(
                Governor(),
                "run-legit",
                v3,
                recorder=log,
                policy=EnforcementPolicy(mode="guarded"),
                effect_governance=EffectGovernanceConfig(
                    store=store,
                    resolver=_CallbackResolver(
                        lambda _a, _c: ResolvedAction(
                            planned_effect=planned,
                            host_facts=HostFacts(
                                facts={
                                    "sensitive": True,
                                    "requester_id": "req-1",
                                    "approval_id": "appr-001",
                                }
                            ),
                            policy_scope="scope.auth",
                            requester_id="req-1",
                            evaluated_at="2026-06-01T10:30:00Z",
                            approval=approval,
                            retrieved_evidence=self._evidence(),
                        )
                    ),
                    observer=_CallbackObserver(
                        lambda _in, _res: ObservedEffect(
                            status="confirmed", evidence_ref="gw-101"
                        )
                    ),
                    policy_scope="scope.auth",
                ),
            )
            self.assertEqual(controller.begin(ctx).violations, [])
            outcome = controller.execute(
                ActionProposal(
                    tool_name="send_notification",
                    arguments={"recipient": "alerts@example.com", "sensitive": False},
                ),
                ctx,
                lambda _p: calls.append("sent") or "ok",
            )
            self.assertTrue(outcome.executed)
            assert outcome.effect is not None
            self.assertEqual(outcome.effect.status, "confirmed")
            self.assertEqual(outcome.effect.approval_id, "appr-001")
            self.assertEqual(calls, ["sent"])
            self.assertEqual(controller.finish(ctx, {"status": "ok"}).violations, [])

            snap = store.snapshot("scope.auth")
            appr_state = snap.approval_by_id("appr-001")
            self.assertIsNotNone(appr_state)
            assert appr_state is not None
            self.assertEqual(appr_state.status, "consumed")

            events = log.read()
            self.assertEqual(
                [ev.event_type for ev in events],
                ["decision", "decision", "tool_completed", "effect_observed", "decision"],
            )
            self.assertEqual(events[1].approval_id, "appr-001")
            self.assertIsNone(events[2].approval_id)
            self.assertEqual(events[3].approval_id, "appr-001")

            # Single-use replay on a second controller with a different run_id (INV-11) is blocked
            controller2 = WorkflowController(
                Governor(),
                "run-replay",
                v3,
                policy=EnforcementPolicy(mode="guarded"),
                effect_governance=EffectGovernanceConfig(
                    store=store,
                    resolver=_CallbackResolver(
                        lambda _a, _c: ResolvedAction(
                            planned_effect=planned,
                            host_facts=HostFacts(
                                facts={
                                    "sensitive": True,
                                    "requester_id": "req-1",
                                    "approval_id": "appr-001",
                                }
                            ),
                            policy_scope="scope.auth",
                            requester_id="req-1",
                            evaluated_at="2026-06-01T10:35:00Z",
                            approval=approval,
                            retrieved_evidence=self._evidence(),
                        )
                    ),
                    observer=_CallbackObserver(
                        lambda _in, _res: ObservedEffect(status="confirmed")
                    ),
                    policy_scope="scope.auth",
                ),
            )
            controller2.begin(ctx)
            replay = controller2.execute(
                ActionProposal(tool_name="send_notification"),
                ctx,
                lambda _p: calls.append("replayed"),
            )
            self.assertFalse(replay.executed)
            self.assertEqual(replay.decision.decision, "block")
            self.assertEqual([v.rule for v in replay.decision.violations], ["bound-approval"])
            self.assertEqual(calls, ["sent"])

    def test_rejects_tampered_authorization_evidence_destination_and_spoofed_sensitivity(self):
        v3 = self._auth_v3_contract()
        ctx = _v3_context(v3, state={})
        valid_planned = self._planned()
        valid_approval = self._approval(valid_planned)

        cases = [
            (
                "modified_destination_after_approval",
                self._planned(recipient="ops@example.com"),
                valid_approval,
                "req-1",
                "2026-06-01T10:30:00Z",
                self._evidence(),
                True,
                "bound-approval",
            ),
            (
                "foreign_requester_id",
                valid_planned,
                valid_approval,
                "req-foreign",
                "2026-06-01T10:30:00Z",
                self._evidence(),
                True,
                "bound-approval",
            ),
            (
                "wrong_policy_scope",
                valid_planned,
                self._approval(valid_planned, policy_scope="scope.other"),
                "req-1",
                "2026-06-01T10:30:00Z",
                self._evidence(),
                True,
                "bound-approval",
            ),
            (
                "disallowed_self_approval",
                valid_planned,
                self._approval(valid_planned, approver_id="req-1"),
                "req-1",
                "2026-06-01T10:30:00Z",
                self._evidence(),
                True,
                "bound-approval",
            ),
            (
                "missing_authority",
                valid_planned,
                self._approval(valid_planned, approver_authorities=("viewer",)),
                "req-1",
                "2026-06-01T10:30:00Z",
                self._evidence(),
                True,
                "bound-approval",
            ),
            (
                "expired_approval",
                valid_planned,
                valid_approval,
                "req-1",
                "2026-06-01T11:00:00Z",
                self._evidence(),
                True,
                "bound-approval",
            ),
            (
                "future_approval",
                valid_planned,
                valid_approval,
                "req-1",
                "2026-06-01T09:59:59Z",
                self._evidence(),
                True,
                "bound-approval",
            ),
            (
                "revoked_approval",
                valid_planned,
                self._approval(valid_planned, status="revoked"),
                "req-1",
                "2026-06-01T10:30:00Z",
                self._evidence(),
                True,
                "bound-approval",
            ),
            (
                "invented_evidence_id",
                self._planned(evidence_ids=["ev-invented"]),
                self._approval(self._planned(evidence_ids=["ev-invented"])),
                "req-1",
                "2026-06-01T10:30:00Z",
                self._evidence("ev-001"),
                True,
                "evidence-check",
            ),
            (
                "disallowed_destination",
                self._planned(recipient="attacker@evil.example"),
                self._approval(self._planned(recipient="attacker@evil.example")),
                "req-1",
                "2026-06-01T10:30:00Z",
                self._evidence(),
                True,
                "dest-allow",
            ),
            (
                "agent_claims_not_sensitive_when_host_sensitive_true",
                valid_planned,
                None,
                "req-1",
                "2026-06-01T10:30:00Z",
                self._evidence(),
                True,
                "bound-approval",
            ),
        ]

        for mode in ("guarded", "strict"):
            for (
                label,
                planned_eff,
                appr,
                req_id,
                eval_at,
                ev_tuple,
                sensitive,
                expected_rule,
            ) in cases:
                with self.subTest(mode=mode, case=label):
                    calls: list[str] = []
                    controller = WorkflowController(
                        Governor(),
                        f"run-{mode}-{label}",
                        v3,
                        policy=EnforcementPolicy(mode=mode),
                        effect_governance=EffectGovernanceConfig(
                            store=InMemoryEffectStore(),
                            resolver=_CallbackResolver(
                                lambda _a, _c, pe=planned_eff, ap=appr, ri=req_id, ea=eval_at, ev=ev_tuple, sens=sensitive: ResolvedAction(
                                    planned_effect=pe,
                                    host_facts=HostFacts(
                                        facts={
                                            "sensitive": sens,
                                            "requester_id": ri,
                                            **(
                                                {"approval_id": ap.approval_id}
                                                if ap is not None
                                                else {}
                                            ),
                                        }
                                    ),
                                    policy_scope="scope.auth",
                                    requester_id=ri,
                                    evaluated_at=ea,
                                    approval=ap,
                                    retrieved_evidence=ev,
                                )
                            ),
                            observer=_CallbackObserver(
                                lambda _in, _res: ObservedEffect(status="confirmed")
                            ),
                            policy_scope="scope.auth",
                        ),
                    )
                    controller.begin(ctx)
                    outcome = controller.execute(
                        ActionProposal(
                            tool_name="send_notification",
                            arguments={"sensitive": False, "evidence_ids": ["ev-001"]},
                        ),
                        ctx,
                        lambda _p: calls.append("called"),
                    )
                    self.assertFalse(outcome.executed)
                    self.assertIsNone(outcome.effect)
                    self.assertEqual(
                        outcome.decision.decision,
                        "abort" if mode == "strict" else "block",
                    )
                    self.assertIn(
                        expected_rule, [v.rule for v in outcome.decision.violations]
                    )
                    self.assertEqual(calls, [])

    def test_uncertain_locks_approval_and_reconciliation_gates_retry_and_consumption(self):
        v3_retry = self._auth_v3_contract(allow_retry_after_confirmed_absent=True)
        v3_no_retry = self._auth_v3_contract(allow_retry_after_confirmed_absent=False)
        ctx_retry = _v3_context(v3_retry, state={})
        planned = self._planned()
        appr = self._approval(planned, approval_id="appr-unc-1")

        # Part A: tool raises -> observer uncertain -> locked_uncertain -> reconcile confirmed -> permanently consumed
        store_a = InMemoryEffectStore()
        rec_a: list[RecordedEvent] = []

        class ListRecA:
            def record(self, ev: RecordedEvent) -> None:
                rec_a.append(ev)

        ctrl_a = WorkflowController(
            Governor(),
            "run-unc-confirm",
            v3_retry,
            recorder=ListRecA(),
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=EffectGovernanceConfig(
                store=store_a,
                resolver=_CallbackResolver(
                    lambda _a, _c: ResolvedAction(
                        planned_effect=planned,
                        host_facts=HostFacts(facts={"sensitive": True}),
                        policy_scope="scope.auth",
                        requester_id="req-1",
                        evaluated_at="2026-06-01T10:30:00Z",
                        approval=appr,
                        retrieved_evidence=self._evidence(),
                    )
                ),
                observer=_CallbackObserver(
                    lambda _in, _res: ObservedEffect(
                        status="uncertain", evidence_ref="obs-unc"
                    )
                ),
                policy_scope="scope.auth",
            ),
        )
        ctrl_a.begin(ctx_retry)
        with self.assertRaisesRegex(RuntimeError, "gw-timeout"):
            ctrl_a.execute(
                ActionProposal(tool_name="send_notification"),
                ctx_retry,
                lambda _p: (_ for _ in ()).throw(RuntimeError("gw-timeout")),
            )
        self.assertEqual(
            store_a.snapshot("scope.auth").approval_by_id("appr-unc-1").status,
            "locked_uncertain",
        )
        self.assertEqual(rec_a[-1].event_type, "effect_observed")
        self.assertEqual(rec_a[-1].approval_id, "appr-unc-1")

        with self.assertRaises(ScopeSuspendedError):
            ctrl_a.execute(
                ActionProposal(tool_name="send_notification"), ctx_retry, lambda _p: "nope"
            )

        unc_id = store_a.uncertain_effects("scope.auth")[0]
        reconciled = ctrl_a.reconcile(
            ReconciliationRecord(
                effect_id=unc_id,
                resolved_status="confirmed",
                evidence_ref="gw-confirmed-audit",
                policy_scope="scope.auth",
            )
        )
        self.assertEqual(reconciled.approval_id, "appr-unc-1")
        self.assertEqual(rec_a[-1].event_type, "effect_reconciled")
        self.assertEqual(rec_a[-1].approval_id, "appr-unc-1")
        self.assertEqual(
            store_a.snapshot("scope.auth").approval_by_id("appr-unc-1").status,
            "consumed",
        )
        # Compensation of confirmed effect does NOT restore consumed approval
        ctrl_a.record_compensation(
            CompensationRecord(
                compensates_effect_id=unc_id,
                tool_name="cancel_notification",
                operation_digest=PlannedEffect(tool_name="cancel_notification").operation_digest(),
                evidence_ref="comp-1",
                policy_scope="scope.auth",
            )
        )
        self.assertEqual(
            store_a.snapshot("scope.auth").approval_by_id("appr-unc-1").status,
            "consumed",
        )
        retry_after_confirm = ctrl_a.execute(
            ActionProposal(tool_name="send_notification"), ctx_retry, lambda _p: "nope"
        )
        self.assertFalse(retry_after_confirm.executed)
        self.assertEqual(retry_after_confirm.decision.decision, "block")

        # Part B: observer fails -> uncertain -> reconcile confirmed_absent -> released_absent
        store_b = InMemoryEffectStore()
        rec_b: list[RecordedEvent] = []

        class ListRecB:
            def record(self, ev: RecordedEvent) -> None:
                rec_b.append(ev)

        appr_b = self._approval(planned, approval_id="appr-unc-2")
        obs_mode = {"fail": True}
        eval_state = {"at": "2026-06-01T10:30:00Z", "planned": planned}
        ctrl_b = WorkflowController(
            Governor(),
            "run-unc-absent",
            v3_retry,
            recorder=ListRecB(),
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=EffectGovernanceConfig(
                store=store_b,
                resolver=_CallbackResolver(
                    lambda _a, _c: ResolvedAction(
                        planned_effect=eval_state["planned"],
                        host_facts=HostFacts(facts={"sensitive": True}),
                        policy_scope="scope.auth",
                        requester_id="req-1",
                        evaluated_at=eval_state["at"],
                        approval=appr_b,
                        retrieved_evidence=self._evidence(),
                    )
                ),
                observer=_CallbackObserver(
                    lambda _in, _res: (
                        (_ for _ in ()).throw(RuntimeError("obs-crash"))
                        if obs_mode["fail"]
                        else ObservedEffect(status="confirmed", evidence_ref="retry-ok")
                    )
                ),
                policy_scope="scope.auth",
            ),
        )
        ctrl_b.begin(ctx_retry)
        with self.assertRaises(EffectObservationError):
            ctrl_b.execute(ActionProposal(tool_name="send_notification"), ctx_retry, lambda _p: "ret")
        self.assertEqual(rec_b[-1].event_type, "effect_observed")
        self.assertEqual(rec_b[-1].approval_id, "appr-unc-2")
        ctrl_b.reconcile(
            ReconciliationRecord(
                effect_id=store_b.uncertain_effects("scope.auth")[0],
                resolved_status="confirmed_absent",
                evidence_ref="gw-absent-audit",
                policy_scope="scope.auth",
            )
        )
        self.assertEqual(
            store_b.snapshot("scope.auth").approval_by_id("appr-unc-2").status,
            "released_absent",
        )

        # Retry rejected when contract has allow_retry_after_confirmed_absent=False
        ctrl_no_retry = WorkflowController(
            Governor(),
            "run-no-retry",
            v3_no_retry,
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=EffectGovernanceConfig(
                store=store_b,
                resolver=_CallbackResolver(
                    lambda _a, _c: ResolvedAction(
                        planned_effect=planned,
                        host_facts=HostFacts(facts={"sensitive": True}),
                        policy_scope="scope.auth",
                        requester_id="req-1",
                        evaluated_at="2026-06-01T10:40:00Z",
                        approval=appr_b,
                        retrieved_evidence=self._evidence(),
                    )
                ),
                observer=_CallbackObserver(lambda _in, _res: ObservedEffect(status="confirmed")),
                policy_scope="scope.auth",
            ),
        )
        ctrl_no_retry.begin(_v3_context(v3_no_retry, state={}))
        denied_no_retry = ctrl_no_retry.execute(
            ActionProposal(tool_name="send_notification"),
            _v3_context(v3_no_retry, state={}),
            lambda _p: "nope",
        )
        self.assertFalse(denied_no_retry.executed)

        # Retry rejected if expired or modified
        obs_mode["fail"] = False
        eval_state["at"] = "2026-06-01T11:00:00Z"
        expired_retry = ctrl_b.execute(
            ActionProposal(tool_name="send_notification"), ctx_retry, lambda _p: "nope"
        )
        self.assertFalse(expired_retry.executed)

        eval_state["at"] = "2026-06-01T10:45:00Z"
        eval_state["planned"] = self._planned(recipient="ops@example.com")
        modified_retry = ctrl_b.execute(
            ActionProposal(tool_name="send_notification"), ctx_retry, lambda _p: "nope"
        )
        self.assertFalse(modified_retry.executed)

        # Identical operation while unexpired succeeds and permanently consumes approval
        eval_state["planned"] = planned
        ok_retry = ctrl_b.execute(
            ActionProposal(tool_name="send_notification"), ctx_retry, lambda _p: "sent-retry"
        )
        self.assertTrue(ok_retry.executed)
        assert ok_retry.effect is not None
        self.assertEqual(ok_retry.effect.status, "confirmed")
        self.assertEqual(
            store_b.snapshot("scope.auth").approval_by_id("appr-unc-2").status,
            "consumed",
        )

    def test_multithread_toctou_double_spend_single_use_approval_allows_at_most_one(self):
        v3 = self._auth_v3_contract()
        ctx = _v3_context(v3, state={})
        planned = self._planned()
        approval = self._approval(planned, approval_id="appr-race-1")
        store = InMemoryEffectStore()
        barrier = threading.Barrier(2, timeout=5.0)
        base_gov = Governor()

        class BarrierEvaluator:
            def evaluate(self, request: GovernorInput) -> GovernanceDecision:
                decision = base_gov.evaluate(request)
                if request.phase == "runtime":
                    barrier.wait()
                return decision

        invocations: list[str] = []
        outcomes: list[str] = []
        lock = threading.Lock()
        controllers: list[WorkflowController] = []

        for label in ("c1", "c2"):
            ctrl = WorkflowController(
                Governor(evaluator=BarrierEvaluator()),
                f"run-race-{label}",
                v3,
                policy=EnforcementPolicy(mode="guarded"),
                effect_governance=EffectGovernanceConfig(
                    store=store,
                    resolver=_CallbackResolver(
                        lambda _a, _c: ResolvedAction(
                            planned_effect=planned,
                            host_facts=HostFacts(facts={"sensitive": True}),
                            policy_scope="scope.auth",
                            requester_id="req-1",
                            evaluated_at="2026-06-01T10:30:00Z",
                            approval=approval,
                            retrieved_evidence=self._evidence(),
                        )
                    ),
                    observer=_CallbackObserver(
                        lambda _in, _res: ObservedEffect(status="confirmed", evidence_ref="race-ok")
                    ),
                    policy_scope="scope.auth",
                ),
            )
            ctrl.begin(ctx)
            controllers.append(ctrl)

        def run_one(label: str, ctrl: WorkflowController) -> None:
            try:
                out = ctrl.execute(
                    ActionProposal(tool_name="send_notification"),
                    ctx,
                    lambda _p: (lock.acquire(), invocations.append(label), lock.release()) and label,
                )
                assert out.executed
                with lock:
                    outcomes.append("executed")
            except (ConcurrencyError, ApprovalReuseError):
                with lock:
                    outcomes.append("rejected_operational")

        threads = [
            threading.Thread(target=run_one, args=(lbl, ctrl))
            for lbl, ctrl in zip(("c1", "c2"), controllers)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10.0)
            self.assertFalse(t.is_alive())

        self.assertEqual(sorted(outcomes), ["executed", "rejected_operational"])
        self.assertEqual(len(invocations), 1)
        self.assertEqual(
            store.snapshot("scope.auth").approval_by_id("appr-race-1").status,
            "consumed",
        )

    def test_advisory_violation_preserves_consumed_approval_and_pre_record_failure_releases_absent(self):
        v3 = self._auth_v3_contract()
        ctx = _v3_context(v3, state={})
        planned = self._planned()
        appr = self._approval(planned, approval_id="appr-adv-1")

        # 1. Pre-invocation recorder failure releases approval as released_absent without tool call
        store_rec = InMemoryEffectStore()
        calls: list[str] = []
        rec_count = 0

        class FailSecond:
            def record(self, _ev: RecordedEvent) -> None:
                nonlocal rec_count
                rec_count += 1
                if rec_count == 2:
                    raise OSError("pre-record failure")

        ctrl_fail = WorkflowController(
            Governor(),
            "run-pre-rec-appr",
            v3,
            recorder=FailSecond(),
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=EffectGovernanceConfig(
                store=store_rec,
                resolver=_CallbackResolver(
                    lambda _a, _c: ResolvedAction(
                        planned_effect=planned,
                        host_facts=HostFacts(facts={"sensitive": True}),
                        policy_scope="scope.auth",
                        requester_id="req-1",
                        evaluated_at="2026-06-01T10:30:00Z",
                        approval=appr,
                        retrieved_evidence=self._evidence(),
                    )
                ),
                observer=_CallbackObserver(lambda _in, _res: ObservedEffect(status="confirmed")),
                policy_scope="scope.auth",
            ),
        )
        ctrl_fail.begin(ctx)
        with self.assertRaisesRegex(OSError, "pre-record failure"):
            ctrl_fail.execute(
                ActionProposal(tool_name="send_notification"),
                ctx,
                lambda _p: calls.append("called"),
            )
        self.assertEqual(calls, [])
        self.assertEqual(
            store_rec.snapshot("scope.auth").approval_by_id("appr-adv-1").status,
            "released_absent",
        )

        # 2. Consume approval cleanly, then run advisory mode with consumed approval (INV-12)
        ctrl_ok = WorkflowController(
            Governor(),
            "run-consume-first",
            v3,
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=EffectGovernanceConfig(
                store=store_rec,
                resolver=_CallbackResolver(
                    lambda _a, _c: ResolvedAction(
                        planned_effect=planned,
                        host_facts=HostFacts(facts={"sensitive": True}),
                        policy_scope="scope.auth",
                        requester_id="req-1",
                        evaluated_at="2026-06-01T10:35:00Z",
                        approval=appr,
                        retrieved_evidence=self._evidence(),
                    )
                ),
                observer=_CallbackObserver(lambda _in, _res: ObservedEffect(status="confirmed")),
                policy_scope="scope.auth",
            ),
        )
        ctrl_ok.begin(ctx)
        self.assertTrue(
            ctrl_ok.execute(
                ActionProposal(tool_name="send_notification"),
                ctx,
                lambda _p: calls.append("first") or "ok",
            ).executed
        )
        self.assertEqual(
            store_rec.snapshot("scope.auth").approval_by_id("appr-adv-1").status,
            "consumed",
        )

        ctrl_adv = WorkflowController(
            Governor(),
            "run-advisory-consumed",
            v3,
            policy=EnforcementPolicy(mode="advisory"),
            effect_governance=EffectGovernanceConfig(
                store=store_rec,
                resolver=_CallbackResolver(
                    lambda _a, _c: ResolvedAction(
                        planned_effect=planned,
                        host_facts=HostFacts(facts={"sensitive": True}),
                        policy_scope="scope.auth",
                        requester_id="req-1",
                        evaluated_at="2026-06-01T10:40:00Z",
                        approval=appr,
                        retrieved_evidence=self._evidence(),
                    )
                ),
                observer=_CallbackObserver(lambda _in, _res: ObservedEffect(status="confirmed")),
                policy_scope="scope.auth",
            ),
        )
        ctrl_adv.begin(ctx)
        adv_out = ctrl_adv.execute(
            ActionProposal(tool_name="send_notification"),
            ctx,
            lambda _p: calls.append("advisory") or "warned",
        )
        self.assertTrue(adv_out.executed)
        self.assertEqual(adv_out.decision.decision, "allow_with_warning")
        self.assertEqual([v.rule for v in adv_out.decision.violations], ["bound-approval"])
        assert adv_out.effect is not None
        self.assertIsNone(adv_out.effect.approval_id)
        self.assertEqual(
            store_rec.snapshot("scope.auth").approval_by_id("appr-adv-1").status,
            "consumed",
        )

    def test_proposal_snapshot_before_resolution_prevents_caller_and_resolver_mutation_redirect(self):
        v3 = self._auth_v3_contract()
        ctx = _v3_context(v3, state={})
        planned = self._planned(recipient="alerts@example.com")
        appr = self._approval(planned, approval_id="appr-snap-1")
        caller_proposal = ActionProposal(
            tool_name="send_notification",
            arguments={"recipient": "alerts@example.com", "evidence_ids": ["ev-001"]},
        )
        observed_recipients: list[object] = []

        def mutating_resolve(
            arg_proposal: ActionProposal, arg_ctx: ExecutionContext
        ) -> ResolvedAction:
            resolved = ResolvedAction(
                planned_effect=planned,
                host_facts=HostFacts(facts={"sensitive": True}),
                policy_scope="scope.auth",
                requester_id="req-1",
                evaluated_at="2026-06-01T10:30:00Z",
                approval=appr,
                retrieved_evidence=self._evidence(),
            )
            # Mutate both caller's original proposal and the resolver's copy after resolution
            caller_proposal.arguments["recipient"] = "evil@example.com"
            arg_proposal.arguments["recipient"] = "resolver-evil@example.com"
            arg_ctx.state["tampered"] = True
            return resolved

        controller = WorkflowController(
            Governor(),
            "run-snap-mutation",
            v3,
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=EffectGovernanceConfig(
                store=InMemoryEffectStore(),
                resolver=_CallbackResolver(mutating_resolve),
                observer=_CallbackObserver(
                    lambda _in, _res: ObservedEffect(status="confirmed", evidence_ref="snap-ok")
                ),
                policy_scope="scope.auth",
            ),
        )
        controller.begin(ctx)
        outcome = controller.execute(
            caller_proposal,
            ctx,
            lambda invoked: observed_recipients.append(invoked.arguments["recipient"]) or "sent",
        )
        self.assertTrue(outcome.executed)
        self.assertEqual(observed_recipients, ["alerts@example.com"])

    def test_unrelated_approval_on_non_sensitive_or_non_governed_tool_is_not_consumed(self):
        base_v3 = self._auth_v3_contract()
        draft = ContractRulesV3.model_validate({
            **base_v3.model_dump(mode="json"),
            "declared_tools": ["send_notification", "list_status"],
            "contract_fingerprint": "sha256:placeholder",
        })
        v3 = draft.model_copy(
            update={"contract_fingerprint": compute_v3_contract_fingerprint(draft)}
        )
        ctx = ExecutionContext(
            state={},
            available_tools=["send_notification", "list_status"],
            observed_agent_fingerprint="agent-v1",
            observed_contract_fingerprint=v3.contract_fingerprint,
        )
        sensitive_planned = self._planned(recipient="alerts@example.com")
        sensitive_approval = self._approval(
            sensitive_planned, approval_id="appr-sensitive-only"
        )
        ops_planned = self._planned(recipient="ops@example.com")
        status_planned = PlannedEffect(tool_name="list_status", parameters={})

        store = InMemoryEffectStore()
        recorded: list[RecordedEvent] = []

        class ListRec:
            def record(self, ev: RecordedEvent) -> None:
                recorded.append(ev)

        resolver_mode = {"kind": "ops"}

        def resolve_fn(proposal: ActionProposal, _c: ExecutionContext) -> ResolvedAction:
            if resolver_mode["kind"] == "ops":
                return ResolvedAction(
                    planned_effect=ops_planned,
                    host_facts=HostFacts(facts={"sensitive": False}),
                    policy_scope="scope.auth",
                    requester_id="req-1",
                    evaluated_at="2026-06-01T10:20:00Z",
                    approval=sensitive_approval,
                    retrieved_evidence=self._evidence(),
                )
            if resolver_mode["kind"] == "status":
                return ResolvedAction(
                    planned_effect=status_planned,
                    host_facts=HostFacts(facts={"sensitive": True}),
                    policy_scope="scope.auth",
                    requester_id="req-1",
                    evaluated_at="2026-06-01T10:22:00Z",
                    approval=sensitive_approval,
                )
            return ResolvedAction(
                planned_effect=sensitive_planned,
                host_facts=HostFacts(facts={"sensitive": True}),
                policy_scope="scope.auth",
                requester_id="req-1",
                evaluated_at="2026-06-01T10:25:00Z",
                approval=sensitive_approval,
                retrieved_evidence=self._evidence(),
            )

        controller = WorkflowController(
            Governor(),
            "run-non-consume",
            v3,
            recorder=ListRec(),
            policy=EnforcementPolicy(mode="guarded"),
            effect_governance=EffectGovernanceConfig(
                store=store,
                resolver=_CallbackResolver(resolve_fn),
                observer=_CallbackObserver(
                    lambda _in, _res: ObservedEffect(status="confirmed", evidence_ref="ok")
                ),
                policy_scope="scope.auth",
            ),
        )
        controller.begin(ctx)

        # 1. Non-sensitive ops@example.com with sensitive_approval attached does NOT bind or consume it
        out_ops = controller.execute(
            ActionProposal(tool_name="send_notification", arguments={"recipient": "ops@example.com"}),
            ctx,
            lambda _p: "ops-sent",
        )
        self.assertTrue(out_ops.executed)
        assert out_ops.effect is not None
        self.assertIsNone(out_ops.effect.approval_id)
        self.assertIsNone(store.snapshot("scope.auth").approval_by_id("appr-sensitive-only"))
        self.assertTrue(all(ev.approval_id is None for ev in recorded))

        # 2. Unrelated non-governed tool list_status also does NOT bind or consume sensitive_approval
        resolver_mode["kind"] = "status"
        out_status = controller.execute(
            ActionProposal(tool_name="list_status", arguments={}),
            ctx,
            lambda _p: "status-ok",
        )
        self.assertTrue(out_status.executed)
        assert out_status.effect is not None
        self.assertIsNone(out_status.effect.approval_id)
        self.assertIsNone(store.snapshot("scope.auth").approval_by_id("appr-sensitive-only"))

        # 3. Intended sensitive alerts@example.com immediately succeeds and consumes sensitive_approval
        resolver_mode["kind"] = "alerts"
        out_alerts = controller.execute(
            ActionProposal(tool_name="send_notification", arguments={"recipient": "alerts@example.com"}),
            ctx,
            lambda _p: "alerts-sent",
        )
        self.assertTrue(out_alerts.executed)
        assert out_alerts.effect is not None
        self.assertEqual(out_alerts.effect.approval_id, "appr-sensitive-only")
        self.assertEqual(
            store.snapshot("scope.auth").approval_by_id("appr-sensitive-only").status,
            "consumed",
        )


if __name__ == "__main__":
    unittest.main()
