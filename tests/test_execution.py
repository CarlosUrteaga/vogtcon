# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from vogtcon import (
    ActionProposal,
    AgentContract,
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


if __name__ == "__main__":
    unittest.main()
