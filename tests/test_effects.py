# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import threading
import unittest
from copy import deepcopy
from types import MappingProxyType
from typing import Any

from pydantic import ValidationError

from vogtcon.effects import (
    ApprovalReuseError,
    CompensationRecord,
    ConcurrencyError,
    EffectGovernanceConfig,
    EffectGovernanceError,
    EffectObservationError,
    EffectResolutionError,
    InMemoryEffectStore,
    ObservationInput,
    ObservedEffect,
    ReconciliationError,
    ReconciliationRecord,
    ResolvedAction,
    ScopeSuspendedError,
)
from vogtcon.models import (
    ActionProposal,
    ExecutionContext,
    HostApproval,
    HostFacts,
    PlannedEffect,
    RetrievedEvidence,
)


def _sample_digest(seed: str = "a") -> str:
    return "sha256:" + (seed * 64)[:64]


class _DummyResolver:
    def resolve(
        self, action: ActionProposal, context: ExecutionContext
    ) -> ResolvedAction:
        return ResolvedAction(
            planned_effect=PlannedEffect(
                tool_name=action.tool_name,
                parameters=dict(action.arguments),
            ),
            host_facts=HostFacts(facts=dict(context.state)),
        )


class _DummyObserver:
    def observe(
        self, observation: ObservationInput, *, tool_result: Any = None
    ) -> ObservedEffect:
        return ObservedEffect(status="confirmed", evidence_ref="ev-ok")


class HostInterfaceModelTests(unittest.TestCase):
    def test_resolved_action_and_observation_input_strict_validation(self) -> None:
        effect = PlannedEffect(
            tool_name="send_notification",
            parameters={"recipient": "ops@example.com"},
        )
        resolved = ResolvedAction(planned_effect=effect, policy_scope="scope.alpha")
        self.assertEqual(resolved.planned_effect, effect)
        self.assertEqual(resolved.host_facts, HostFacts())
        self.assertEqual(resolved.policy_scope, "scope.alpha")
        self.assertEqual(deepcopy(resolved), resolved)
        self.assertEqual(resolved.model_copy(deep=True), resolved)

        updated_resolved = resolved.model_copy(update={"policy_scope": "scope.beta"})
        self.assertEqual(updated_resolved.policy_scope, "scope.beta")
        with self.assertRaises(ValidationError):
            resolved.model_copy(update={"policy_scope": " invalid scope "})

        obs_returned = ObservationInput(
            effect_id="eff-000001",
            run_id="run-1",
            policy_scope="scope.alpha",
            planned_effect=effect,
            invocation_outcome="returned",
        )
        self.assertIsNone(obs_returned.error_type)
        self.assertEqual(deepcopy(obs_returned), obs_returned)
        self.assertEqual(obs_returned.model_copy(deep=True), obs_returned)

        obs_raised = ObservationInput(
            effect_id="eff-000001",
            run_id="run-1",
            planned_effect=effect,
            invocation_outcome="raised",
            error_type="TimeoutError",
        )
        self.assertEqual(obs_raised.error_type, "TimeoutError")

        with self.assertRaisesRegex(
            ValidationError,
            "error_type is not accepted when invocation_outcome is 'returned'",
        ):
            ObservationInput(
                effect_id="eff-000001",
                run_id="run-1",
                planned_effect=effect,
                invocation_outcome="returned",
                error_type="TimeoutError",
            )
        with self.assertRaisesRegex(
            ValidationError,
            "error_type is required when invocation_outcome is 'raised'",
        ):
            ObservationInput(
                effect_id="eff-000001",
                run_id="run-1",
                planned_effect=effect,
                invocation_outcome="raised",
            )
        with self.assertRaises(ValidationError):
            obs_returned.model_copy(update={"error_type": "RuntimeError"})

    def test_observed_reconciliation_and_compensation_deep_immutability_and_no_secret_leaks(
        self,
    ) -> None:
        raw_meta: dict[str, Any] = {
            "provider": "spei",
            "nested": {"tags": ["t1", "t2"], "flags": {"verified": True}},
        }
        obs = ObservedEffect(
            status="confirmed",
            evidence_ref="ev-1",
            metadata=raw_meta,
        )
        rec = ReconciliationRecord(
            effect_id="eff-000001",
            resolved_status="confirmed_absent",
            evidence_ref="audit-ref-1",
            policy_scope="scope.1",
            metadata=raw_meta,
        )
        comp = CompensationRecord(
            compensates_effect_id="eff-000001",
            tool_name="refund_payment",
            operation_digest=_sample_digest("b"),
            evidence_ref="refund-ref-1",
            policy_scope="scope.1",
            metadata=raw_meta,
        )

        # Mutate caller input after construction
        raw_meta["provider"] = "tampered"
        raw_meta["nested"]["tags"].append("t3")
        raw_meta["nested"]["flags"]["verified"] = False

        for model in (obs, rec, comp):
            with self.subTest(model=type(model).__name__):
                self.assertIsInstance(model.metadata, MappingProxyType)
                self.assertEqual(model.metadata["provider"], "spei")
                self.assertEqual(model.metadata["nested"]["tags"], ("t1", "t2"))
                with self.assertRaises(TypeError):
                    model.metadata["provider"] = "hacked"  # type: ignore[index]
                with self.assertRaises(AttributeError):
                    model.metadata["nested"]["tags"].append("x")  # type: ignore[union-attr]
                with self.assertRaises(TypeError):
                    model.metadata["nested"]["flags"]["verified"] = False  # type: ignore[index]

                for dumped in (
                    model.model_dump(),
                    model.model_dump(mode="json"),
                    json.loads(model.model_dump_json()),
                ):
                    self.assertIs(type(dumped["metadata"]), dict)
                    self.assertIs(type(dumped["metadata"]["nested"]["tags"]), list)

                self.assertEqual(deepcopy(model), model)
                copied = model.model_copy(
                    update={"metadata": {"updated": ["a"]}}, deep=True
                )
                self.assertIsInstance(copied.metadata, MappingProxyType)
                self.assertEqual(copied.metadata["updated"], ("a",))

        # Invalid statuses, digests, and secret sentinel non-leakage
        sentinel = "TOP_SECRET_EFFECT_PAYLOAD_777"
        for invalid_call in (
            lambda: ObservedEffect(status=sentinel),  # type: ignore[arg-type]
            lambda: ReconciliationRecord(
                effect_id="eff-000001",
                resolved_status="uncertain",  # type: ignore[arg-type]
                evidence_ref=sentinel,
            ),
            lambda: ReconciliationRecord(
                effect_id="eff-000001",
                resolved_status="reserved",  # type: ignore[arg-type]
                evidence_ref=sentinel,
            ),
            lambda: ReconciliationRecord(
                effect_id="eff-000001",
                resolved_status="confirmed",
                evidence_ref="",
            ),
            lambda: CompensationRecord(
                compensates_effect_id="eff-000001",
                tool_name="refund",
                operation_digest=sentinel,
                evidence_ref="ref-1",
            ),
        ):
            with self.assertRaises(ValidationError) as ctx:
                invalid_call()
            self.assertNotIn(sentinel, str(ctx.exception))

    def test_operational_exception_hierarchy_and_config_validation(self) -> None:
        err = ScopeSuspendedError(
            policy_scope="tenant.mx",
            uncertain_effect_ids=["eff-000001", "eff-000002"],
        )
        self.assertIsInstance(err, EffectGovernanceError)
        self.assertIsInstance(err, RuntimeError)
        self.assertEqual(err.policy_scope, "tenant.mx")
        self.assertEqual(err.uncertain_effect_ids, ("eff-000001", "eff-000002"))
        self.assertIn("tenant.mx", str(err))
        self.assertIn("eff-000001, eff-000002", str(err))

        undelimited_err = ScopeSuspendedError(
            policy_scope=None, uncertain_effect_ids=("eff-000003",)
        )
        self.assertIsNone(undelimited_err.policy_scope)
        self.assertIn("undelimited scope", str(undelimited_err))

        self.assertTrue(issubclass(ConcurrencyError, EffectGovernanceError))
        self.assertTrue(issubclass(EffectResolutionError, EffectGovernanceError))
        self.assertTrue(issubclass(EffectObservationError, EffectGovernanceError))
        self.assertTrue(issubclass(ReconciliationError, ValueError))

        store = InMemoryEffectStore()
        resolver = _DummyResolver()
        observer = _DummyObserver()
        cfg = EffectGovernanceConfig(
            store=store,
            resolver=resolver,
            observer=observer,
            policy_scope="tenant.mx",
        )
        self.assertEqual(cfg.policy_scope, "tenant.mx")

        with self.assertRaisesRegex(ValueError, "Invalid policy_scope"):
            EffectGovernanceConfig(
                store=store,
                resolver=resolver,
                observer=observer,
                policy_scope="bad scope!",
            )
        with self.assertRaisesRegex(TypeError, "callable resolve"):
            EffectGovernanceConfig(
                store=store,
                resolver=object(),  # type: ignore[arg-type]
                observer=observer,
            )
        with self.assertRaisesRegex(TypeError, "callable observe"):
            EffectGovernanceConfig(
                store=store,
                resolver=resolver,
                observer=object(),  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(TypeError, "implement callable"):
            EffectGovernanceConfig(
                store=object(),  # type: ignore[arg-type]
                resolver=resolver,
                observer=observer,
            )


class InMemoryEffectStoreTests(unittest.TestCase):
    def test_reserve_observe_append_only_trajectory_and_no_reset_methods(self) -> None:
        store = InMemoryEffectStore()
        for forbidden_method in ("reset_scope", "clear", "delete", "reset", "remove"):
            self.assertFalse(hasattr(store, forbidden_method))

        self.assertIn("Crash/restart boundary", InMemoryEffectStore.__doc__ or "")

        res1 = store.reserve(
            run_id="run-1",
            policy_scope="scope.a",
            action_index=1,
            tool_name="transfer_funds",
            operation_digest=_sample_digest("1"),
            metadata={"attempt": 1, "tags": ["initial"]},
        )
        self.assertEqual(res1.effect_id, "eff-000001")
        self.assertEqual(res1.status, "reserved")
        self.assertFalse(store.is_scope_suspended("scope.a"))

        obs1 = store.record_observation(
            effect_id=res1.effect_id,
            status="confirmed",
            evidence_ref="bank-tx-101",
            metadata={"bank_code": "SPEI", "tags": ["settled"]},
        )
        self.assertEqual(obs1.status, "confirmed")
        self.assertEqual(obs1.evidence_ref, "bank-tx-101")
        self.assertEqual(
            dict(obs1.metadata),
            {"attempt": 1, "bank_code": "SPEI", "tags": ("settled",)},
        )

        res2 = store.reserve(
            run_id="run-1",
            policy_scope="scope.a",
            action_index=2,
            tool_name="send_notification",
            operation_digest=_sample_digest("2"),
        )
        obs2 = store.record_observation(
            effect_id=res2.effect_id,
            status="confirmed_absent",
            evidence_ref="not-sent-400",
        )
        self.assertEqual(obs2.status, "confirmed_absent")

        view = store.snapshot("scope.a")
        self.assertEqual(view.policy_scope, "scope.a")
        self.assertFalse(view.suspended)
        self.assertEqual(view.uncertain_effect_ids, ())
        self.assertEqual([e.sequence for e in view.entries], [1, 2, 3, 4])
        self.assertEqual(
            [(e.kind, e.status, e.effect_id) for e in view.entries],
            [
                ("reserved", "reserved", "eff-000001"),
                ("observed", "confirmed", "eff-000001"),
                ("reserved", "reserved", "eff-000002"),
                ("observed", "confirmed_absent", "eff-000002"),
            ],
        )
        # Prior reserved entry metadata is preserved unchanged (INV-07)
        self.assertEqual(
            dict(view.entries[0].metadata),
            {"attempt": 1, "tags": ("initial",)},
        )
        self.assertEqual(len(view.effects), 2)
        self.assertEqual(view.effect_by_id("eff-000001"), obs1)
        self.assertEqual(view.effect_by_id("eff-000002"), obs2)

        # Deep immutability of returned TrajectoryView
        with self.assertRaises(AttributeError):
            view.entries.append(view.entries[0])  # type: ignore[attr-defined]
        with self.assertRaises(AttributeError):
            view.effects.append(obs1)  # type: ignore[attr-defined]
        with self.assertRaises(TypeError):
            view.effects[0].metadata["attempt"] = 99  # type: ignore[index]
        with self.assertRaises(AttributeError):
            view.effects[0].metadata["tags"].append("hacked")  # type: ignore[union-attr]


class ConcurrencyRejectionTests(unittest.TestCase):
    def test_overlapping_reservation_on_same_scope_fails_closed(self) -> None:
        store = InMemoryEffectStore()
        first = store.reserve(
            run_id="run-1",
            policy_scope="scope.concurrent",
            action_index=1,
            tool_name="transfer_funds",
            operation_digest=_sample_digest("1"),
        )
        with self.assertRaisesRegex(
            ConcurrencyError, "already has an active reserved effect"
        ):
            store.reserve(
                run_id="run-1",
                policy_scope="scope.concurrent",
                action_index=2,
                tool_name="transfer_funds",
                operation_digest=_sample_digest("2"),
            )

        # Distinct scope is not blocked by in-flight reservation on scope.concurrent
        other = store.reserve(
            run_id="run-2",
            policy_scope="scope.other",
            action_index=1,
            tool_name="transfer_funds",
            operation_digest=_sample_digest("3"),
        )
        self.assertEqual(other.effect_id, "eff-000002")

        # First reservation is still intact and can be finalized
        finalized = store.record_observation(
            effect_id=first.effect_id,
            status="confirmed",
            evidence_ref="tx-1",
        )
        self.assertEqual(finalized.status, "confirmed")

        # Undelimited scope (policy_scope=None) also rejects overlapping reservation
        undelimited = store.reserve(
            run_id="run-3",
            policy_scope=None,
            action_index=1,
            tool_name="transfer_funds",
            operation_digest=_sample_digest("4"),
        )
        with self.assertRaises(ConcurrencyError):
            store.reserve(
                run_id="run-3",
                policy_scope=None,
                action_index=2,
                tool_name="transfer_funds",
                operation_digest=_sample_digest("5"),
            )
        store.record_observation(
            effect_id=undelimited.effect_id,
            status="confirmed_absent",
        )

    def test_deterministic_lock_contention_raises_concurrency_error(self) -> None:
        store = InMemoryEffectStore()
        lock_acquired = threading.Event()
        release_lock = threading.Event()

        def hold_store_lock() -> None:
            with store._acquire_lock():
                lock_acquired.set()
                release_lock.wait(timeout=5.0)

        holder = threading.Thread(target=hold_store_lock)
        holder.start()
        try:
            self.assertTrue(lock_acquired.wait(timeout=5.0))
            with self.assertRaisesRegex(
                ConcurrencyError,
                "Concurrent access to InMemoryEffectStore is not supported",
            ):
                store.snapshot("scope.a")
            with self.assertRaises(ConcurrencyError):
                store.reserve(
                    run_id="run-1",
                    policy_scope="scope.a",
                    action_index=1,
                    tool_name="transfer_funds",
                    operation_digest=_sample_digest("1"),
                )
        finally:
            release_lock.set()
            holder.join(timeout=5.0)

    def test_reserve_expected_last_sequence_atomic_cas_and_scope_isolation(
        self,
    ) -> None:
        store = InMemoryEffectStore()

        for bad_seq in (-1, -100, True, False, "0", 1.5):
            with self.subTest(bad_seq=repr(bad_seq)):
                with self.assertRaisesRegex(
                    ValueError,
                    "expected_last_sequence must be a non-negative integer",
                ):
                    store.reserve(
                        run_id="run-1",
                        policy_scope="scope.a",
                        action_index=1,
                        tool_name="transfer_funds",
                        operation_digest=_sample_digest("1"),
                        expected_last_sequence=bad_seq,  # type: ignore[arg-type]
                    )

        # Non-zero expected_last_sequence fails on empty scope without mutating store
        with self.assertRaisesRegex(
            ConcurrencyError,
            "Policy scope trajectory changed between evaluation and reservation",
        ):
            store.reserve(
                run_id="run-1",
                policy_scope="scope.a",
                action_index=1,
                tool_name="transfer_funds",
                operation_digest=_sample_digest("1"),
                expected_last_sequence=1,
            )
        self.assertEqual(store.snapshot("scope.a").entries, ())

        # expected_last_sequence=0 succeeds on empty scope.a (creates sequence 1)
        res1 = store.reserve(
            run_id="run-1",
            policy_scope="scope.a",
            action_index=1,
            tool_name="transfer_funds",
            operation_digest=_sample_digest("1"),
            expected_last_sequence=0,
        )
        self.assertEqual(res1.effect_id, "eff-000001")
        # Observation creates sequence 2 in scope.a
        store.record_observation(
            effect_id=res1.effect_id,
            status="confirmed",
            evidence_ref="tx-1",
        )
        self.assertEqual(store.snapshot("scope.a").entries[-1].sequence, 2)

        # Stale expected_last_sequence=0 (or 1) fails without mutating store
        for stale_seq in (0, 1, 99):
            with self.subTest(stale_seq=stale_seq):
                with self.assertRaisesRegex(
                    ConcurrencyError,
                    "Policy scope trajectory changed between evaluation and reservation",
                ):
                    store.reserve(
                        run_id="run-2",
                        policy_scope="scope.a",
                        action_index=1,
                        tool_name="transfer_funds",
                        operation_digest=_sample_digest("2"),
                        expected_last_sequence=stale_seq,
                    )
        self.assertEqual(len(store.snapshot("scope.a").entries), 2)
        self.assertEqual(len(store.snapshot("scope.a").effects), 1)

        # Activity in scope.b (sequences 3 and 4) does NOT invalidate scope.a's last sequence (2)
        res_b = store.reserve(
            run_id="run-b",
            policy_scope="scope.b",
            action_index=1,
            tool_name="transfer_funds",
            operation_digest=_sample_digest("b"),
            expected_last_sequence=0,
        )
        store.record_observation(
            effect_id=res_b.effect_id,
            status="confirmed",
            evidence_ref="tx-b",
        )
        self.assertEqual(store.snapshot("scope.b").entries[-1].sequence, 4)

        # Matching expected_last_sequence=2 for scope.a succeeds (creates sequence 5, then 6 on observe)
        res2 = store.reserve(
            run_id="run-2",
            policy_scope="scope.a",
            action_index=1,
            tool_name="transfer_funds",
            operation_digest=_sample_digest("2"),
            expected_last_sequence=2,
        )
        self.assertEqual(res2.effect_id, "eff-000003")
        store.record_observation(
            effect_id=res2.effect_id,
            status="uncertain",
            evidence_ref="timeout-2",
        )
        # Reconciliation creates sequence 7 in scope.a
        store.reconcile(
            ReconciliationRecord(
                effect_id=res2.effect_id,
                resolved_status="confirmed",
                evidence_ref="reconciled-2",
                policy_scope="scope.a",
            )
        )
        with self.assertRaises(ConcurrencyError):
            store.reserve(
                run_id="run-3",
                policy_scope="scope.a",
                action_index=1,
                tool_name="transfer_funds",
                operation_digest=_sample_digest("3"),
                expected_last_sequence=6,
            )

        # Compensation creates sequence 8 in scope.a
        store.record_compensation(
            run_id="run-3",
            compensation=CompensationRecord(
                compensates_effect_id=res2.effect_id,
                tool_name="refund_funds",
                operation_digest=_sample_digest("c"),
                evidence_ref="comp-2",
                policy_scope="scope.a",
            ),
        )
        with self.assertRaises(ConcurrencyError):
            store.reserve(
                run_id="run-3",
                policy_scope="scope.a",
                action_index=1,
                tool_name="transfer_funds",
                operation_digest=_sample_digest("3"),
                expected_last_sequence=7,
            )
        res3 = store.reserve(
            run_id="run-3",
            policy_scope="scope.a",
            action_index=1,
            tool_name="transfer_funds",
            operation_digest=_sample_digest("3"),
            expected_last_sequence=8,
        )
        self.assertEqual(res3.effect_id, "eff-000005")


class SharedScopeTests(unittest.TestCase):
    def test_cross_run_scope_continuity_and_scope_isolation(self) -> None:
        store = InMemoryEffectStore()
        r1 = store.reserve(
            run_id="run-alpha",
            policy_scope="tenant.shared",
            action_index=1,
            tool_name="transfer_funds",
            operation_digest=_sample_digest("a"),
        )
        store.record_observation(
            effect_id=r1.effect_id,
            status="confirmed",
            evidence_ref="tx-alpha",
        )

        # Second run on same policy_scope sees run-alpha's confirmed effect
        r2 = store.reserve(
            run_id="run-beta",
            policy_scope="tenant.shared",
            action_index=1,
            tool_name="transfer_funds",
            operation_digest=_sample_digest("b"),
        )
        store.record_observation(
            effect_id=r2.effect_id,
            status="uncertain",
            evidence_ref="timeout-beta",
        )

        # Scope is now suspended across ALL runs targeting tenant.shared (INV-11)
        self.assertTrue(store.is_scope_suspended("tenant.shared"))
        self.assertEqual(store.uncertain_effects("tenant.shared"), (r2.effect_id,))
        with self.assertRaises(ScopeSuspendedError) as ctx:
            store.reserve(
                run_id="run-gamma",
                policy_scope="tenant.shared",
                action_index=1,
                tool_name="transfer_funds",
                operation_digest=_sample_digest("c"),
            )
        self.assertEqual(ctx.exception.policy_scope, "tenant.shared")
        self.assertEqual(ctx.exception.uncertain_effect_ids, (r2.effect_id,))

        # Another scope on the same store remains completely unaffected
        self.assertFalse(store.is_scope_suspended("tenant.other"))
        r_other = store.reserve(
            run_id="run-gamma",
            policy_scope="tenant.other",
            action_index=1,
            tool_name="transfer_funds",
            operation_digest=_sample_digest("d"),
        )
        store.record_observation(
            effect_id=r_other.effect_id,
            status="confirmed",
            evidence_ref="tx-other",
        )
        self.assertEqual(len(store.snapshot("tenant.other").effects), 1)
        self.assertEqual(len(store.snapshot("tenant.shared").effects), 2)


class ReconciliationTests(unittest.TestCase):
    def test_reconcile_resolves_uncertainty_preserves_history_and_lifts_suspension(
        self,
    ) -> None:
        store = InMemoryEffectStore()
        res = store.reserve(
            run_id="run-1",
            policy_scope="scope.rec",
            action_index=1,
            tool_name="transfer_funds",
            operation_digest=_sample_digest("1"),
            metadata={"origin": "wire"},
        )
        store.record_observation(
            effect_id=res.effect_id,
            status="uncertain",
            evidence_ref="net-timeout",
            metadata={"timeout_ms": 5000},
        )
        self.assertTrue(store.is_scope_suspended("scope.rec"))

        reconciled = store.reconcile(
            ReconciliationRecord(
                effect_id=res.effect_id,
                resolved_status="confirmed_absent",
                evidence_ref="ledger-check-absent-1",
                policy_scope="scope.rec",
                metadata={"auditor": "sec-ops"},
            )
        )
        self.assertEqual(reconciled.status, "confirmed_absent")
        self.assertEqual(reconciled.evidence_ref, "ledger-check-absent-1")
        self.assertEqual(
            dict(reconciled.metadata),
            {"origin": "wire", "timeout_ms": 5000, "auditor": "sec-ops"},
        )
        self.assertFalse(store.is_scope_suspended("scope.rec"))
        self.assertEqual(store.uncertain_effects("scope.rec"), ())

        # Trajectory preserves reserved -> observed(uncertain) -> reconciled(confirmed_absent)
        view = store.snapshot("scope.rec")
        self.assertEqual(
            [(e.sequence, e.kind, e.status, e.evidence_ref) for e in view.entries],
            [
                (1, "reserved", "reserved", None),
                (2, "observed", "uncertain", "net-timeout"),
                (3, "reconciled", "confirmed_absent", "ledger-check-absent-1"),
            ],
        )

        # Scope can now reserve new effects
        next_res = store.reserve(
            run_id="run-1",
            policy_scope="scope.rec",
            action_index=2,
            tool_name="transfer_funds",
            operation_digest=_sample_digest("2"),
        )
        self.assertEqual(next_res.effect_id, "eff-000002")

    def test_reconcile_rejects_unknown_non_uncertain_repeated_and_scope_mismatched_effects(
        self,
    ) -> None:
        store = InMemoryEffectStore()
        with self.assertRaisesRegex(
            ReconciliationError, "Unknown effect_id for reconciliation"
        ):
            store.reconcile(
                ReconciliationRecord(
                    effect_id="eff-999999",
                    resolved_status="confirmed",
                    evidence_ref="ev-missing",
                )
            )

        res = store.reserve(
            run_id="run-1",
            policy_scope="scope.a",
            action_index=1,
            tool_name="transfer_funds",
            operation_digest=_sample_digest("1"),
        )
        # Cannot reconcile while still reserved
        with self.assertRaisesRegex(
            ReconciliationError, "Only uncertain effects can be reconciled"
        ):
            store.reconcile(
                ReconciliationRecord(
                    effect_id=res.effect_id,
                    resolved_status="confirmed",
                    evidence_ref="ev-reserved",
                )
            )

        store.record_observation(
            effect_id=res.effect_id,
            status="uncertain",
            evidence_ref="timeout",
        )

        # Mismatched policy_scope rejected without mutating trajectory
        with self.assertRaisesRegex(
            ReconciliationError,
            "Reconciliation policy_scope does not match target effect",
        ):
            store.reconcile(
                ReconciliationRecord(
                    effect_id=res.effect_id,
                    resolved_status="confirmed",
                    evidence_ref="ev-wrong-scope",
                    policy_scope="scope.other",
                )
            )
        self.assertTrue(store.is_scope_suspended("scope.a"))

        # Valid reconciliation succeeds once
        store.reconcile(
            ReconciliationRecord(
                effect_id=res.effect_id,
                resolved_status="confirmed",
                evidence_ref="ev-confirmed",
                policy_scope="scope.a",
            )
        )

        # Repeated or contradictory reconciliation on already-reconciled effect fails
        for repeat_status in ("confirmed", "confirmed_absent"):
            with self.subTest(repeat_status=repeat_status):
                with self.assertRaisesRegex(
                    ReconciliationError, "Only uncertain effects can be reconciled"
                ):
                    store.reconcile(
                        ReconciliationRecord(
                            effect_id=res.effect_id,
                            resolved_status=repeat_status,  # type: ignore[arg-type]
                            evidence_ref="ev-repeat",
                        )
                    )
        self.assertEqual(len(store.snapshot("scope.a").entries), 3)


class CompensationTests(unittest.TestCase):
    def test_compensation_creates_new_linked_effect_without_erasing_target(
        self,
    ) -> None:
        store = InMemoryEffectStore()
        res = store.reserve(
            run_id="run-1",
            policy_scope="scope.pay",
            action_index=1,
            tool_name="charge_card",
            operation_digest=_sample_digest("1"),
        )
        confirmed = store.record_observation(
            effect_id=res.effect_id,
            status="confirmed",
            evidence_ref="charge-101",
        )

        comp_record = store.record_compensation(
            run_id="run-2",
            compensation=CompensationRecord(
                compensates_effect_id=confirmed.effect_id,
                tool_name="refund_card",
                operation_digest=_sample_digest("2"),
                evidence_ref="refund-202",
                policy_scope="scope.pay",
                metadata={"reason": "customer_cancel"},
            ),
        )
        self.assertEqual(comp_record.effect_id, "eff-000002")
        self.assertEqual(comp_record.status, "confirmed")
        self.assertEqual(comp_record.compensates_effect_id, confirmed.effect_id)
        self.assertEqual(comp_record.run_id, "run-2")
        self.assertEqual(comp_record.policy_scope, "scope.pay")

        view = store.snapshot("scope.pay")
        # Original confirmed effect remains confirmed and unmutated (INV-07)
        self.assertEqual(view.effect_by_id("eff-000001"), confirmed)
        self.assertEqual(view.effect_by_id("eff-000002"), comp_record)
        self.assertEqual(
            [(e.sequence, e.kind, e.effect_id, e.compensates_effect_id) for e in view.entries],
            [
                (1, "reserved", "eff-000001", None),
                (2, "observed", "eff-000001", None),
                (3, "compensated", "eff-000002", "eff-000001"),
            ],
        )

    def test_compensation_rejects_unknown_non_confirmed_and_mismatched_scope_targets(
        self,
    ) -> None:
        store = InMemoryEffectStore()
        with self.assertRaisesRegex(
            ReconciliationError, "Unknown target effect_id for compensation"
        ):
            store.record_compensation(
                run_id="run-1",
                compensation=CompensationRecord(
                    compensates_effect_id="eff-999999",
                    tool_name="refund",
                    operation_digest=_sample_digest("1"),
                    evidence_ref="ref-1",
                ),
            )

        # Reserved effect cannot be compensated
        res_reserved = store.reserve(
            run_id="run-1",
            policy_scope="scope.1",
            action_index=1,
            tool_name="charge",
            operation_digest=_sample_digest("1"),
        )
        with self.assertRaisesRegex(
            ReconciliationError, "Only confirmed effects can be compensated"
        ):
            store.record_compensation(
                run_id="run-1",
                compensation=CompensationRecord(
                    compensates_effect_id=res_reserved.effect_id,
                    tool_name="refund",
                    operation_digest=_sample_digest("2"),
                    evidence_ref="ref-2",
                ),
            )

        # Absent effect cannot be compensated
        store.record_observation(
            effect_id=res_reserved.effect_id,
            status="confirmed_absent",
            evidence_ref="absent-1",
        )
        with self.assertRaisesRegex(
            ReconciliationError, "Only confirmed effects can be compensated"
        ):
            store.record_compensation(
                run_id="run-1",
                compensation=CompensationRecord(
                    compensates_effect_id=res_reserved.effect_id,
                    tool_name="refund",
                    operation_digest=_sample_digest("2"),
                    evidence_ref="ref-2",
                ),
            )

        # Uncertain effect cannot be compensated
        res_uncertain = store.reserve(
            run_id="run-1",
            policy_scope="scope.1",
            action_index=2,
            tool_name="charge",
            operation_digest=_sample_digest("3"),
        )
        store.record_observation(
            effect_id=res_uncertain.effect_id,
            status="uncertain",
            evidence_ref="timeout-1",
        )
        with self.assertRaisesRegex(
            ReconciliationError, "Only confirmed effects can be compensated"
        ):
            store.record_compensation(
                run_id="run-1",
                compensation=CompensationRecord(
                    compensates_effect_id=res_uncertain.effect_id,
                    tool_name="refund",
                    operation_digest=_sample_digest("4"),
                    evidence_ref="ref-4",
                ),
            )

        # Reconcile to confirmed, then test scope mismatch rejection
        store.reconcile(
            ReconciliationRecord(
                effect_id=res_uncertain.effect_id,
                resolved_status="confirmed",
                evidence_ref="reconciled-1",
            )
        )
        with self.assertRaisesRegex(
            ReconciliationError,
            "Compensation policy_scope does not match target effect",
        ):
            store.record_compensation(
                run_id="run-1",
                compensation=CompensationRecord(
                    compensates_effect_id=res_uncertain.effect_id,
                    tool_name="refund",
                    operation_digest=_sample_digest("4"),
                    evidence_ref="ref-4",
                    policy_scope="scope.other",
                ),
            )


class ApprovalStoreTests(unittest.TestCase):
    def test_resolved_action_authorization_fields_and_deep_immutability(self) -> None:
        effect = PlannedEffect(
            tool_name="send_notification",
            parameters={"destination": "ops@example.com"},
        )
        approval = HostApproval(
            approval_id="app-100",
            operation_digest=effect.operation_digest(),
            requester_id="alice",
            approver_id="bob",
            approver_authorities=["notify.approve"],
            policy_scope="scope.ops",
            issued_at="2026-11-27T10:00:00Z",
            expires_at="2026-11-27T11:00:00Z",
        )
        ev_list = [RetrievedEvidence(evidence_id="doc-1", source="kb")]
        resolved = ResolvedAction(
            planned_effect=effect,
            policy_scope="scope.ops",
            requester_id="alice",
            evaluated_at="2026-11-27T10:05:00Z",
            approval=approval,
            retrieved_evidence=ev_list,
        )
        ev_list.clear()
        assert resolved.retrieved_evidence is not None
        self.assertEqual(len(resolved.retrieved_evidence), 1)
        self.assertIsInstance(resolved.retrieved_evidence, tuple)
        self.assertEqual(deepcopy(resolved), resolved)
        copied = resolved.model_copy(update={"requester_id": "carol"})
        self.assertEqual(copied.requester_id, "carol")
        self.assertEqual(copied.approval, approval)

    def test_single_use_consume_uncertain_lock_reconcile_retry_and_compensation(
        self,
    ) -> None:
        store = InMemoryEffectStore()
        d1 = _sample_digest("1")
        d2 = _sample_digest("2")

        # Non-null policy_scope required for bound approval
        with self.assertRaisesRegex(ValueError, "non-null policy_scope"):
            store.reserve(
                run_id="run-1",
                policy_scope=None,
                action_index=1,
                tool_name="transfer",
                operation_digest=d1,
                approval_id="app-null",
            )

        # 1. Reserve -> confirmed -> consumed -> replay rejected (including across runs)
        r1 = store.reserve(
            run_id="run-1",
            policy_scope="scope.pay",
            action_index=1,
            tool_name="transfer",
            operation_digest=d1,
            approval_id="app-single",
        )
        self.assertEqual(r1.approval_id, "app-single")
        self.assertEqual(
            store.snapshot("scope.pay").approval_by_id("app-single").status,  # type: ignore[union-attr]
            "reserved",
        )

        # While reserved, cross-scope, modified digest, or single_use downgrade rejected
        with self.assertRaisesRegex(ApprovalReuseError, "different operation_digest"):
            store.reserve(
                run_id="run-2",
                policy_scope="scope.other",
                action_index=1,
                tool_name="transfer",
                operation_digest=d2,
                approval_id="app-single",
            )
        with self.assertRaisesRegex(ApprovalReuseError, "different policy_scope"):
            store.reserve(
                run_id="run-2",
                policy_scope="scope.other",
                action_index=1,
                tool_name="transfer",
                operation_digest=d1,
                approval_id="app-single",
            )

        c1 = store.record_observation(
            effect_id=r1.effect_id, status="confirmed", evidence_ref="tx-1"
        )
        self.assertEqual(c1.approval_id, "app-single")
        self.assertEqual(
            store.snapshot("scope.pay").approval_by_id("app-single").status,  # type: ignore[union-attr]
            "consumed",
        )
        self.assertEqual(store.snapshot("scope.other").approvals, ())

        # Replay in same or new run rejected; downgrade to single_use=False rejected
        with self.assertRaisesRegex(ApprovalReuseError, "already been consumed"):
            store.reserve(
                run_id="run-2",
                policy_scope="scope.pay",
                action_index=1,
                tool_name="transfer",
                operation_digest=d1,
                approval_id="app-single",
            )
        with self.assertRaisesRegex(ApprovalReuseError, "cannot change single_use"):
            store.reserve(
                run_id="run-2",
                policy_scope="scope.pay",
                action_index=1,
                tool_name="transfer",
                operation_digest=d1,
                approval_id="app-single",
                approval_single_use=False,
            )

        # Compensation does NOT release consumed approval (INV-07)
        store.record_compensation(
            run_id="run-2",
            compensation=CompensationRecord(
                compensates_effect_id=c1.effect_id,
                tool_name="refund",
                operation_digest=_sample_digest("9"),
                evidence_ref="refund-1",
                policy_scope="scope.pay",
            ),
        )
        self.assertEqual(
            store.snapshot("scope.pay").approval_by_id("app-single").status,  # type: ignore[union-attr]
            "consumed",
        )
        with self.assertRaisesRegex(ApprovalReuseError, "already been consumed"):
            store.reserve(
                run_id="run-3",
                policy_scope="scope.pay",
                action_index=1,
                tool_name="transfer",
                operation_digest=d1,
                approval_id="app-single",
            )

        # 2. Uncertain -> locked_uncertain -> reconcile confirmed -> permanently consumed
        r2 = store.reserve(
            run_id="run-2",
            policy_scope="scope.unc",
            action_index=1,
            tool_name="transfer",
            operation_digest=d2,
            approval_id="app-unc-confirm",
        )
        store.record_observation(
            effect_id=r2.effect_id, status="uncertain", evidence_ref="timeout"
        )
        self.assertEqual(
            store.snapshot("scope.unc").approval_by_id("app-unc-confirm").status,  # type: ignore[union-attr]
            "locked_uncertain",
        )
        with self.assertRaises(ScopeSuspendedError):
            store.reserve(
                run_id="run-3",
                policy_scope="scope.unc",
                action_index=1,
                tool_name="transfer",
                operation_digest=d2,
                approval_id="app-unc-confirm",
            )
        # Defense-in-depth: even if scope suspension were bypassed, locked_uncertain still rejects reuse
        store._effects[r2.effect_id] = store._effects[r2.effect_id].model_copy(
            update={"status": "confirmed_absent"}
        )
        with self.assertRaisesRegex(
            ApprovalReuseError, "locked by an unresolved uncertain effect"
        ):
            store.reserve(
                run_id="run-3",
                policy_scope="scope.unc",
                action_index=1,
                tool_name="transfer",
                operation_digest=d2,
                approval_id="app-unc-confirm",
            )
        store._effects[r2.effect_id] = store._effects[r2.effect_id].model_copy(
            update={"status": "uncertain"}
        )
        reconciled_c = store.reconcile(
            ReconciliationRecord(
                effect_id=r2.effect_id,
                resolved_status="confirmed",
                evidence_ref="audit-confirmed",
                policy_scope="scope.unc",
            )
        )
        self.assertEqual(reconciled_c.approval_id, "app-unc-confirm")
        with self.assertRaisesRegex(ApprovalReuseError, "already been consumed"):
            store.reserve(
                run_id="run-3",
                policy_scope="scope.unc",
                action_index=1,
                tool_name="transfer",
                operation_digest=d2,
                approval_id="app-unc-confirm",
            )

        # 3. Uncertain -> reconcile confirmed_absent -> released_absent -> retry gating
        d3 = _sample_digest("3")
        r3 = store.reserve(
            run_id="run-3",
            policy_scope="scope.retry",
            action_index=1,
            tool_name="transfer",
            operation_digest=d3,
            approval_id="app-retry",
        )
        store.record_observation(
            effect_id=r3.effect_id, status="uncertain", evidence_ref="timeout-3"
        )
        store.reconcile(
            ReconciliationRecord(
                effect_id=r3.effect_id,
                resolved_status="confirmed_absent",
                evidence_ref="audit-absent",
                policy_scope="scope.retry",
            )
        )
        self.assertEqual(
            store.snapshot("scope.retry").approval_by_id("app-retry").status,  # type: ignore[union-attr]
            "released_absent",
        )

        # Retry disallowed by default
        with self.assertRaisesRegex(
            ApprovalReuseError, "after confirmed absence is not permitted"
        ):
            store.reserve(
                run_id="run-4",
                policy_scope="scope.retry",
                action_index=1,
                tool_name="transfer",
                operation_digest=d3,
                approval_id="app-retry",
                allow_retry_after_confirmed_absent=False,
            )

        # Retry with modified operation_digest ALWAYS rejected even when retry allowed
        with self.assertRaisesRegex(ApprovalReuseError, "different operation_digest"):
            store.reserve(
                run_id="run-4",
                policy_scope="scope.retry",
                action_index=1,
                tool_name="transfer",
                operation_digest=d1,
                approval_id="app-retry",
                allow_retry_after_confirmed_absent=True,
            )

        # Retry with identical operation_digest & policy_scope succeeds and increments retry_count
        r3_retry = store.reserve(
            run_id="run-4",
            policy_scope="scope.retry",
            action_index=1,
            tool_name="transfer",
            operation_digest=d3,
            approval_id="app-retry",
            allow_retry_after_confirmed_absent=True,
        )
        app_retry_state = store.snapshot("scope.retry").approval_by_id("app-retry")
        assert app_retry_state is not None
        self.assertEqual(app_retry_state.status, "reserved")
        self.assertEqual(app_retry_state.retry_count, 1)
        store.record_observation(
            effect_id=r3_retry.effect_id, status="confirmed", evidence_ref="tx-retry-ok"
        )
        self.assertEqual(
            store.snapshot("scope.retry").approval_by_id("app-retry").status,  # type: ignore[union-attr]
            "consumed",
        )


class ApprovalConcurrencyTests(unittest.TestCase):
    def test_multithread_barrier_single_use_approval_prevents_double_spend(
        self,
    ) -> None:
        digest = _sample_digest("7")
        for _ in range(25):
            store = InMemoryEffectStore()
            barrier = threading.Barrier(2)
            successes: list[str] = []
            errors: list[Exception] = []
            out_lock = threading.Lock()

            def worker(idx: int) -> None:
                barrier.wait(timeout=5.0)
                try:
                    rec = store.reserve(
                        run_id=f"run-{idx}",
                        policy_scope="scope.race",
                        action_index=1,
                        tool_name="transfer_funds",
                        operation_digest=digest,
                        approval_id="app-race-1",
                    )
                    store.record_observation(
                        effect_id=rec.effect_id,
                        status="confirmed",
                        evidence_ref=f"tx-{idx}",
                    )
                    with out_lock:
                        successes.append(rec.effect_id)
                except (ConcurrencyError, ApprovalReuseError) as exc:
                    with out_lock:
                        errors.append(exc)

            t1 = threading.Thread(target=worker, args=(1,))
            t2 = threading.Thread(target=worker, args=(2,))
            t1.start()
            t2.start()
            t1.join(timeout=5.0)
            t2.join(timeout=5.0)

            self.assertEqual(len(successes), 1)
            self.assertEqual(len(errors), 1)
            self.assertEqual(
                len(store.snapshot("scope.race").effects_by_status("confirmed")), 1
            )


if __name__ == "__main__":
    unittest.main()
