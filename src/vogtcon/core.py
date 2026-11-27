# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Pure deterministic checks; execution and run-level effects belong to callers."""

from __future__ import annotations

from typing import Protocol

from .contracts import validate_contract_rules
from .models import ContractRulesV3, GovernanceDecision, GovernorInput, Violation
from .rules import DEFAULT_RULE_CATALOG, RuleCatalog


class GovernorEvaluator(Protocol):
    def evaluate(self, request: GovernorInput) -> GovernanceDecision: ...


def _pre_violations(request: GovernorInput) -> list[Violation]:
    approved = [
        item if isinstance(item, str) else item.fingerprint
        for item in request.contract.approved_agent_configurations
    ]
    checks = (
        ("agent.configuration_fingerprint_match", request.context.observed_agent_fingerprint not in approved),
        ("contract.fingerprint_match", request.context.observed_contract_fingerprint != request.contract.contract_fingerprint),
    )
    return [Violation(rule=rule, phase=request.phase) for rule, failed in checks if failed]


class DeterministicEvaluator:
    """Evaluate configured rules without executing tools or mutating evidence."""

    def __init__(self, rule_catalog: RuleCatalog | None = None) -> None:
        self._rule_catalog = rule_catalog if rule_catalog is not None else DEFAULT_RULE_CATALOG

    def evaluate(self, request: GovernorInput) -> GovernanceDecision:
        validate_contract_rules(request.contract, rule_catalog=self._rule_catalog)
        request._validate_policy_binding()
        request.validate_source_agreement()
        if isinstance(request.contract, ContractRulesV3):
            self._rule_catalog.validate_v3_handlers(request.contract)
        mode = request.effective_mode
        violations = []
        if mode != "no_contract":
            if isinstance(request.contract, ContractRulesV3):
                if request.phase == "pre_execution":
                    violations = _pre_violations(
                        request
                    ) + self._rule_catalog.evaluate_v3(request)
                else:
                    violations = self._rule_catalog.evaluate_v3(request)
            else:
                checks = {
                    "pre_execution": _pre_violations,
                    "runtime": self._rule_catalog.evaluate_runtime,
                    "post_execution": self._rule_catalog.evaluate_post,
                }
                violations = checks[request.phase](request)
        decision = None
        if request.phase == "runtime":
            decision = "allow" if not violations else {
                "advisory": "allow_with_warning", "guarded": "block", "strict": "abort",
            }[mode]
        return GovernanceDecision(phase=request.phase, violations=violations, decision=decision)


class Governor:
    """Evaluate one checkpoint with the deterministic default or an injected evaluator.

    ``Governor(rule_catalog=catalog)`` enables custom rules from a contract.
    The Governor returns a decision; :class:`WorkflowController` owns the
    run state and invokes tools only after the runtime check.
    """

    def __init__(
        self,
        evaluator: GovernorEvaluator | None = None,
        rule_catalog: RuleCatalog | None = None,
    ) -> None:
        if evaluator is not None and rule_catalog is not None:
            raise ValueError("Cannot specify both evaluator and rule_catalog")
        if evaluator is not None:
            self._evaluator = evaluator
        else:
            self._evaluator = DeterministicEvaluator(rule_catalog=rule_catalog)

    def evaluate(self, request: GovernorInput) -> GovernanceDecision:
        return self._evaluator.evaluate(request)
