# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Typed contracts and deterministic governance, independent of execution."""

from .contracts import compute_v3_contract_fingerprint, load_contract
from .core import DeterministicEvaluator, Governor, GovernorEvaluator
from .execution import GovernedToolExecutor, ToolExecutionOutcome, WorkflowController
from .models import (
    OPERATION_DIGEST_EXCLUDED_METADATA,
    OPERATION_IDENTITY_VERSION,
    ActionProposal,
    AgentContract,
    ContractDocument,
    ContractRulesV2,
    ContractRulesV3,
    EnforcementPolicy,
    ExecutionContext,
    GovernanceDecision,
    GovernorInput,
    HostFacts,
    PlannedEffect,
    RuleBinding,
    Violation,
)
from .rules import (
    DEFAULT_RULE_CATALOG,
    DEFAULT_RULE_TYPES,
    EmptyRuleParams,
    RuleCatalog,
    RuleTypeSpec,
)
from .records import JsonlDecisionLog, RunEvent, RunRecorder
from .telemetry import TelemetryObserver

__all__ = [
    "load_contract",
    "compute_v3_contract_fingerprint",
    "DeterministicEvaluator",
    "Governor",
    "GovernorEvaluator",
    "GovernedToolExecutor",
    "ToolExecutionOutcome",
    "WorkflowController",
    "RuleCatalog",
    "DEFAULT_RULE_CATALOG",
    "DEFAULT_RULE_TYPES",
    "EmptyRuleParams",
    "RuleTypeSpec",
    "JsonlDecisionLog",
    "RunEvent",
    "RunRecorder",
    "TelemetryObserver",
    "ActionProposal",
    "AgentContract",
    "ContractDocument",
    "ContractRulesV2",
    "ContractRulesV3",
    "EnforcementPolicy",
    "ExecutionContext",
    "GovernanceDecision",
    "GovernorInput",
    "HostFacts",
    "OPERATION_DIGEST_EXCLUDED_METADATA",
    "OPERATION_IDENTITY_VERSION",
    "PlannedEffect",
    "RuleBinding",
    "Violation",
]
