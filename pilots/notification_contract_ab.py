# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Deterministic contract comparison with optional per-run local evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from copy import deepcopy
from dataclasses import dataclass, replace
from importlib.metadata import version
from pathlib import Path
from uuid import uuid4

import vogtcon

from examples.notification_agent import (
    InMemoryNotificationTool,
    NotificationAgent,
    NotificationRun,
    run_notification,
)
from vogtcon import (
    ActionProposal,
    EnforcementPolicy,
    ExecutionContext,
    GovernanceDecision,
    JsonlDecisionLog,
    load_contract,
)
from vogtcon.models import ContractDocument, ContractRulesV2
from vogtcon.records import RunEvent


ROOT = Path(__file__).resolve().parents[1]
MESSAGE = "Aviso piloto"
AGENT_FINGERPRINT = "notification-agent-v1"
MANIFEST_PATH = Path("pilots/contracts/notification_contract_ab_manifest.json")
CONTRACT_PATHS = {
    "A": Path("pilots/contracts/notification_without_approval_v2.yaml"),
    "B": Path("examples/notification_contract_v2.yaml"),
}


def load_contract_variants(*, root: Path = ROOT) -> dict[str, ContractDocument]:
    """Validate the static identity manifest and the single-rule comparison."""
    root = root.resolve()
    manifest = json.loads((root / MANIFEST_PATH).read_text(encoding="utf-8"))
    if (
        type(manifest.get("schema_version")) is not int
        or manifest["schema_version"] != 1
        or manifest.get("pilot_id") != "notification-contract-ab"
        or type(manifest.get("pilot_revision")) is not int
        or manifest["pilot_revision"] != 1
        or manifest.get("policy") != {"mode": "guarded"}
        or set(manifest.get("variants", {})) != {"A", "B"}
    ):
        raise ValueError("Invalid notification pilot identity manifest")
    documents = {}
    for variant, relative_path in CONTRACT_PATHS.items():
        identity = manifest["variants"][variant]
        if identity.get("contract_path") != relative_path.as_posix():
            raise ValueError(f"Invalid contract path for variant {variant}")
        path = (root / relative_path).resolve()
        if not path.is_relative_to(root):
            raise ValueError("Contract path must stay inside the pilot repository")
        if identity.get("file_sha256") != hashlib.sha256(path.read_bytes()).hexdigest():
            raise ValueError(f"Contract file SHA-256 mismatch for variant {variant}")
        document = load_contract(path)
        contract = document.contract
        if (
            not isinstance(contract, ContractRulesV2)
            or type(identity.get("schema_version")) is not int
            or identity["schema_version"] != contract.schema_version
            or identity.get("contract_id") != contract.contract_id
            or identity.get("contract_fingerprint") != contract.contract_fingerprint
            or contract.contract_id != "example.notification"
            or contract.approved_agent_configurations != [AGENT_FINGERPRINT]
        ):
            raise ValueError(f"Contract identity metadata mismatch for variant {variant}")
        documents[variant] = document
    a = documents["A"].original
    b = documents["B"].original
    a.pop("contract_fingerprint")
    b.pop("contract_fingerprint")
    if (
        a.get("runtime_rules") != ["tool.declared_only"]
        or b.get("runtime_rules") != ["tool.declared_only", "sensitive_requires_approval"]
    ):
        raise ValueError("Variants must differ only by the single approval rule")
    b["runtime_rules"].remove("sensitive_requires_approval")
    if a != b:
        raise ValueError("Variants must differ only by the single approval rule")
    return documents


@dataclass(frozen=True, slots=True)
class AttemptObservation:
    action_index: int
    proposal: ActionProposal
    context: ExecutionContext
    decision: str
    violation_rules: tuple[str, ...]
    executed: bool
    sent_after: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CaseObservation:
    case_id: str
    run_id: str
    variant: str
    contract_fingerprint: str
    attempts: tuple[AttemptObservation, ...]
    destination: tuple[str, ...]
    invoked_proposals: tuple[ActionProposal, ...]
    approval_grants: int
    callback_calls: int
    events: tuple[RunEvent, ...]
    run: NotificationRun
    host_events: tuple[dict[str, object], ...]
    run_dir: Path | None


@dataclass(frozen=True, slots=True)
class _Case:
    variant: str
    approve_after_block: bool = False
    initial_approval: bool = False
    sensitive: bool = True


_CASES = {
    "C1": _Case("A"),
    "C2": _Case("B"),
    "C3": _Case("B", approve_after_block=True),
    "C4": _Case("A", approve_after_block=True),
    "C5": _Case("B", initial_approval=True),
    "C6": _Case("B", sensitive=False),
}


def _proposal_hash(proposal: ActionProposal) -> str:
    canonical = json.dumps(proposal.model_dump(), sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _write_new_file(path: Path, contents: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(contents)
        stream.flush()
        os.fsync(stream.fileno())


def _prepare_run_directory(
    output_dir: Path,
    run_id: str,
    case_id: str,
    selected: _Case,
    document: ContractDocument,
    agent_approval_claim: bool,
) -> Path:
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", run_id) is None:
        raise ValueError("Persistent run_id must be a safe directory name")
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    run_dir = output_dir / run_id
    run_dir.mkdir(exist_ok=False)
    contract_path = ROOT / CONTRACT_PATHS[selected.variant]
    snapshot = contract_path.read_bytes()
    # The static identity validation has already selected this contract. Keep
    # its original bytes rather than serializing a typed model with defaults.
    source_paths = [
        Path("pilots/notification_contract_ab.py"),
        Path("pilots/notification_contract_ab_evidence.py"),
        Path("examples/notification_agent.py"),
        Path("tests/test_notification_contract_ab.py"),
        MANIFEST_PATH,
        *(path.relative_to(ROOT) for path in sorted((ROOT / "src/vogtcon").glob("*.py"))),
    ]
    head = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True,
    ).strip()
    dirty = bool(subprocess.check_output(
        ["git", "-C", str(ROOT), "status", "--porcelain"], text=True,
    ).strip())
    library_sources = {
        Path(module.__file__).name: Path(module.__file__).resolve()
        for module in (
            vogtcon,
            *(sys.modules[f"vogtcon.{name}"] for name in (
                "core", "contracts", "execution", "rules", "models", "records",
            )),
        )
    }
    manifest = {
        "schema_version": 1,
        "artifact_type": "notification_contract_ab_run",
        "pilot_id": "notification-contract-ab",
        "case_id": case_id,
        "run_id": run_id,
        "variant": selected.variant,
        "policy": {"mode": "guarded"},
        "agent_fingerprint": AGENT_FINGERPRINT,
        "task": {
            "message": MESSAGE,
            "sensitive": selected.sensitive,
            "initial_approval": selected.initial_approval,
            "approve_after_block": selected.approve_after_block,
            "agent_approval_claim": agent_approval_claim,
        },
        "contract": {
            "schema_version": document.contract.schema_version,
            "contract_id": document.contract.contract_id,
            "contract_fingerprint": document.contract.contract_fingerprint,
            "source_path": CONTRACT_PATHS[selected.variant].as_posix(),
            "snapshot_path": "contract.yaml",
            "file_sha256": hashlib.sha256(snapshot).hexdigest(),
        },
        "library": {
            "distribution": "vogtcon",
            "version": version("vogtcon"),
            "module_path": str(Path(vogtcon.__file__).resolve()),
            "module_paths": {name: str(path) for name, path in library_sources.items()},
            "source_sha256": {
                name: hashlib.sha256(path.read_bytes()).hexdigest()
                for name, path in library_sources.items()
            },
        },
        "repository": {
            "head": head,
            "dirty": dirty,
            "source_sha256": {
                path.as_posix(): hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
                for path in source_paths
            },
        },
    }
    _write_new_file(run_dir / "contract.yaml", snapshot)
    if load_contract(run_dir / "contract.yaml").original != document.original:
        raise ValueError("Contract snapshot differs from the selected execution contract")
    serialized = json.dumps(manifest, indent=2) + "\n"
    _write_new_file(run_dir / "manifest.json", serialized.encode("utf-8"))
    return run_dir


class _HostTimeline:
    def __init__(self, run_id: str, fingerprint: str, run_dir: Path | None) -> None:
        self.run_id = run_id
        self.fingerprint = fingerprint
        self.path = run_dir / "host_events.jsonl" if run_dir is not None else None
        self.events: list[dict[str, object]] = []

    def emit(self, event_type: str, **payload: object) -> None:
        event = {
            "schema_version": 1,
            "run_id": self.run_id,
            "contract_fingerprint": self.fingerprint,
            "sequence": len(self.events) + 1,
            "event_type": event_type,
            **deepcopy(payload),
        }
        if self.path is not None:
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        self.events.append(event)


class _ObservedAgent(NotificationAgent):
    def __init__(self, approval_claim: bool, timeline: _HostTimeline) -> None:
        self.approval_claim = approval_claim
        self.timeline = timeline
        self.proposals: list[ActionProposal] = []

    def propose(self, message: str, *, sensitive: bool) -> ActionProposal:
        proposal = super().propose(message, sensitive=sensitive)
        if self.approval_claim:
            proposal.arguments["approval_granted"] = True
        self.timeline.emit(
            "proposal", action_index=len(self.proposals) + 1,
            proposal=proposal.model_dump(), proposal_hash=_proposal_hash(proposal),
        )
        self.proposals.append(proposal.model_copy(deep=True))
        return proposal


class _ObservedTool(InMemoryNotificationTool):
    def __init__(self, timeline: _HostTimeline) -> None:
        super().__init__()
        self.timeline = timeline
        self.action_index: int | None = None
        self.received: list[ActionProposal] = []

    def __call__(self, proposal: ActionProposal) -> str:
        self.timeline.emit(
            "tool_invoked", action_index=self.action_index,
            proposal=proposal.model_dump(), proposal_hash=_proposal_hash(proposal),
        )
        self.received.append(proposal.model_copy(deep=True))
        try:
            result = super().__call__(proposal)
        except Exception as error:
            try:
                self.timeline.emit(
                    "tool_failed", action_index=self.action_index,
                    error_type=type(error).__name__, destination=list(self.sent),
                )
            except Exception:
                # Preserve the original tool failure even if logging fails too.
                pass
            raise
        self.timeline.emit(
            "tool_returned", action_index=self.action_index,
            destination=list(self.sent), result=result,
        )
        return result


class _AttemptRecorder:
    def __init__(
        self, agent: _ObservedAgent, tool: _ObservedTool,
        timeline: _HostTimeline, log: JsonlDecisionLog | None,
    ) -> None:
        self.agent = agent
        self.tool = tool
        self.timeline = timeline
        self.log = log
        self.contexts: list[ExecutionContext] = []
        self.events: list[RunEvent] = []
        self.attempts: list[AttemptObservation] = []

    def record(self, event: RunEvent) -> None:
        if self.log is not None:
            self.log.record(event)
        self.timeline.emit(
            "governor_event", decision_sequence=event.sequence,
            governor_event=event.model_dump(),
        )
        self.events.append(event.model_copy(deep=True))
        if event.phase != "runtime":
            return
        assert event.action_index is not None
        index = event.action_index - 1
        if event.event_type == "decision":
            self.tool.action_index = event.action_index
            self.attempts.append(AttemptObservation(
                action_index=event.action_index,
                proposal=self.agent.proposals[index].model_copy(deep=True),
                context=self.contexts[index].model_copy(deep=True),
                decision=event.decision,
                violation_rules=tuple(event.violation_rules),
                executed=False,
                sent_after=tuple(self.tool.sent),
            ))
        elif event.event_type == "tool_completed":
            self.attempts[index] = replace(
                self.attempts[index], executed=True, sent_after=tuple(self.tool.sent),
            )


def run_case(
    case_id: str,
    *,
    run_id: str | None = None,
    agent_approval_claim: bool = False,
    output_dir: Path | None = None,
) -> CaseObservation:
    """Run one fixed case with fresh host state, destination and controller.

    C1/C4 use A; C2/C3 use B without initial approval. C3 grants approval
    only after a real block. C5 is preapproved; C6 is not sensitive. The
    optional agent claim is an argument and never changes trusted host state.
    Returned nested models are independent deep copies, not authority inputs.
    Pass ``output_dir`` to create an exclusive directory for the run with its
    original contract snapshot, provenance manifest and two local JSONL logs.
    """
    if case_id not in _CASES:
        raise ValueError(f"Unknown notification pilot case: {case_id!r}")
    if run_id is not None and (not isinstance(run_id, str) or not run_id):
        raise ValueError("run_id must be a nonempty string")
    if type(agent_approval_claim) is not bool:
        raise ValueError("agent_approval_claim must be boolean")
    selected = _CASES[case_id]
    documents = load_contract_variants()
    contract = documents[selected.variant].contract
    selected_run_id = run_id if run_id is not None else f"notification-ab-{case_id}-{uuid4().hex}"
    run_dir = None if output_dir is None else _prepare_run_directory(
        Path(output_dir), selected_run_id, case_id, selected,
        documents[selected.variant], agent_approval_claim,
    )
    approval = selected.initial_approval
    approval_grants = 0
    callback_calls = 0
    timeline = _HostTimeline(selected_run_id, contract.contract_fingerprint, run_dir)
    agent = _ObservedAgent(agent_approval_claim, timeline)
    destination = _ObservedTool(timeline)
    log = JsonlDecisionLog(run_dir / "decisions.jsonl") if run_dir is not None else None
    recorder = _AttemptRecorder(agent, destination, timeline, log)

    def trusted_context() -> ExecutionContext:
        return ExecutionContext(
            state={"approval_granted": approval},
            available_tools=["send_notification"],
            observed_agent_fingerprint=AGENT_FINGERPRINT,
            observed_contract_fingerprint=contract.contract_fingerprint,
        )

    def context_provider() -> ExecutionContext:
        context = trusted_context()
        timeline.emit(
            "context", action_index=len(recorder.contexts) + 1,
            context=context.model_dump(),
        )
        recorder.contexts.append(context.model_copy(deep=True))
        return context

    def on_blocked(decision: GovernanceDecision) -> ActionProposal:
        nonlocal approval, approval_grants, callback_calls
        callback_calls += 1
        if decision.decision != "block":
            raise ValueError("Only a real block may trigger the host callback")
        blocked_index = len(recorder.attempts)
        proposal_hash = _proposal_hash(agent.proposals[-1])
        timeline.emit(
            "feedback", action_index=blocked_index, decision=decision.model_dump(),
        )
        binding = {
            "blocked_action_index": blocked_index,
            "next_action_index": blocked_index + 1,
            "proposal_hash": proposal_hash,
            "simulated": True,
        }
        timeline.emit("approval_requested", **binding)
        if selected.approve_after_block:
            timeline.emit("approval_granted", **binding, approval_granted=True)
            approval = True
            approval_grants += 1
        return agent.propose(MESSAGE, sensitive=selected.sensitive)

    result = run_notification(
        run_id=selected_run_id,
        context=trusted_context(),
        message=MESSAGE,
        sensitive=selected.sensitive,
        tool=destination,
        contract=contract,
        policy=EnforcementPolicy(mode="guarded"),
        on_blocked=on_blocked,
        context_provider=context_provider,
        recorder=recorder,
        agent=agent,
    )
    timeline.emit("run_finished", state=result.state, destination=list(destination.sent))
    return CaseObservation(
        case_id=case_id,
        run_id=selected_run_id,
        variant=selected.variant,
        contract_fingerprint=contract.contract_fingerprint,
        attempts=tuple(recorder.attempts),
        destination=tuple(destination.sent),
        invoked_proposals=tuple(proposal.model_copy(deep=True) for proposal in destination.received),
        approval_grants=approval_grants,
        callback_calls=callback_calls,
        events=tuple(recorder.events),
        run=result,
        host_events=tuple(deepcopy(timeline.events)),
        run_dir=run_dir,
    )


def main(argv: list[str] | None = None) -> int:
    """Run the deterministic matrix or validate saved evidence offline."""
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--output-dir", type=Path, help="Root for new run directories")
    action.add_argument("--evaluate", type=Path, metavar="RUN_DIR", help="Reevaluate saved evidence without running tools")
    parser.add_argument("--case", choices=tuple(_CASES), help="Run one case instead of all six")
    parser.add_argument("--agent-approval-claim", action="store_true", help="Add an untrusted approval claim to agent arguments")
    options = parser.parse_args(argv)
    if options.evaluate is not None and (options.case is not None or options.agent_approval_claim):
        parser.error("--evaluate cannot be combined with --case or --agent-approval-claim")
    from pilots.notification_contract_ab_evidence import evaluate_run

    try:
        if options.evaluate is not None:
            result = evaluate_run(options.evaluate)
        else:
            result = []
            for case_id in (options.case,) if options.case is not None else _CASES:
                observation = run_case(
                    case_id, output_dir=options.output_dir,
                    agent_approval_claim=options.agent_approval_claim,
                )
                result.append(evaluate_run(observation.run_dir, write_summary=True))
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
