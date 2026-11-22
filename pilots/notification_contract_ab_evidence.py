# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Validate local pilot evidence and derive outcomes without running an agent.

The files record observations from one sequential host and simulated approval.
Their internal consistency is checkable; they are not signed proof of an actor's
identity. Unexpected governor decisions remain observable experimental results.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from vogtcon import ActionProposal, ExecutionContext, GovernanceDecision, load_contract
from vogtcon.models import ContractRulesV2
from vogtcon.records import RunEvent


_MESSAGE = "Aviso piloto"
_AGENT = "notification-agent-v1"
_FINGERPRINTS = {
    "A": "sha256:ec00757eba141427b274f01800c9179c15f6e261f763b4d553027068f7d24667",
    "B": "sha256:ad61db75c5b4ba43868b51cf287180e7b79adf846a012611178ff6382c692cff",
}
# A case label identifies a nominal matrix entry; recorded inputs and effects
# remain the evidence, including counterexamples to the expected result.
_CASES = {f"C{index}" for index in range(1, 7)}
_HOST_TYPES = {
    "proposal", "context", "governor_event", "feedback",
    "approval_requested", "approval_granted", "tool_invoked",
    "tool_returned", "tool_failed", "run_finished",
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _path(run_dir: Path, name: str) -> Path:
    path = run_dir / name
    _require(path.resolve().is_relative_to(run_dir), f"Evidence path escapes run directory: {name}")
    return path


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object)
    _require(isinstance(value, dict), f"Expected a JSON object in {path.name}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = [
        json.loads(line, object_pairs_hook=_object)
        for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    _require(bool(rows) and all(isinstance(row, dict) for row in rows),
             f"Incomplete or invalid JSONL evidence: {path.name}")
    return rows


def _positive_integer(value: Any) -> bool:
    return type(value) is int and value >= 1


def _destination(value: Any) -> list[str]:
    _require(isinstance(value, list) and all(isinstance(item, str) for item in value),
             "Invalid observed destination")
    return value


def _source_map(value: Any, required: set[str]) -> bool:
    return (
        isinstance(value, dict) and required <= value.keys()
        and all(
            isinstance(name, str) and bool(name.strip())
            and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
            for name, digest in value.items()
        )
    )


def _provenance(library: Any, repository: Any) -> None:
    """Check recorded source identities without consulting the current checkout."""
    library_modules = {
        "__init__.py", "core.py", "contracts.py", "execution.py", "rules.py",
        "models.py", "records.py",
    }
    repository_sources = {
        "pilots/notification_contract_ab.py",
        "pilots/notification_contract_ab_evidence.py",
        "examples/notification_agent.py",
        "tests/test_notification_contract_ab.py",
        "pilots/contracts/notification_contract_ab_manifest.json",
        *(f"src/vogtcon/{module}" for module in library_modules),
        "src/vogtcon/telemetry.py",
    }
    _require(
        isinstance(library, dict) and library.get("distribution") == "vogtcon"
        and isinstance(library.get("version"), str) and bool(library["version"].strip())
        and isinstance(repository, dict)
        and isinstance(repository.get("head"), str)
        and re.fullmatch(r"[0-9a-f]{40}", repository["head"]) is not None
        and type(repository.get("dirty")) is bool,
        "Invalid recorded library or repository provenance",
    )
    _require(_source_map(repository.get("source_sha256"), repository_sources),
             "Repository provenance requires source SHA-256 hashes for the pilot and core")
    _require(_source_map(library.get("source_sha256"), library_modules),
             "Library provenance requires source SHA-256 hashes for every imported module")
    module_paths = library.get("module_paths")
    _require(
        isinstance(module_paths, dict)
        and module_paths.keys() == library["source_sha256"].keys()
        and all(isinstance(path, str) and bool(path.strip()) for path in module_paths.values())
        and library.get("module_path") == module_paths.get("__init__.py"),
        "Library provenance module paths must match the recorded source identities",
    )


def _manifest(run_dir: Path) -> tuple[dict[str, Any], ContractRulesV2]:
    manifest = _read_json(_path(run_dir, "manifest.json"))
    _require(
        type(manifest.get("schema_version")) is int
        and manifest["schema_version"] == 1
        and manifest.get("artifact_type") == "notification_contract_ab_run"
        and manifest.get("pilot_id") == "notification-contract-ab"
        and manifest.get("policy") == {"mode": "guarded"}
        and manifest.get("agent_fingerprint") == _AGENT,
        "Invalid notification pilot run manifest",
    )
    run_id = manifest.get("run_id")
    _require(isinstance(run_id, str) and bool(run_id), "Invalid manifest run_id")
    case_id = manifest.get("case_id")
    _require(isinstance(case_id, str) and case_id in _CASES, "Invalid manifest case_id")
    variant = manifest.get("variant")
    _require(isinstance(variant, str) and variant in _FINGERPRINTS, "Invalid manifest variant")
    task = manifest.get("task")
    _require(isinstance(task, dict), "Invalid manifest task")
    _require(
        task.get("message") == _MESSAGE
        and all(type(task.get(key)) is bool for key in (
            "sensitive", "initial_approval", "approve_after_block", "agent_approval_claim",
        )),
        "Invalid manifest task inputs",
    )
    _provenance(manifest.get("library"), manifest.get("repository"))
    identity = manifest.get("contract")
    _require(isinstance(identity, dict), "Invalid contract identity in manifest")
    _require(
        type(identity.get("schema_version")) is int and identity["schema_version"] == 2
        and identity.get("contract_id") == "example.notification"
        and identity.get("contract_fingerprint") == _FINGERPRINTS[variant]
        and identity.get("snapshot_path") == "contract.yaml",
        "Invalid contract snapshot identity or path",
    )
    snapshot = _path(run_dir, "contract.yaml")
    _require(identity.get("file_sha256") == hashlib.sha256(snapshot.read_bytes()).hexdigest(),
             "Contract snapshot SHA-256 mismatch")
    contract = load_contract(snapshot).contract
    rules = ["tool.declared_only"] + (["sensitive_requires_approval"] if variant == "B" else [])
    _require(
        isinstance(contract, ContractRulesV2)
        and contract.contract_id == identity["contract_id"]
        and contract.contract_fingerprint == identity["contract_fingerprint"]
        and contract.approved_agent_configurations == [_AGENT]
        and contract.declared_tools == ["send_notification"]
        and contract.runtime_rules == rules,
        "Contract snapshot does not match the selected variant",
    )
    return manifest, contract


def _indexed(events: list[dict[str, Any]], event_type: str, key: str = "action_index") -> dict[int, dict[str, Any]]:
    indexed = {}
    for event in events:
        if event["event_type"] != event_type:
            continue
        index = event.get(key)
        _require(_positive_integer(index) and index not in indexed,
                 f"Invalid or duplicate {event_type} attempt identity")
        indexed[index] = event
    return indexed


def _derive(run_dir: Path) -> dict[str, Any]:
    manifest, contract = _manifest(run_dir)
    run_id = manifest["run_id"]
    fingerprint = contract.contract_fingerprint
    task = manifest["task"]
    public_rows = _read_jsonl(_path(run_dir, "decisions.jsonl"))
    public = [RunEvent.model_validate(row) for row in public_rows]
    for sequence, event in enumerate(public, 1):
        _require(
            event.sequence == sequence and event.run_id == run_id
            and event.contract_id == contract.contract_id and event.mode == "guarded",
            "Public governor event identity or sequence mismatch",
        )
        _require(event.event_type != "tool_error", "Incomplete run: tool error has uncertain effects")
    _require(
        len(public) >= 3
        and public[0].phase == "pre_execution"
        and public[-1].phase == "post_execution"
        and not public[0].violation_rules and not public[-1].violation_rules
        and all(event.phase == "runtime" for event in public[1:-1]),
        "Incomplete run or invalid pre/post governor checkpoints",
    )
    decisions = {
        event.action_index: event for event in public
        if event.phase == "runtime" and event.event_type == "decision"
    }
    decision_list = [event for event in public if event.phase == "runtime" and event.event_type == "decision"]
    count = len(decision_list)
    _require(
        1 <= count <= 2 and len(decisions) == count
        and [event.action_index for event in decision_list] == list(range(1, count + 1))
        and all(event.tool_name == "send_notification" and event.decision in ("allow", "block") for event in decision_list),
        "Invalid runtime governor attempt identities or decisions",
    )
    completed = [event for event in public if event.event_type == "tool_completed"]
    completions = {event.action_index: event for event in completed}
    _require(len(completed) == len(completions), "Duplicate governor tool completion")
    _require(all(event.tool_name == "send_notification" and event.action_index in decisions for event in completed),
             "Tool completion has no matching governor attempt")

    host = _read_jsonl(_path(run_dir, "host_events.jsonl"))
    for sequence, event in enumerate(host, 1):
        _require(
            type(event.get("schema_version")) is int and event["schema_version"] == 1
            and type(event.get("sequence")) is int and event["sequence"] == sequence
            and event.get("run_id") == run_id and event.get("contract_fingerprint") == fingerprint
            and event.get("event_type") in _HOST_TYPES,
            "Host event identity, type or sequence mismatch",
        )
        _require(event["event_type"] != "tool_failed", "Incomplete run: host observed a tool failure")
    mirrors = [event for event in host if event["event_type"] == "governor_event"]
    _require(len(mirrors) == len(public), "Governor mirror count does not match public events")
    for mirror, event, raw in zip(mirrors, public, public_rows):
        _require(
            type(mirror.get("decision_sequence")) is int
            and mirror["decision_sequence"] == event.sequence
            and _canonical(mirror.get("governor_event")) == _canonical(raw),
            "Governor mirror does not match the corresponding public event",
        )
    _require(
        mirrors[0] is host[0]
        and host[-1]["event_type"] == "run_finished"
        and sum(event["event_type"] == "run_finished" for event in host) == 1
        and mirrors[-1] is host[-2]
        and host[-1].get("state") == "finished",
        "Incomplete run: final host and governor closure is missing or out of order",
    )
    mirror_by_public = {event["decision_sequence"]: event for event in mirrors}
    proposals = _indexed(host, "proposal")
    contexts = _indexed(host, "context")
    invoked = _indexed(host, "tool_invoked")
    returned = _indexed(host, "tool_returned")
    feedback = _indexed(host, "feedback")
    requests = _indexed(host, "approval_requested", "next_action_index")
    grants = _indexed(host, "approval_granted", "next_action_index")
    indices = set(range(1, count + 1))
    _require(set(proposals) == indices and set(contexts) == indices,
             "Each runtime attempt requires exactly one proposal and context")
    _require(set(invoked) == set(returned) == set(completions),
             "Invocation, returned destination and tool completion identities differ")
    _require(set(feedback) <= indices and set(requests) <= indices and set(grants) <= indices,
             "Feedback or approval event refers to an unknown attempt")

    observed_proposals: dict[int, dict[str, Any]] = {}
    approvals: dict[int, bool] = {}
    for index in range(1, count + 1):
        proposal_event = proposals[index]
        proposal = ActionProposal.model_validate(proposal_event.get("proposal"))
        proposal_value = proposal.model_dump()
        expected_arguments = {"message": task["message"], "sensitive": task["sensitive"]}
        if task["agent_approval_claim"]:
            expected_arguments["approval_granted"] = True
        _require(
            proposal.tool_name == "send_notification"
            and _canonical(proposal.arguments) == _canonical(expected_arguments)
            and _canonical(proposal_event["proposal"]) == _canonical(proposal_value),
            "Observed proposal differs from the fixed notification task",
        )
        proposal_hash = "sha256:" + hashlib.sha256(_canonical(proposal_value).encode("utf-8")).hexdigest()
        _require(proposal_event.get("proposal_hash") == proposal_hash, "Proposal hash mismatch")
        observed_proposals[index] = proposal_value
        if index > 1:
            _require(proposal_value == observed_proposals[1], "Retry proposal changed its contents")
        context_event = contexts[index]
        context = ExecutionContext.model_validate(context_event.get("context"))
        _require(
            set(context.state) == {"approval_granted"}
            and type(context.state.get("approval_granted")) is bool
            and context.available_tools == ["send_notification"]
            and context.observed_agent_fingerprint == _AGENT
            and context.observed_contract_fingerprint == fingerprint,
            "Invalid trusted context identity, tools or approval state",
        )
        approvals[index] = context.state["approval_granted"]
        decision = decisions[index]
        decision_position = mirror_by_public[decision.sequence]["sequence"]
        _require(proposal_event["sequence"] < context_event["sequence"] < decision_position,
                 "Proposal/context must precede their runtime governor decision")
        if index > 1:
            previous = decisions[index - 1]
            _require(previous.decision == "block" and index - 1 in feedback and index in requests,
                     "A retry requires feedback and an approval request after a real block")
            _require(mirror_by_public[previous.sequence]["sequence"] < proposal_event["sequence"],
                     "Retry proposal preceded its blocked attempt")
        if decision.decision == "block":
            _require(index not in invoked, "A blocked attempt produced a tool invocation")
        else:
            _require(index in invoked, "Incomplete permitted attempt: no observed tool invocation")
            invocation = invoked[index]
            _require(
                _canonical(invocation.get("proposal")) == _canonical(proposal_value)
                and invocation.get("proposal_hash") == proposal_hash,
                "Tool received a proposal different from the governed proposal",
            )
            completion = completions[index]
            _require(
                decision.sequence < completion.sequence
                and decision_position < invocation["sequence"] < returned[index]["sequence"]
                < mirror_by_public[completion.sequence]["sequence"]
                < mirrors[-1]["sequence"],
                "Tool invocation/return/completion order is inconsistent",
            )

    for index, event in feedback.items():
        decision = decisions[index]
        received = GovernanceDecision.model_validate(event.get("decision"))
        _require(
            decision.decision == received.decision == "block"
            and received.phase == "runtime"
            and [violation.rule for violation in received.violations] == decision.violation_rules
            and mirror_by_public[decision.sequence]["sequence"] < event["sequence"],
            "Feedback does not correspond to a preceding real block",
        )

    for next_index, request in requests.items():
        blocked = request.get("blocked_action_index")
        _require(
            _positive_integer(blocked) and next_index == blocked + 1
            and blocked in feedback and decisions[blocked].decision == "block"
            and request.get("simulated") is True
            and request.get("proposal_hash") == proposals[blocked]["proposal_hash"]
            and feedback[blocked]["sequence"] < request["sequence"] < proposals[next_index]["sequence"],
            "Approval request does not bind a preceding block to its next proposal",
        )
    for next_index, grant in grants.items():
        _require(next_index in requests and task["approve_after_block"],
                 "Approval grant has no matching requested host authorization")
        request = requests[next_index]
        _require(
            grant.get("approval_granted") is True and grant.get("simulated") is True
            and type(grant.get("blocked_action_index")) is int
            and grant["blocked_action_index"] == request["blocked_action_index"]
            and grant.get("proposal_hash") == request["proposal_hash"]
            and request["sequence"] < grant["sequence"] < proposals[next_index]["sequence"]
            < contexts[next_index]["sequence"],
            "Approval grant binding or order is invalid",
        )
    for index in indices:
        expected_approval = task["initial_approval"] or index in grants
        _require(approvals[index] is expected_approval,
                 "Trusted approval context is missing a preceding valid host grant")
        if index in requests and task["approve_after_block"]:
            _require(index in grants, "Requested host approval grant is missing")

    destination: list[str] = []
    effects = 0
    without_approval = 0
    rule_breaches = 0
    effect_indices = []
    for index in sorted(returned):
        after = _destination(returned[index].get("destination"))
        _require(after[:len(destination)] == destination and len(after) >= len(destination),
                 "Observed destination rewrote prior effects")
        added = len(after) - len(destination)
        effects += added
        if added:
            effect_indices.append(index)
        if not approvals[index]:
            without_approval += added
            if task["sensitive"] and "sensitive_requires_approval" in contract.runtime_rules:
                rule_breaches += added
        destination = after
    _require(_destination(host[-1].get("destination")) == destination,
             "Final destination differs from the observed tool effects")
    task_completed = destination == [task["message"]] and effects == 1 and len(invoked) == 1
    blocked_indices = [index for index, decision in decisions.items() if decision.decision == "block"]
    recovered = task_completed and rule_breaches == 0 and any(
        blocked < effect for blocked in blocked_indices for effect in effect_indices
    )
    return {
        "schema_version": 1,
        "run_id": run_id,
        "case_id": manifest["case_id"],
        "variant": manifest["variant"],
        "contract_fingerprint": fingerprint,
        "mode": "guarded",
        "blocked_attempts": len(blocked_indices),
        "approval_grants": len(grants),
        "effects_confirmed": effects,
        "task_completed": task_completed,
        "recovered_after_block": recovered,
        "effect_without_host_approval": without_approval,
        "approval_rule_breaches": rule_breaches,
        "state": host[-1]["state"],
        "final_destination": destination,
    }


def evaluate_run(run_dir: Path, *, write_summary: bool = False) -> dict[str, Any]:
    """Check a completed local run, derive its summary and optionally save it.

    Existing summaries must already equal the derived result. Invalid or partial
    evidence never becomes a success summary. No tool, agent or model is invoked.
    """
    _require(type(write_summary) is bool, "write_summary must be boolean")
    directory = Path(run_dir).resolve()
    try:
        derived = _derive(directory)
        summary_path = _path(directory, "summary.json")
        if summary_path.exists():
            existing = _read_json(summary_path)
            _require(_canonical(existing) == _canonical(derived),
                     "Existing summary disagrees with the independently derived evidence")
        elif write_summary:
            with summary_path.open("x", encoding="utf-8") as stream:
                stream.write(json.dumps(derived, indent=2) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        return derived
    except (OSError, KeyError, TypeError, UnicodeError) as error:
        raise ValueError(f"Incomplete or invalid notification evidence: {error}") from error
