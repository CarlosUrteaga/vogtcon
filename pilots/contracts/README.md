<!-- Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
SPDX-License-Identifier: Apache-2.0 -->

# Notification contract comparison fixtures

Variant A removes only `sensitive_requires_approval` from the integrated v2
notification contract and recalculates its fingerprint. Variant B reuses
`examples/notification_contract_v2.yaml` unchanged. Both variants use a separate
`guarded` enforcement policy.

`notification_contract_ab_manifest.json` is a static identity manifest for this
experiment definition. Its repository-relative paths, parsed contract fingerprints
and file SHA-256 values identify the two fixtures. The implementation base revision
identifies the starting checkout; it does not identify a commit containing these
new fixtures. This manifest is not evidence that any run occurred, approval was
granted or notification was sent. Per-run provenance and evidence belong to later
pilot stages.

Verify the fixtures from the repository root with:

```sh
python -m unittest discover -s tests -p 'test_notification_contract_ab.py' -v
```

## In memory case comparison

The API runs the existing notification example with these deterministic
cases: C1/C4 allow under A, C2 blocks twice under B, and C3 blocks under B before
the host grants approval and the second attempt sends. C5 starts preapproved;
C6 uses a nonsensitive notification. All cases keep `guarded` mode fixed.

From the repository root, after installing the development environment:

```python
from pilots.notification_contract_ab import run_case

case = run_case("C3")
assert [attempt.decision for attempt in case.attempts] == ["block", "allow"]
assert [attempt.sent_after for attempt in case.attempts] == [(), ("Aviso piloto",)]
assert case.approval_grants == 1
assert case.destination == ("Aviso piloto",)
```

The API validates both contract identities and their single rule difference
before starting the example. Each call creates a fresh destination, controller
and host state, and generates a fresh run ID unless the caller supplies one.
An optional `agent_approval_claim=True` adds that claim to both actual agent
proposals without changing host approval. Injecting an observed agent into the
example captures the actual first proposal and retry; the tool observer copies
what the real destination received. Context and proposal snapshots are independent
deep copies. Without `output_dir`, governance events and observations remain in
memory.

## Per run evidence

The API optionally saves the observations to a new directory for each run:

```python
from pathlib import Path
from pilots.notification_contract_ab import run_case

case = run_case("C3", run_id="recovery-001", output_dir=Path("pilots/results/notification-contract-ab"))
print(case.run_dir)
```

The run directory is exclusive: an existing directory is never overwritten, and
the persistent run ID must be a safe directory name. Before the example begins,
`manifest.json` records the task, host script, mode, installed library version,
Git revision and dirty status, and hashes of the actual runner, example and
contract identity sources. It separately identifies the library modules actually
imported, with their resolved paths and source hashes. The revision alone does
not identify new uncommitted files. `contract.yaml` preserves the selected
fixture's original bytes and is validated against the execution contract.

`decisions.jsonl` uses the existing public `JsonlDecisionLog` unchanged.
`host_events.jsonl` records proposals, context snapshots, feedback, simulated host
requests and grants, actual invocations and destination observations. It also
mirrors every public governance event exactly, joining the two logs by the
public decision sequence. Its own sequence is contiguous across all host events.
Approval grants bind the blocked proposal hash to the next attempt and are
written before changing host approval. A runtime mirror write failure prevents
tool invocation. C4 never manufactures a grant, and C5 records approval as an
initial condition rather than recovery.

A tool error can leave an observed effect: the exception propagates, the public
log retains `tool_error` with unknown execution status, and the host log records
the destination observed at failure. There is no successful `run_finished` event
after an exception. These local logs support one sequential process; they do not
provide distributed transactions.

## Run and evaluate the pilot

From the repository root, run all six cases without a model or network access:

```sh
.venv/bin/python -m pilots.notification_contract_ab --output-dir pilots/results/notification-contract-ab
```

Use `--case C3` for only the recovery case. Add `--agent-approval-claim` to check
the same cases when agent arguments claim approval. Both options apply only to
new runs. Each run keeps its own UUID-based directory, provenance, original
contract snapshot and two logs, then writes `summary.json` derived from those
observations. The command prints the resulting summaries as a JSON array.

Reevaluate a saved run without proposing actions or invoking a tool:

```sh
.venv/bin/python -m pilots.notification_contract_ab --evaluate /absolute/path/to/run
```

Offline evaluation checks identities, exact governance mirrors, proposal and
invocation correspondence, host authorization order, destination observations
and terminal evidence. It rejects partial runs and inconsistent evidence. An
existing summary must match the newly derived result; it is never silently
overwritten. Missing or late grants, altered tool arguments and a summary that
turns blocking into recovery are rejection cases.

`blocked_attempts` preserves earlier blocks even when the task completes.
`task_completed` requires exactly one observed `Aviso piloto` in the destination;
`recovered_after_block` additionally requires completion consistent with the
contract after an earlier block. For a sensitive effect under B, this requires
the recorded host concession before the effect. A completion that breaches that
approval rule remains an operational completion and is not recovery.
`effects_confirmed` counts destination changes rather
than permitted calls or `tool_completed` events. `effect_without_host_approval`
counts effects whose context lacked approval, including effects allowed by A and
nonsensitive C6. `approval_rule_breaches` separately counts sensitive effects
without approval when the contract requires it. Internally consistent adverse
observations are reported by these fields rather than rejected for disagreeing
with the expected matrix, so they can refute the pilot hypothesis.

The nominal matrix has no approval-rule breaches. C1/C4 complete with A and no
host concession; C2 remains blocked without completion; C3 preserves its first
block and completes after the simulated host concession; C5 starts approved;
C6 is nonsensitive. This demonstrates programmed host recovery and a deterministic
gate. It does not measure a language model's ability to request authorization or
recover from feedback.
