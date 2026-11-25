# Verification Record — `vogtcon-review` Skill

- **Target CLI version:** `vogtcon 0.4.0` (`output_version: 1`, `RunEvent` v1)
- **Skill definition:** [SKILL.md](SKILL.md)
- **Usage guide & examples:** [GUIDE.md](GUIDE.md), [examples/README.md](examples/README.md)

## 1. Format & Contract Validation

- Validated [SKILL.md](SKILL.md) YAML frontmatter (`name: vogtcon-review`, non-empty `description`), body structure, relative link resolution across all skill markdown docs (`SKILL.md`, `GUIDE.md`, `VERIFICATION.md`, `examples/README.md`), dash-prefixed path/`--run-id=` protection (`--`), dynamic installed-distribution `--version` check, and CLI ground-truth invariants via:
  ```bash
  /tmp/vogtcon-review-skill/.venv/bin/python -m unittest discover -s /tmp/vogtcon-review-skill/tests -p 'test_review_skill.py' -v
  ```
  (`Ran 29 tests`, exit code `0`, `OK`).
- Confirmed strictly **read-only** behavior: input contracts and JSONL trace files retain identical SHA-256 byte digests before and after every CLI invocation and fresh Codex session.

## 2. Recorded CLI Ground-Truth & Behavioral Matrix

### Stage 1 — Contracts (`validate`) & Contingencies

| Check | User Request / Prompt | Exact Command | Exit Code | Expected vs Observed JSON Facts |
| --- | --- | --- | --- | --- |
| CLI gate | Verify installed CLI version | `vogtcon --version` | `0` | Expected `vogtcon 0.4.0` (verified baseline matching installed distribution); observed `vogtcon 0.4.0` (`stderr` empty). |
| Missing CLI | Validate contract when `vogtcon` is absent from `PATH` | `vogtcon --version` (missing binary) | `127` | Expected manual `0.4.0` install guidance (`pip install "vogtcon==0.4.0"` or local wheel), zero auto-install, and pending checks listed; observed compliant behavior without modifying files. |
| Notificaciones v1 | Review v1 YAML contract | `vogtcon validate --json -- "examples/notification_contract.yaml"` | `0` | Expected `status: "valid"`, `contract_version: 1`, `mode: "guarded"`, `fingerprint.verified: false`; observed exact match (`contract_id: "example.notification"`). |
| Notificaciones v2 | Review v2 YAML contract | `vogtcon validate --json -- "examples/notification_contract_v2.yaml"` | `0` | Expected `status: "valid"`, `contract_version: 2`, `mode: null`, `fingerprint.verified: true`; observed exact match (`sha256:ad61db75...`). |
| Tampered v2 | Validate contract with altered SHA-256 | `vogtcon validate --json -- "<tampered_v2.yaml>"` | `1` | Expected `status: "invalid_contract"`, `data: null`, diagnostic citing fingerprint; observed exact match with original bytes preserved. |

### Stage 2 — Traces (`explain`) & Notificaciones

| Check | User Request / Prompt | Exact Command | Exit Code | Expected vs Observed JSON Facts |
| --- | --- | --- | --- | --- |
| Recovery trace | Explain `wheel-recovery` run | `vogtcon explain --run-id="wheel-recovery" --json -- ".agents/skills/vogtcon-review/examples/notification_recovery.jsonl"` | `0` | Expected `status: "ok"`, `trace_integrity: "complete"`, `terminal: "post_execution"`, action 1 `block` (`sensitive_requires_approval`), action 2 `allow` (`prior_same_tool_block_action_index: 1`, `tool_outcome: "completed"`, `effect_evidence: "not_verified"`); observed exact match. |
| Tool error | Explain failed tool execution | `vogtcon explain --json -- ".agents/skills/vogtcon-review/examples/notification_tool_error.jsonl"` | `0` | Expected `trace_integrity: "complete"`, `terminal: "tool_error"`, `tool_outcome: "error"`, `effect_evidence: "indeterminate"`; observed exact match. |
| Partial trace | Explain truncated execution log | `vogtcon explain --json -- ".agents/skills/vogtcon-review/examples/notification_partial.jsonl"` | `0` | Expected `trace_integrity: "partial"`, `terminal: null`, `partial_log` diagnostic, action 2 `tool_outcome: "unfinalized"`, `effect_evidence: "indeterminate"`; observed exact match. |
| Inconsistent log | Review multi-run log with contradiction | `vogtcon explain --json -- ".agents/skills/vogtcon-review/examples/notification_inconsistent.jsonl"` | `1` | Expected `status: "inconsistent_log"`, `inconsistent_log` diagnostic at physical line `8` for `wheel-recovery-corrupt`, while preserving `wheel-recovery-ok` (`complete`) separately; observed exact match. |
| Missing selector | Explain non-existent `run_id` | `vogtcon explain --run-id="missing" --json -- ".agents/skills/vogtcon-review/examples/notification_recovery.jsonl"` | `2` | Expected `status: "run_not_found"`, `data: null`, diagnostic `run_not_found`; observed exact match. |
| Dash-prefixed args | Validate `-contract.yaml` & explain `--demo` in `-trace.jsonl` | `vogtcon validate --json -- "-contract.yaml"` and `vogtcon explain --run-id=--demo --json -- "-trace.jsonl"` | `0`, `0` | Expected option separator `--` and inline `--run-id=` to prevent option-parsing failure (`exit 3`); observed `status: "valid"` and `status: "ok"` (`run_id: "--demo"`). |
| Incompatible `output_version` | Handle unknown JSON envelope schema (`output_version: 99`) | Envelope check before `data` | `0` (mocked) | Expected immediate stop and incompatibility report without interpreting `data`; observed compliant stop on `output_version: 99 != 1`. |

### Stage 3 — Isolated Wheel Consumer Smoke

| Check | User Request / Prompt | Exact Command | Exit Code | Expected vs Observed JSON Facts |
| --- | --- | --- | --- | --- |
| Clean wheel smoke | Build `vogtcon-0.4.0-py3-none-any.whl` offline and run full Notificaciones + CFDI suite in isolated consumer venv (`pydantic_ai` absent, `env -u PYTHONPATH`, no checkout imports) | `bash tests/smoke_review_skill.sh` | `0` | Expected `.agents/` excluded from wheel, isolated `0.4.0` install, Notificaciones (`validate` v1/v2 exit `0`; `explain` recovery/tool_error/partial exit `0`, inconsistent exit `1`, missing `run_id` exit `2`), CFDI (`validate` exit `2`, `explain` exit `0`), and identical SHA-256 digests; observed `"Smoke review skill consumer checks passed"`. |

## 3. Fresh Codex CLI Behavioral Acceptance (`codex-cli 0.171.0`)

Both independent consumers were verified in ephemeral, read-only Codex CLI sessions (`codex exec --ephemeral --sandbox read-only --skip-git-repo-check --json`) inside isolated directories with `env -u PYTHONPATH` and an isolated venv containing only the built `vogtcon-0.4.0-py3-none-any.whl` (`pydantic_ai` absent, no checkout on `PYTHONPATH`).

### Consumer 1 — Notificaciones (`consumer-notifications`)

- **Prompt:**
  `Use the vogtcon-review skill in .agents/skills/vogtcon-review/SKILL.md to review notification_contract_v2.yaml and explain run wheel-recovery in .agents/skills/vogtcon-review/examples/notification_recovery.jsonl.`
- **Observed commands & exit codes:**
  1. `cat .agents/skills/vogtcon-review/SKILL.md` (`exit 0`)
  2. `vogtcon --version` (`exit 0` -> `vogtcon 0.4.0`)
  3. `vogtcon explain --run-id='wheel-recovery' --json -- '.agents/skills/vogtcon-review/examples/notification_recovery.jsonl'` (`exit 0`)
  4. `vogtcon validate --json -- 'notification_contract_v2.yaml'` (`exit 0`)
  5. `python -c 'import subprocess,json; ...'` capturing exit code, `stdout`, and `stderr` separately for both `vogtcon` calls (`exit 0`).
- **Observed Codex response (verbatim):**

  ```markdown
  [notification_contract_v2.yaml](/tmp/vogtcon-codex-verify/consumer-notifications/notification_contract_v2.yaml) is valid under Vogtcon 0.4.0. It declares contract ID `example.notification`, version 2, and a null mode. Its pre-execution, runtime, and post-execution validation phases are active. The loader verified its SHA-256 fingerprint.

  The contract declares `send_notification`, applies the runtime rules `tool.declared_only` and `sensitive_requires_approval`, and specifies the postcondition `response.schema_complete`.

  In [the wheel-recovery trace](/tmp/vogtcon-codex-verify/consumer-notifications/.agents/skills/vogtcon-review/examples/notification_recovery.jsonl), the run has the same contract ID:

  1. **Action 1**, decision sequence 2: `send_notification` was blocked under `sensitive_requires_approval`. The recorded decision prevented invocation; there is no tool event for this action.
  2. **Action 2**, decision sequence 3 and tool event sequence 4: a later `send_notification` action was allowed, and the tool callable returned. The trace identifies action 1 as the prior block on the same tool, but does not establish that the arguments were identical, that this was a retry, or that host authorization was effective.

  The run’s trace integrity is `complete`, and its terminal is `post_execution`. That establishes log integrity, not external delivery or task success; the completed action’s external effect remains unverified. The matching contract ID links the reports, but does not prove that this exact contract revision or fingerprint was used at runtime.
  ```

- **Comparison with CLI JSON:**

| Field / Criterion | CLI JSON Output | Codex Session Report | Match |
| --- | --- | --- | --- |
| `validate` status & metadata | `status: "valid"`, `contract_id: "example.notification"`, `contract_version: 2`, `mode: null`, `fingerprint.verified: true` | Reported valid under `0.4.0`, `example.notification`, version 2, null mode, verified SHA-256 fingerprint | Exact |
| `validate` rules & phases | `validation_phases: ["pre_execution", "runtime", "post_execution"]`, `declared_tools: ["send_notification"]`, `runtime_rules: ["tool.declared_only", "sensitive_requires_approval"]`, `postconditions: ["response.schema_complete"]` | Cited all 3 phases, `send_notification`, both runtime rules, and `response.schema_complete` | Exact |
| `explain` Action 1 | `action_index: 1`, `decision_sequence: 2`, `decision: "block"`, `violation_rules: ["sensitive_requires_approval"]`, `tool_event_sequence: null`, `tool_outcome: "prevented"` | Cited Action 1, decision sequence 2, blocked under `sensitive_requires_approval`, prevented invocation, no tool event | Exact |
| `explain` Action 2 & boundaries | `action_index: 2`, `decision_sequence: 3`, `tool_event_sequence: 4`, `decision: "allow"`, `prior_same_tool_block_action_index: 1`, `tool_outcome: "completed"`, `effect_evidence: "not_verified"` | Cited Action 2, sequences 3 & 4, prior block at action 1, callable returned, external effect unverified; left argument identity, retry, and host authorization undetermined | Exact |
| `explain` integrity & cross-check | `trace_integrity: "complete"`, `terminal: "post_execution"`, `contract_id: "example.notification"` | Clarified `complete` = log integrity only; noted matching `contract_id` does not prove runtime contract revision/fingerprint | Exact |

### Consumer 2 — CFDI (`consumer-cfdi`)

- **Prompt:**
  `Use the vogtcon-review skill in .agents/skills/vogtcon-review/SKILL.md to review cfdi_contract.yaml and explain .agents/skills/vogtcon-review/examples/cfdi_reconciliation.jsonl.`
- **Observed commands & exit codes:**
  1. `cat .agents/skills/vogtcon-review/SKILL.md` (`exit 0`)
  2. `vogtcon --version` (`exit 0` -> `vogtcon 0.4.0`)
  3. `python -c 'import subprocess,json; ...'` executing `vogtcon validate --json -- cfdi_contract.yaml` (`exit 2`) and `vogtcon explain --json -- .agents/skills/vogtcon-review/examples/cfdi_reconciliation.jsonl` (`exit 0`) capturing exit code, `stdout`, and `stderr` separately (`exit 0`)
  4. Read-only `cat` inspection of `.agents/skills/vogtcon-review/examples/README.md`, `cfdi_contract.yaml`, and `.agents/skills/vogtcon-review/examples/cfdi_reconciliation.jsonl` (`exit 0`).
- **Observed Codex response (verbatim):**

  ```markdown
  The review is **inconclusive for the contract**, while the trace is internally complete. The installed Vogtcon 0.4.0 CLI could not validate [cfdi_contract.yaml](/tmp/vogtcon-codex-verify/consumer-cfdi/cfdi_contract.yaml) against its default catalog because the `runtime_rules` field contains the unsupported rule `cfdi.exact_match_required`. Validation may require the host’s rule catalog. The contract’s fingerprint and subsequent checks therefore remain unverified.

  The contract declares `mark_reconciled` as a tool and includes pre-execution, runtime, and post-execution validation phases. Its `contract_id`, `example.cfdi_reconciliation`, matches the ID in the [trace](/tmp/vogtcon-codex-verify/consumer-cfdi/.agents/skills/vogtcon-review/examples/cfdi_reconciliation.jsonl). That links the reports, but does not establish that the trace used this exact contract revision or fingerprint.

  For run `cfdi-reconciliation-demo`, the trace records:

  1. **Action 1:** At decision sequence 2, `mark_reconciled` was blocked for `cfdi.exact_match_required`. There is no tool event for this action; the recorded decision prevented invocation.
  2. **Action 2:** At decision sequence 3, another `mark_reconciled` action was allowed; its tool-completed event is sequence 4. The callable returned, but the trace does not verify an external effect. It also does not establish whether the two actions had identical arguments or whether the second was a retry.
  3. The run reached post-execution at sequence 5. Its `trace_integrity` is `complete`, which describes the log’s integrity, not effective authorization, external delivery, or overall task success.

  The example’s [provenance](/tmp/vogtcon-codex-verify/consumer-cfdi/.agents/skills/vogtcon-review/examples/README.md) identifies it as a synthetic test trace, not a record produced by executing the CFDI benchmark.
  ```

- **Comparison with CLI JSON:**

| Field / Criterion | CLI JSON Output | Codex Session Report | Match |
| --- | --- | --- | --- |
| `validate` exit & status | Exit `2`, `status: "unsupported_rules"`, `data: {"field": "runtime_rules", "unsupported_ids": ["cfdi.exact_match_required"]}`, no `fingerprint` in `data` | Reported contract validation inconclusive (`runtime_rules`, `cfdi.exact_match_required`), may require host catalog, fingerprint and subsequent checks unverified | Exact |
| `explain` run & provenance | Exit `0`, `status: "ok"`, `run_id: "cfdi-reconciliation-demo"`, `contract_id: "example.cfdi_reconciliation"` | Reported `cfdi-reconciliation-demo`, `example.cfdi_reconciliation`, noted synthetic test provenance from `examples/README.md` | Exact |
| `explain` Action 1 | `action_index: 1`, `decision_sequence: 2`, `tool_name: "mark_reconciled"`, `decision: "block"`, `violation_rules: ["cfdi.exact_match_required"]`, `tool_outcome: "prevented"` | Cited Action 1, decision sequence 2, `mark_reconciled` blocked for `cfdi.exact_match_required`, prevented invocation, no tool event | Exact |
| `explain` Action 2 & boundaries | `action_index: 2`, `decision_sequence: 3`, `tool_event_sequence: 4`, `decision: "allow"`, `prior_same_tool_block_action_index: 1`, `tool_outcome: "completed"`, `effect_evidence: "not_verified"` | Cited Action 2, sequences 3 & 4, `mark_reconciled` allowed, callable returned, external effect unverified; left argument identity & retry undetermined | Exact |
| `explain` integrity & cross-check | `trace_integrity: "complete"`, `terminal: "post_execution"`, `post_execution.sequence: 5` | Cited post-execution sequence 5, `trace_integrity: "complete"` (log integrity only), and noted `contract_id` match does not establish runtime revision/fingerprint | Exact |

## 4. Input Byte Preservation (SHA-256)

All inspected fixtures maintained identical SHA-256 digests before and after both repository tests and both isolated Codex consumer sessions (`OK`):

- `examples/notification_contract.yaml`: `507d535e8473a93ba4795798063740c8d0b6d07518fa39114914b214b2cc834e`
- `examples/notification_contract_v2.yaml`: `5c89e5aeb4692ec3440653198935c3d0c5d321f33735dda56800470cc2e0b271`
- `examples/cfdi_contract.yaml`: `5387af8a7fea69bc117b8b1168f37b758492e8b5c315302c2ce2f64f91ebdae1`
- [examples/notification_recovery.jsonl](examples/notification_recovery.jsonl): `cdd37fe287f7b8a5d0bb90c5df8bf460b7850e0834d4474376542a6c2246f1d9`
- [examples/notification_tool_error.jsonl](examples/notification_tool_error.jsonl): `2b48bfd6d9ed3a4612078363fac3ad212067c63100b01ebd7d0606fc2d068bfa`
- [examples/notification_partial.jsonl](examples/notification_partial.jsonl): `8416b1c2cca3356e3c1b7fc90ca9a73400a4e8ac7a0b959c9a6e553ced7243fc`
- [examples/notification_inconsistent.jsonl](examples/notification_inconsistent.jsonl): `f65f9102c164354566bc4e986b6c8055980b169520cdcfe8677f168f4003c1c4`
- [examples/cfdi_reconciliation.jsonl](examples/cfdi_reconciliation.jsonl): `583139e6d5c7152c7e6c1dffc8bebad2b28268ea7a35f6a54924706d794799c2`

## 5. Deferred & Out-of-Scope Items

- **MCP integration:** Deferred to Phase 3 of `ROADMAP_INTERFACES.md`.
- **Workflow execution, file edits, auto-installation, custom `RuleCatalog` loading, and benchmark runs:** Explicitly out of scope for this read-only review skill.
