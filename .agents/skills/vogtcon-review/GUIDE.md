# Vogtcon Review Skill — Usage Guide

This guide describes how to run the `vogtcon-review` skill in a clean consumer environment using the `vogtcon 0.4.0` wheel.

## Prerequisites & Scope

- **Distribution:** The skill (`.agents/skills/vogtcon-review/`) is distributed separately from the `vogtcon` Python wheel.
- **Clean consumer setup:** Install `vogtcon==0.4.0` (for example `python -m pip install "vogtcon==0.4.0"` or from a local `0.4.0` wheel) into a fresh virtual environment and run from an isolated consumer directory **without importing the repository checkout** and **without installing the benchmark extras** (`pydantic-ai` is not required).
- **Read-only boundary:** Never modify inspected contracts or JSONL traces, never execute workflows, never auto-install dependencies, and keep MCP and benchmark campaigns out of scope.
- **Verify CLI first:**

  ```bash
  vogtcon --version
  # Expected: vogtcon 0.4.0
  ```

## Walkthrough 1: Notificaciones

Copy `examples/notification_contract.yaml`, `examples/notification_contract_v2.yaml`, and the skill's `examples/` directory into your consumer workspace.

1. **Validate v1 and v2 contracts:**

   ```bash
   vogtcon validate "notification_contract.yaml" --json
   vogtcon validate "notification_contract_v2.yaml" --json
   ```

   - `notification_contract.yaml` (v1): exit `0`, `status: "valid"`, `contract_version: 1`, `mode: "guarded"`, `fingerprint.verified: false` (declared only).
   - `notification_contract_v2.yaml` (v2): exit `0`, `status: "valid"`, `contract_version: 2`, `mode: null`, `fingerprint.verified: true` (SHA-256 verified).

2. **Explain the recovery trace (`wheel-recovery`):**

   ```bash
   vogtcon explain ".agents/skills/vogtcon-review/examples/notification_recovery.jsonl" --run-id "wheel-recovery" --json
   ```

   - Exit `0`, `status: "ok"`, `trace_integrity: "complete"`, `terminal: "post_execution"`.
   - Action 1 (`send_notification`): `decision: "block"`, `violation_rules: ["sensitive_requires_approval"]`, `tool_outcome: "prevented"`.
   - Action 2 (`send_notification`): `decision: "allow"`, `prior_same_tool_block_action_index: 1`, `tool_outcome: "completed"`, `effect_evidence: "not_verified"` (argument identity, host authorization, and retry relationship remain undetermined).

3. **Explain controlled failure and integrity variants:**

   ```bash
   vogtcon explain ".agents/skills/vogtcon-review/examples/notification_tool_error.jsonl" --json
   vogtcon explain ".agents/skills/vogtcon-review/examples/notification_partial.jsonl" --json
   vogtcon explain ".agents/skills/vogtcon-review/examples/notification_inconsistent.jsonl" --json
   vogtcon explain ".agents/skills/vogtcon-review/examples/notification_recovery.jsonl" --run-id "missing" --json
   ```

   - `notification_tool_error.jsonl`: exit `0`, `trace_integrity: "complete"`, `terminal: "tool_error"`, `tool_outcome: "error"`, `effect_evidence: "indeterminate"`.
   - `notification_partial.jsonl`: exit `0`, `trace_integrity: "partial"`, `terminal: null`, `partial_log` diagnostic, `tool_outcome: "unfinalized"`, `effect_evidence: "indeterminate"`.
   - `notification_inconsistent.jsonl`: exit `1`, `status: "inconsistent_log"`, `inconsistent_log` diagnostic at physical line `8`, with `wheel-recovery-ok` preserved separately from `wheel-recovery-corrupt`.
   - `--run-id "missing"`: exit `2`, `status: "run_not_found"`.

## Walkthrough 2: CFDI

Copy `examples/cfdi_contract.yaml` into your consumer workspace alongside the synthetic trace [examples/cfdi_reconciliation.jsonl](examples/cfdi_reconciliation.jsonl).

1. **Validate the CFDI contract with the default catalog:**

   ```bash
   vogtcon validate "cfdi_contract.yaml" --json
   ```

   - Exit `2`, `status: "unsupported_rules"`.
   - `data.field: "runtime_rules"`, `data.unsupported_ids: ["cfdi.exact_match_required"]`.
   - Validation against the default catalog is inconclusive (requires the host `RuleCatalog`); fingerprint verification and subsequent checks remain unconcluded.

2. **Explain the synthetic CFDI trace separately:**

   ```bash
   vogtcon explain ".agents/skills/vogtcon-review/examples/cfdi_reconciliation.jsonl" --json
   ```

   - Exit `0`, `status: "ok"`, `contract_id: "example.cfdi_reconciliation"`, `trace_integrity: "complete"`, `terminal: "post_execution"`.
   - Action 1 (`mark_reconciled`): `block` citing `cfdi.exact_match_required` (`tool_outcome: "prevented"`).
   - Action 2 (`mark_reconciled`): `allow` with `prior_same_tool_block_action_index: 1`, `tool_outcome: "completed"`, and `effect_evidence: "not_verified"`.
   - Matching `contract_id` links the reports conceptually while leaving exact contract revision or fingerprint verification at runtime pending.

## Contingencies

- **Missing CLI:** Never auto-install; direct the user to install `vogtcon==0.4.0` (`python -m pip install "vogtcon==0.4.0"` or local wheel) and list all unverified checks as pending.
- **Incompatible `output_version`:** Stop immediately if `output_version != 1` and report the schema mismatch.
- See [examples/README.md](examples/README.md) for trace provenance and [VERIFICATION.md](VERIFICATION.md) for verification records.
