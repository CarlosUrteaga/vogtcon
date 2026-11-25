# Verification Record — `vogtcon-review` Skill

- **Target CLI version:** `vogtcon 0.4.0` (`output_version: 1`, `RunEvent` v1)
- **Skill definition:** [SKILL.md](SKILL.md)
- **Usage guide & examples:** [GUIDE.md](GUIDE.md), [examples/README.md](examples/README.md)

## 1. Format & Contract Validation

- Validated [SKILL.md](SKILL.md) YAML frontmatter (`name: vogtcon-review`, non-empty `description`), body structure, relative link resolution across all skill markdown docs (`SKILL.md`, `GUIDE.md`, `VERIFICATION.md`, `examples/README.md`), and CLI ground-truth invariants via:
  ```bash
  /tmp/vogtcon-review-skill/.venv/bin/python -m unittest discover -s /tmp/vogtcon-review-skill/tests -p 'test_review_skill.py' -v
  ```
  (`Ran 28 tests`, exit code `0`, `OK`).
- Confirmed strictly **read-only** behavior: input contracts and JSONL trace files retain identical SHA-256 byte digests before and after every CLI invocation.

## 2. Recorded Behavioral Walkthroughs

### Stage 1 — Contracts (`validate`) & Contingencies

| Check | User Request / Prompt | Exact Command | Exit Code | Expected vs Observed JSON Facts |
| --- | --- | --- | --- | --- |
| CLI gate | Verify installed CLI version | `vogtcon --version` | `0` | Expected `vogtcon 0.4.0`; observed `vogtcon 0.4.0` (`stderr` empty). |
| Missing CLI | Validate contract when `vogtcon` is absent from `PATH` | `vogtcon --version` (missing binary) | `127` | Expected manual `0.4.0` install guidance (`pip install "vogtcon==0.4.0"` or local wheel), zero auto-install, and pending checks listed; observed compliant behavior without modifying files. |
| Notificaciones v1 | Review v1 YAML contract | `vogtcon validate "examples/notification_contract.yaml" --json` | `0` | Expected `status: "valid"`, `contract_version: 1`, `mode: "guarded"`, `fingerprint.verified: false`; observed exact match (`contract_id: "example.notification"`). |
| Notificaciones v2 | Review v2 YAML contract | `vogtcon validate "examples/notification_contract_v2.yaml" --json` | `0` | Expected `status: "valid"`, `contract_version: 2`, `mode: null`, `fingerprint.verified: true`; observed exact match (`sha256:ad61db75...`). |
| Tampered v2 | Validate contract with altered SHA-256 | `vogtcon validate "<tampered_v2.yaml>" --json` | `1` | Expected `status: "invalid_contract"`, `data: null`, diagnostic citing fingerprint; observed exact match with original bytes preserved. |

### Stage 2 — Traces (`explain`) & Notificaciones

| Check | User Request / Prompt | Exact Command | Exit Code | Expected vs Observed JSON Facts |
| --- | --- | --- | --- | --- |
| Recovery trace | Explain `wheel-recovery` run | `vogtcon explain ".agents/skills/vogtcon-review/examples/notification_recovery.jsonl" --run-id "wheel-recovery" --json` | `0` | Expected `status: "ok"`, `trace_integrity: "complete"`, `terminal: "post_execution"`, action 1 `block` (`sensitive_requires_approval`), action 2 `allow` (`prior_same_tool_block_action_index: 1`, `tool_outcome: "completed"`, `effect_evidence: "not_verified"`); observed exact match. |
| Tool error | Explain failed tool execution | `vogtcon explain ".agents/skills/vogtcon-review/examples/notification_tool_error.jsonl" --json` | `0` | Expected `trace_integrity: "complete"`, `terminal: "tool_error"`, `tool_outcome: "error"`, `effect_evidence: "indeterminate"`; observed exact match. |
| Partial trace | Explain truncated execution log | `vogtcon explain ".agents/skills/vogtcon-review/examples/notification_partial.jsonl" --json` | `0` | Expected `trace_integrity: "partial"`, `terminal: null`, `partial_log` diagnostic, action 2 `tool_outcome: "unfinalized"`, `effect_evidence: "indeterminate"`; observed exact match. |
| Inconsistent log | Review multi-run log with contradiction | `vogtcon explain ".agents/skills/vogtcon-review/examples/notification_inconsistent.jsonl" --json` | `1` | Expected `status: "inconsistent_log"`, `inconsistent_log` diagnostic at physical line `8` for `wheel-recovery-corrupt`, while preserving `wheel-recovery-ok` (`complete`) separately; observed exact match. |
| Missing selector | Explain non-existent `run_id` | `vogtcon explain ".agents/skills/vogtcon-review/examples/notification_recovery.jsonl" --run-id "missing" --json` | `2` | Expected `status: "run_not_found"`, `data: null`, diagnostic `run_not_found`; observed exact match. |
| Incompatible `output_version` | Handle unknown JSON envelope schema (`output_version: 99`) | Envelope check before `data` | `0` (mocked) | Expected immediate stop and incompatibility report without interpreting `data`; observed compliant stop on `output_version: 99 != 1`. |

### Stage 3 — CFDI & Clean Wheel Consumer

| Check | User Request / Prompt | Exact Command | Exit Code | Expected vs Observed JSON Facts |
| --- | --- | --- | --- | --- |
| Clean wheel smoke | Build `vogtcon-0.4.0-py3-none-any.whl` offline and run full Notificaciones + CFDI suite in isolated consumer venv (`pydantic_ai` absent, `env -u PYTHONPATH`, no checkout imports) | `bash tests/smoke_review_skill.sh` | `0` | Expected `.agents/` excluded from wheel, isolated `0.4.0` install, Notificaciones (`validate` v1/v2 exit `0`; `explain` recovery/tool_error/partial exit `0`, inconsistent exit `1`, missing `run_id` exit `2`), CFDI (`validate` exit `2`, `explain` exit `0`), and identical SHA-256 digests; observed `"Smoke review skill consumer checks passed"`. |
| Clean-session CLI gate | Fresh session in `/tmp/vogtcon-stage3-clean-wheel/consumer` (`env -u PYTHONPATH`, `PATH` pointing only to isolated `0.4.0` wheel venv) | `vogtcon --version` | `0` | Expected `vogtcon 0.4.0`; observed `vogtcon 0.4.0` (`stderr` empty). |
| Clean-session CFDI contract | Review CFDI contract with default catalog in isolated consumer | `vogtcon validate "cfdi_contract.yaml" --json` | `2` | Expected `status: "unsupported_rules"`, `data.field: "runtime_rules"`, `data.unsupported_ids: ["cfdi.exact_match_required"]`, host `RuleCatalog` note, and fingerprint/subsequent checks left unconcluded; observed exact match. |
| Clean-session CFDI trace | Explain synthetic CFDI reconciliation trace in isolated consumer | `vogtcon explain "cfdi_reconciliation.jsonl" --json` | `0` | Expected `status: "ok"`, `run_id: "cfdi-reconciliation-demo"`, `contract_id: "example.cfdi_reconciliation"`, `trace_integrity: "complete"`, `terminal: "post_execution"`, action 1 `mark_reconciled` `block` (`cfdi.exact_match_required`), action 2 `mark_reconciled` `allow` (`prior_same_tool_block_action_index: 1`, `tool_outcome: "completed"`, `effect_evidence: "not_verified"`), with contract/trace comparison left unconcluded due to exit `2` on `validate`; observed exact match. |

## 3. Input Byte Preservation (SHA-256)

All inspected fixtures maintained identical SHA-256 digests before and after both repository and clean-wheel consumer runs (`OK`):

- `examples/notification_contract.yaml`: `507d535e8473a93ba4795798063740c8d0b6d07518fa39114914b214b2cc834e`
- `examples/notification_contract_v2.yaml`: `5c89e5aeb4692ec3440653198935c3d0c5d321f33735dda56800470cc2e0b271`
- `examples/cfdi_contract.yaml`: `5387af8a7fea69bc117b8b1168f37b758492e8b5c315302c2ce2f64f91ebdae1`
- [examples/notification_recovery.jsonl](examples/notification_recovery.jsonl): `cdd37fe287f7b8a5d0bb90c5df8bf460b7850e0834d4474376542a6c2246f1d9`
- [examples/notification_tool_error.jsonl](examples/notification_tool_error.jsonl): `2b48bfd6d9ed3a4612078363fac3ad212067c63100b01ebd7d0606fc2d068bfa`
- [examples/notification_partial.jsonl](examples/notification_partial.jsonl): `8416b1c2cca3356e3c1b7fc90ca9a73400a4e8ac7a0b959c9a6e553ced7243fc`
- [examples/notification_inconsistent.jsonl](examples/notification_inconsistent.jsonl): `f65f9102c164354566bc4e986b6c8055980b169520cdcfe8677f168f4003c1c4`
- [examples/cfdi_reconciliation.jsonl](examples/cfdi_reconciliation.jsonl): `583139e6d5c7152c7e6c1dffc8bebad2b28268ea7a35f6a54924706d794799c2`

## 4. Deferred & Out-of-Scope Items

- **MCP integration:** Deferred to Phase 3 of `ROADMAP_INTERFACES.md`.
- **Workflow execution, file edits, auto-installation, custom `RuleCatalog` loading, and benchmark runs:** Explicitly out of scope for this read-only review skill.
