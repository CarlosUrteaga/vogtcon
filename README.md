<!-- Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
SPDX-License-Identifier: Apache-2.0 -->

# Vogtcon

English · [Español](https://github.com/CarlosUrteaga/vogtcon/blob/main/README.es.md)

Vogtcon is an experimental Python library that checks an agent’s proposed tool calls against a YAML contract. For example, an agent can ask to send a sensitive notification, but the application decides whether approval has been granted. Vogtcon evaluates the rules before calling the tool. Its default evaluator is deterministic and works independently of the agent framework.

## Installation

Requires Python 3.11 or later. Install the core library from PyPI with `python -m pip install vogtcon`. For a Pydantic AI application, install the optional extra with `python -m pip install "vogtcon[pydantic-ai]"`.

<a name="probar-la-integración"></a>

## Validate a contract

From a directory containing a Vogtcon contract, run `vogtcon validate contract.yaml`. Add `--json` for structured output in scripts or CI.

## Try the integration

From the root of a clone, run the note-saving example with a scripted model. It works without provider credentials.

```bash
uv sync --locked --extra pydantic-ai --group test
uv run --no-sync python examples/custom_agent.py --log note-events.jsonl
```

The agent asks to save the same public note twice. Look at `decision` and `saved` in the output.

| Approval supplied by the application | Decision | Effect |
| --- | --- | --- |
| `False` | `block` | The list of saved notes stays empty. |
| `True` | `allow` | The list contains one public note. |

The demo appends each run’s decisions to `note-events.jsonl`. Add `--trace-console` to the second command to see OpenTelemetry spans. [Example code](https://github.com/CarlosUrteaga/vogtcon/blob/main/examples/custom_agent.py) · [Note contract](https://github.com/CarlosUrteaga/vogtcon/blob/main/examples/custom_contract.yaml)

## Connect a tool

Create one `WorkflowController` per run. Call `begin` before starting the agent, route each proposed tool call through `execute`, and call `finish` with the application’s final response while the controller is still `active`. A tool exposed directly to the agent bypasses these checks.

This example runs from the repository root with only the core package installed. It prints `block []` because the notification is sensitive and the application has supplied no approval. [Notification contract](https://github.com/CarlosUrteaga/vogtcon/blob/main/examples/notification_contract_v2.yaml)

```python
from vogtcon import ActionProposal, EnforcementPolicy, ExecutionContext, WorkflowController

controller = WorkflowController.from_contract_path(
    "examples/notification_contract_v2.yaml",
    run_id="notification-1",
    policy=EnforcementPolicy(mode="guarded"),
)
context = ExecutionContext(
    state={"approval_granted": False},
    available_tools=["send_notification"],
    observed_agent_fingerprint="notification-agent-v1",
    observed_contract_fingerprint=controller.contract.contract_fingerprint,
)
sent = []

def send_notification(proposal: ActionProposal) -> None:
    sent.append(proposal.arguments["message"])

controller.begin(context)
if controller.state == "active":
    proposal = ActionProposal(
        tool_name="send_notification",
        arguments={"message": "Hello", "sensitive": True},
    )
    outcome = controller.execute(proposal, context, send_notification)
    print(outcome.decision.decision, sent)
    if controller.state == "active":
        controller.finish(context, {"status": "sent" if outcome.executed else "blocked"})
```

The example copies the contract fingerprint from the YAML for convenience. In an integration, obtain the observed identity, roles and approvals from trusted application sources. Treat the model’s claims as untrusted. The note example computes `verified_output` from what the tool actually saved.

### Execution lifecycle

```mermaid
sequenceDiagram
    participant A as Application
    participant C as WorkflowController
    participant T as Tool
    A->>C: begin(context)
    opt Run is active
        A->>C: execute(proposal, context, tool)
        alt allow / allow_with_warning
            C->>T: Invoke tool
            T-->>C: Result
            C-->>A: executed=True
        else block
            C-->>A: Skip tool, allow a new proposal
        else abort
            C-->>A: Skip tool, abort run
        end
        opt Run is active
            A->>C: finish(context, response)
        end
    end
```

## Choose an enforcement mode

A v2 contract defines the rules. The application must supply an explicit `EnforcementPolicy` for each run. A [v1 contract](https://github.com/CarlosUrteaga/vogtcon/blob/main/examples/notification_contract.yaml) stores the mode in its YAML and can be loaded without a separate policy.

| Mode | Decision on a proposed tool call | What happens next |
| --- | --- | --- |
| `no_contract` | `allow` without evaluating the rules | The tool runs. This mode provides an experimental baseline. |
| `advisory` | `allow_with_warning` on a violation | The tool runs and the decision reports the violation. |
| `guarded` | `block` on a violation | The tool is skipped and the agent can propose another action. |
| `strict` | `abort` on a violation | The tool is skipped and the run ends in `aborted`. |

Check `controller.state` after `begin` and each `execute`. In strict mode, a pre-execution violation also aborts the run. A violation at `finish` sets the state to `failed_post`. Effects that have already occurred remain in place.

## Decision logs and traces

Pass `recorder=JsonlDecisionLog(path)` when creating the controller to record decisions in a local JSONL file. The controller writes the decision to disk before invoking the tool. If that write fails, the tool is skipped. If the tool itself raises an exception, its effects may be unknown. The log is designed for sequential runs in one process.

For tracing, pass a `TelemetryObserver` to the controller and wrap the run in `with telemetry.run(run_id, contract_id)`. The application configures the OpenTelemetry exporter. The `trace_id` connects spans with decision records. For custom rules with `RuleCatalog` or applications that already manage their own lifecycle with `GovernedToolExecutor`, see the [integration guide (Spanish)](https://github.com/CarlosUrteaga/vogtcon/blob/main/INTEGRACION.md).

## More examples

- **Retrieval-augmented generation (RAG) with LangChain.** The agent retrieves documents from an in-memory vector store and applies the contract before publishing a brief. The reference environment uses Linux x86_64, Python 3.12 and CPU PyTorch. On Intel macOS, use Docker or Podman to run the governed agent, the baseline and the tests with the commands below. The first build downloads dependencies and the model. The container then runs offline. [Agent](https://github.com/CarlosUrteaga/vogtcon/blob/main/examples/langchain_rag_agent.py) · [Dependency lock](https://github.com/CarlosUrteaga/vogtcon/blob/main/examples/requirements-langchain-rag.txt) · [Report (Spanish)](https://github.com/CarlosUrteaga/vogtcon/blob/main/examples/REPORTE_LANGCHAIN_RAG.md)
- **Mexican electronic invoices (CFDI).** The example reconciles synthetic invoices and bank transactions against local records. It runs offline and demonstrates application policy. Tax validation and queries to Mexico’s tax authority (SAT) are outside its scope. [Agent](https://github.com/CarlosUrteaga/vogtcon/blob/main/examples/cfdi_agent.py) · [Dependencies](https://github.com/CarlosUrteaga/vogtcon/blob/main/examples/requirements-cfdi.txt) · [Report (Spanish)](https://github.com/CarlosUrteaga/vogtcon/blob/main/examples/REPORTE_CFDI_SAT.md)

```bash
bash scripts/run_rag.sh --container governed
bash scripts/run_rag.sh --container pre
bash scripts/run_rag.sh --container test
```

## Development and tests

After setting up the checkout with the `uv sync` command above, run the controller tests and verify that a separate environment can consume the built wheel.

```bash
uv run --no-sync python -m unittest discover -s tests -p 'test_execution.py'
sh tests/smoke_wheel_consumer.sh
```

Benchmark-dependent tests use `GOVERNOR_BENCHMARK_ROOT` to locate a local benchmark checkout. The exploratory pilot covers scenarios `S-001`, `S-013` and `S-016` across all four modes. The [pilot script](https://github.com/CarlosUrteaga/vogtcon/blob/main/pilots/benchmark_probe.py) defaults to four runs and accepts `--scenarios` and `--modes` for the twelve-run selection. Differences between the manifest and the checkout limit historical comparisons.

Automated tests use scripted models, and the package provides neither a distributed ledger nor an LLM-based Governor. Older reports use the former name `governor_contracts`.

## License

[Apache License 2.0](https://github.com/CarlosUrteaga/vogtcon/blob/main/LICENSE)
