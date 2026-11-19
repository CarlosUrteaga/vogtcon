<!-- Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
SPDX-License-Identifier: Apache-2.0 -->

# Governor Contracts

Biblioteca Python experimental para evaluar contratos antes y después de que un agente use herramientas. El Governor actual es determinista. El ejemplo de Pydantic AI demuestra cómo conectar un agente propio; el núcleo de `vogtcon` no importa Pydantic AI.

El repositorio público, la distribución en PyPI y el import de Python se llaman `vogtcon`. El proyecto se publica bajo [Apache License 2.0](LICENSE). Algunos reportes históricos mencionan el nombre anterior `governor_contracts` y la copia vendor del benchmark; se conservaron como evidencia de esas etapas.

Para empezar con una prueba local, sigue la sección [Probar la integración](#probar-la-integración).
Para incorporarlo a un agente propio, sigue la [guía de integración](INTEGRACION.md).

## Instalación y uso como librería

Requiere **Python ≥ 3.11**.

Para desarrollo local y ejecución de los ejemplos incluidos:

```bash
# Con uv (recomendado para desarrollo en este repo):
uv sync --extra pydantic-ai --group test

# O mediante pip en modo editable:
python -m pip install -e ".[pydantic-ai]"
```

Si el paquete se consume como distribución publicada en PyPI:

```bash
python -m pip install vogtcon
# Extra opcional si se conecta con Pydantic AI:
python -m pip install "vogtcon[pydantic-ai]"
```

> [!IMPORTANT]
> El ejemplo siguiente asume que se ejecuta desde la raíz del repositorio clonado para tener acceso a [`examples/notification_contract_v2.yaml`](examples/notification_contract_v2.yaml). Si integras `vogtcon` en un proyecto independiente, reemplaza esa ruta por la de tu propio contrato YAML.

```python
from vogtcon import (
    ActionProposal, EnforcementPolicy, ExecutionContext, JsonlDecisionLog,
    WorkflowController,
)

controller = WorkflowController.from_contract_path(
    "examples/notification_contract_v2.yaml", "run-1",
    policy=EnforcementPolicy(mode="guarded"),
    recorder=JsonlDecisionLog("run-1.jsonl"),
)
contract = controller.contract
context = ExecutionContext(
    state={"approval_granted": False},
    available_tools=["send_notification"],
    observed_agent_fingerprint="notification-agent-v1",
    observed_contract_fingerprint=contract.contract_fingerprint,
)
sent = []

def send_notification(proposal: ActionProposal) -> str:
    sent.append(proposal.arguments["message"])
    return "sent"

pre = controller.begin(context)
if controller.state == "active":
    action = ActionProposal(
        tool_name="send_notification",
        arguments={"message": "Hola", "sensitive": True},
    )
    outcome = controller.execute(action, context, send_notification)
    if controller.state == "active":
        post = controller.finish(
            context, {"status": "sent" if outcome.executed else "blocked"}
        )

assert sent == []  # guarded bloqueó la acción sensible sin aprobación
```

### Ciclo de vida y flujo de ejecución

```mermaid
sequenceDiagram
    autonumber
    participant Host as Host App
    participant Gov as WorkflowController
    participant Tool as Herramienta con efectos

    Host->>Gov: begin(context)
    opt controller.state == "active"
        Host->>Gov: execute(proposal, context, tool)
        alt allow / allow_with_warning
            Gov->>Tool: Invocación de la herramienta
            Tool-->>Gov: Resultado de la herramienta
            Gov-->>Host: outcome (executed=True)
        else block (guarded)
            Gov-->>Host: outcome (executed=False; reintento permitido)
        else abort (strict / infracción)
            Gov-->>Host: outcome (corrida abortada)
        end
        opt controller.state == "active"
            Host->>Gov: finish(context, response)
        end
    end
```

### Modos de ejecución (`EnforcementPolicy`)

En v2, el YAML contiene las reglas y su fingerprint, mientras que `EnforcementPolicy` fija el modo para cada corrida (la ausencia de política en v2 es un error de configuración). Los contratos históricos v1, como [`examples/notification_contract.yaml`](examples/notification_contract.yaml), mantienen su modo dentro del YAML y siguen aceptando la misma API sin `policy=`.

| Modo | Regla infringida en runtime | Qué hace la aplicación / controlador |
| :--- | :--- | :--- |
| `no_contract` | No se evalúan reglas | Control experimental. El registro depende de que se configure un recorder; cero violaciones no implica cumplimiento. |
| `advisory` | `allow_with_warning`; se invoca la herramienta | Advierte en el registro o salida y continúa la ejecución. |
| `guarded` | `block`; no se invoca la herramienta | La corrida permanece en estado `active`; permite devolver el bloqueo al agente como feedback para recibir otra propuesta. |
| `strict` | `abort`; no se invoca la herramienta | Termina la corrida; el estado pasa a `aborted` y no se llama a `finish`. |

> [!NOTE]
> Consulta siempre `controller.state` tras `begin` y cada `execute`. La llamada a `finish` solo es válida si la corrida continúa `active`. Si `finish` detecta una infracción en modo `strict`, el estado pasa a `failed_post`: se reporta el fallo, pero no se revierten efectos externos ya realizados.

### Componentes clave

| Componente | Responsabilidad |
| :--- | :--- |
| **Contrato YAML v2** | Declara identidad, herramientas declaradas, reglas runtime y condiciones de salida sin acoplar el modo. |
| **`EnforcementPolicy`** | Fija la política (`no_contract`, `advisory`, `guarded`, `strict`) por corrida. Obligatoria en contratos v2. |
| **`ExecutionContext`** | Hechos aportados exclusivamente por la aplicación host (roles, aprobaciones, fingerprints observados). |
| **`WorkflowController`** | Orquesta el ciclo (`begin`, `execute`, `finish`) y gestiona el estado determinista de la ejecución. |
| **`JsonlDecisionLog`** | Persistencia local síncrona de decisiones antes de ejecutar una herramienta (fail-safe). |
| **`TelemetryObserver`** | Observabilidad OpenTelemetry opcional; correlaciona spans mediante `trace_id`. No autoriza. |

Para extender contratos con reglas personalizadas (`RuleCatalog`), construir evaluadores propios o usar `GovernedToolExecutor` cuando la aplicación ya gestiona el ciclo, consulta la [guía de integración](INTEGRACION.md).

## Probar la integración

Desde esta carpeta:

```bash
uv sync --extra pydantic-ai --group test
PYDANTIC_AI_NO_BANNER=1 .venv/bin/python examples/custom_agent.py --log /tmp/governor-note-events.jsonl
```

El ejemplo hace dos ejecuciones con un modelo programado, sin proveedor ni credenciales: una nota pública sin aprobación confiable queda bloqueada, y otra con aprobación se guarda. El archivo JSONL registra el `run_id`, el contrato, la fase, la decisión y las reglas infringidas. Si ya existe, se añaden líneas; usa una ruta nueva para una demostración aislada. Para ver también los spans en consola, agrega `--trace-console` al segundo comando.

```bash
PYDANTIC_AI_NO_BANNER=1 .venv/bin/python examples/custom_agent.py --log /tmp/governor-note-traced.jsonl --trace-console
```

## Conectar otro agente y otra herramienta

1. Define un contrato YAML con las herramientas y reglas que vas a aplicar. Si necesitas una regla propia, regístrala con `RuleCatalog` y pasa el mismo catálogo a `load_contract` y `Governor`.
2. Crea un `WorkflowController` por ejecución con `from_contract_path(path, run_id, policy=..., rule_catalog=...)`. Para v2, pasa una política explícita; para v1, se usa el modo del YAML. La aplicación anfitriona construye `ExecutionContext` con hechos obtenidos de sus sistemas; no toma roles ni aprobaciones de los argumentos del agente.
3. Llama a `begin(context)` antes de iniciar el agente. Convierte cada llamada a herramienta en un `ActionProposal` y pasa su implementación real a `controller.execute(proposal, context, tool)`. Solo `allow` y `allow_with_warning` invocan la herramienta. Devuelve el bloqueo al agente como feedback o termina el flujo según el modo.
4. Llama a `finish(context, response)` con el resultado final. La comprobación post informa fallos, pero no revierte efectos remotos ya realizados.

En [examples/custom_agent.py](examples/custom_agent.py), `save_note` es la única herramienta con efectos registrada en Pydantic AI. Su [contrato v2](examples/custom_contract.yaml) define reglas sin modo; el host crea `EnforcementPolicy(mode="guarded")` por ejecución mediante la fábrica. La herramienta recibe controlador, contexto confiable y `NoteTool` mediante `RunContext[Deps]`, y llama a `WorkflowController.execute` antes del efecto. Un agente o herramienta externos se sustituyen en ese borde; exponer otra herramienta con efectos directamente al modelo la dejaría fuera de Governor. El ejemplo usa `FunctionModel` y no necesita credenciales. El script toma el fingerprint observado del mismo YAML solo para la demostración; una integración real debe obtener esa identidad de una fuente confiable independiente.

La salida del modelo se conserva como `untrusted_agent_output` para inspección. La aplicación debe mostrar `verified_output`, calculada por el host a partir de las acciones realmente ejecutadas; así un bloqueo no se presenta como un guardado exitoso, aunque el modelo lo afirme.

El registro es opcional: pasa `JsonlDecisionLog(path)` al controlador. La decisión se sincroniza en disco antes de invocar una herramienta; si falla esa escritura, la herramienta no se llama. Una excepción posterior a la invocación se registra como resultado incierto. Este JSONL local está pensado para una ejecución secuencial en un proceso; no promete transacciones distribuidas ni escritura concurrente.

La telemetría también es opcional. Pasa `TelemetryObserver` al controlador y mantén `with telemetry.run(run_id, contract_id)` alrededor de las tres fases. La aplicación configura el SDK/exporter de OpenTelemetry. El ejemplo activa la instrumentación nativa de Pydantic AI sin capturar prompts, argumentos ni respuestas completos; los eventos JSONL y spans comparten `trace_id`. Una caída del exporter no cambia permisos. Las trazas observan el trabajo, pero la autorización se comprueba sincrónicamente antes del efecto.

### Otros ejemplos en el repositorio

- **LangChain RAG ([examples/langchain_rag_agent.py](examples/langchain_rag_agent.py)):** Demuestra que el núcleo de `vogtcon` es agnóstico del framework. Gobierna un agente `create_agent` de LangChain con embeddings offline de HuggingFace y un vector store en memoria bajo checkpoints pre, runtime y post. Requiere instalar [`examples/requirements-langchain-rag.txt`](examples/requirements-langchain-rag.txt).
- **Consumo offline de CFDI ([examples/cfdi_agent.py](examples/cfdi_agent.py)):** Demostración de negocio con un ledger local gobernado para conciliar transacciones sintéticas y facturas de forma determinista y offline. **No es un validador fiscal ni consulta al SAT**; procesa hechos locales bajo políticas de la aplicación. Requiere instalar [`examples/requirements-cfdi.txt`](examples/requirements-cfdi.txt).

## Estado y límites

El paquete conserva `no_contract` como control experimental, además de `advisory`, `guarded` y `strict`. `guarded` bloquea una acción y permite una nueva propuesta; `strict` aborta por violaciones pre/runtime. No hay todavía CLI de producto, adaptador al benchmark dentro del paquete, ledger distribuido ni Governor con LLM. La integración con un proveedor LLM real no forma parte de las pruebas automáticas.

El piloto exploratorio incluye `S-001`, `S-013` y `S-016` en los cuatro modos. El arnés
`pilots/benchmark_probe.py` conserva su selección predeterminada de cuatro runs;
`--scenarios` y `--modes` permiten la selección de 12. Las discrepancias entre
el manifest y el checkout impiden presentar ese piloto como una comparación
histórica congelada.

Ejecuta la suite local con:

```bash
PYDANTIC_AI_NO_BANNER=1 GOVERNOR_BENCHMARK_ROOT=/ruta/al/agent-contracts-benchmark .venv/bin/python -m unittest discover -s tests -p 'test*.py' -q
```

Para comprobar el consumo del wheel desde otro directorio y un entorno limpio,
sin Pydantic AI ni el benchmark, ejecuta `sh tests/smoke_wheel_consumer.sh`.
