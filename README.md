<!-- Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
SPDX-License-Identifier: Apache-2.0 -->

# Governor Contracts

Biblioteca Python experimental para evaluar contratos antes y después de que un agente use herramientas. El Governor actual es determinista. El ejemplo de Pydantic AI demuestra cómo conectar un agente propio; el núcleo de `vogtcon` no importa Pydantic AI.

El repositorio público, la distribución en PyPI y el import de Python se llaman `vogtcon`. El proyecto se publica bajo [Apache License 2.0](LICENSE). Algunos reportes históricos mencionan el nombre anterior `governor_contracts` y la copia vendor del benchmark; se conservaron como evidencia de esas etapas.

Para empezar con una prueba local, consulta [Cómo probar Governor Contracts](PRUEBAS.md).
Para incorporarlo a un agente propio, sigue la [guía de integración](INTEGRACION.md).

## Usar como librería

Instala el paquete con `uv pip install .` desde este proyecto, o construye el
wheel con `uv build` e instala ese archivo `.whl` con `pip`. Pydantic AI es opcional;
se necesita el extra `pydantic-ai` solo para `examples/custom_agent.py`.

El siguiente ejemplo usa [un contrato YAML v2](examples/notification_contract_v2.yaml)
y una herramienta propia. El contexto proviene de la aplicación anfitriona, no
de los argumentos que proponga el agente:

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

En v2, el YAML contiene las reglas y su fingerprint, mientras que
`EnforcementPolicy` fija el modo para cada ejecución. El mismo contrato puede
usarse con `no_contract`, `advisory`, `guarded` o `strict` sin cambiar su
identidad. Hay que pasar la política explícitamente; la ausencia de política
en v2 es un error de configuración. Los contratos históricos v1, como
[notification_contract.yaml](examples/notification_contract.yaml), mantienen
su `mode` dentro del YAML y siguen aceptando la misma API sin `policy=`.
En `no_contract`, el registro conserva ese modo y no evalúa reglas: una lista
vacía de infracciones en ese modo no significa que las reglas pasaron.

`load_contract` devuelve un `ContractDocument`: `.contract` es la vista tipada y
`.original` conserva el documento parseado. `Governor` evalúa reglas sin ejecutar
herramientas; `RuleCatalog` añade reglas propias. La fábrica
`WorkflowController.from_contract_path` usa el mismo catálogo al cargar y
evaluar el contrato, y crea un controlador determinista por corrida. La
construcción directa de `WorkflowController` sigue disponible para inyectar un
`Governor` con evaluador propio. `WorkflowController` gestiona pre, runtime y
post; `GovernedToolExecutor` ofrece solo el check y la invocación runtime si la
aplicación ya gestiona el ciclo. `RunRecorder` es el protocolo para persistir
eventos; `JsonlDecisionLog` es su implementación local. `TelemetryObserver`
recibe un proveedor OpenTelemetry configurado por la aplicación y relaciona
spans con los registros mediante `trace_id` y `span_id`.

`pre` y `post` contienen violaciones, pero no una decisión de herramienta.
Consulta `controller.state` antes de seguir: en modo `strict`, una violación
pre/runtime aborta; en `guarded`, un bloqueo runtime permite proponer otra
acción. La llamada a la herramienta ocurre únicamente si la decisión runtime
es `allow` o `allow_with_warning`.

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
