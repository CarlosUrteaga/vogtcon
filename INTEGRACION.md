<!-- Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
SPDX-License-Identifier: Apache-2.0 -->

# Integrar Governor Contracts en un agente Python

Governor Contracts es una biblioteca para comprobar un contrato **antes de iniciar** una ejecución, **antes de cada herramienta** y **al terminar**. El Governor actual evalúa reglas deterministas. La aplicación que aloja al agente conserva el control de las herramientas, los datos de autorización y la respuesta que muestra al usuario. No hace falta usar Pydantic AI: el núcleo acepta cualquier agente que permita interceptar sus llamadas a herramientas.

## Instalar

Se necesita Python 3.11 o superior. Instala la distribución publicada en el entorno de tu aplicación:

```sh
python -m pip install vogtcon
```

Antes de la publicación en PyPI, o para probar cambios locales, usa `python -m pip install .` desde la raíz de este proyecto. Pydantic AI es opcional. Si vas a ejecutar [el ejemplo con Pydantic AI](examples/custom_agent.py), instala también el extra desde la raíz de este proyecto con `python -m pip install ".[pydantic-ai]"`. OpenTelemetry API viene con la biblioteca; para exportar spans instala `opentelemetry-sdk` y configura su exporter en la aplicación.

## Piezas de la integración

| Pieza | Responsabilidad |
| --- | --- |
| Contrato YAML v2 | Declara identidad, herramientas, reglas y condiciones de salida. No contiene el modo. |
| `EnforcementPolicy` | Selecciona `no_contract`, `advisory`, `guarded` o `strict` para una corrida. Es obligatoria con v2. |
| `ExecutionContext` | Lleva hechos que la aplicación obtiene de fuentes confiables: aprobación, herramientas disponibles e identidades observadas. |
| `WorkflowController` | Ejecuta los checkpoints `begin`, `execute` y `finish` y mantiene el estado de una corrida. |
| `JsonlDecisionLog` y `TelemetryObserver` | Registran decisiones y spans opcionales; no autorizan herramientas. |

Se crea **un controlador nuevo y un `run_id` único por ejecución**. La aplicación debe asegurar que toda herramienta con efectos pase por `controller.execute(...)`. Una herramienta expuesta directamente al agente queda fuera de la puerta.

## Integración mínima ejecutable

Este ejemplo usa el [contrato v2 incluido](examples/notification_contract_v2.yaml) y no necesita un LLM. Puedes guardarlo como `probar_integracion.py` en la raíz del proyecto y ejecutarlo con `python probar_integracion.py` después de instalar el paquete.

```python
from vogtcon import (
    ActionProposal,
    EnforcementPolicy,
    ExecutionContext,
    JsonlDecisionLog,
    WorkflowController,
)

run_id = "notification-001"
controller = WorkflowController.from_contract_path(
    "examples/notification_contract_v2.yaml",
    run_id,
    policy=EnforcementPolicy(mode="guarded"),
    recorder=JsonlDecisionLog("notification-001.jsonl"),
)

# Estos datos pertenecen a la aplicación, no a los argumentos del agente.
context = ExecutionContext(
    state={"approval_granted": False},
    available_tools=["send_notification"],
    observed_agent_fingerprint="notification-agent-v1",
    observed_contract_fingerprint=controller.contract.contract_fingerprint,
)
sent = []

def send_notification(proposal: ActionProposal) -> str:
    sent.append(proposal.arguments["message"])
    return "sent"

pre = controller.begin(context)
if controller.state == "active":
    proposal = ActionProposal(
        tool_name="send_notification",
        arguments={"message": "Hola", "sensitive": True},
    )
    outcome = controller.execute(proposal, context, send_notification)
    if controller.state == "active":
        post = controller.finish(
            context,
            {"status": "sent" if outcome.executed else "blocked"},
        )

assert pre.violations == []
assert outcome.decision.decision == "block"
assert not outcome.executed
assert sent == []
assert controller.state == "finished"
```

En esta demostración, el fingerprint observado se toma del contrato cargado para simplificar. En una integración real, la aplicación debe obtener la identidad observada de una fuente de despliegue confiable e independiente. Un fingerprint enviado por el agente no prueba su identidad. El resultado final que se presenta al usuario también debe basarse en `outcome.executed` y en los efectos confirmados, no solo en lo que el modelo afirme.

## Continuación autorizada, registro y cierre

Desde la raíz de este checkout, ejecuta el ejemplo siguiente con `.venv/bin/python -`. Usa el consumidor de notificaciones incluido, el contrato v2, un destino en memoria y un archivo JSONL temporal. No requiere un LLM. Cada corrida mantiene su propio controlador, contrato y `run_id`; el host actualiza la aprobación después del primer bloqueo.

```python
from pathlib import Path
from tempfile import TemporaryDirectory

from vogtcon import (
    EnforcementPolicy,
    ExecutionContext,
    JsonlDecisionLog,
    load_contract,
)
from examples.notification_agent import (
    InMemoryNotificationTool,
    NotificationAgent,
    run_notification,
)

contract = load_contract("examples/notification_contract_v2.yaml").contract

for approve_after_block in (False, True):
    run_id = f"notification-{approve_after_block}"
    host = {"approval_granted": False}
    destination = InMemoryNotificationTool()
    attempts = []

    def trusted_context():
        return ExecutionContext(
            state={"approval_granted": host["approval_granted"]},
            available_tools=["send_notification"],
            observed_agent_fingerprint="notification-agent-v1",
            observed_contract_fingerprint=contract.contract_fingerprint,
        )

    def on_blocked(decision):
        # block significa que execute no invocó la herramienta.
        attempts.append({
            "decision": decision.decision,
            "executed": False,
            "sent_after_attempt": list(destination.sent),
        })
        if approve_after_block:
            host["approval_granted"] = True
        return NotificationAgent().propose("Hola", sensitive=True)

    with TemporaryDirectory() as directory:
        log_path = Path(directory) / "decisions.jsonl"
        result = run_notification(
            run_id=run_id,
            context=trusted_context(),
            message="Hola",
            sensitive=True,
            tool=destination,
            contract=contract,
            policy=EnforcementPolicy(mode="guarded"),
            on_blocked=on_blocked,
            context_provider=trusted_context,
            recorder=JsonlDecisionLog(log_path),
        )

        # runtime informa el último intento; el destino confirma el efecto real.
        attempts.append({
            "decision": result.runtime.decision.decision,
            "executed": result.runtime.executed,
            "sent_after_attempt": list(destination.sent),
        })
        expected_decisions = ["block", "allow"] if approve_after_block else ["block", "block"]
        expected_sent = [[], ["Hola"]] if approve_after_block else [[], []]
        assert [item["decision"] for item in attempts] == expected_decisions
        assert [item["sent_after_attempt"] for item in attempts] == expected_sent
        assert [item["executed"] for item in attempts] == (
            [False, True] if approve_after_block else [False, False]
        )
        assert result.post is not None and result.post.violations == []
        assert result.state == "finished"

        events = JsonlDecisionLog(log_path).read()
        assert all(event.run_id == run_id for event in events)
        if approve_after_block:
            assert [event.event_type for event in events] == [
                "decision", "decision", "decision", "tool_completed", "decision",
            ]
            assert [event.decision for event in events] == [
                None, "block", "allow", None, None,
            ]
            assert [event.action_index for event in events] == [None, 1, 2, 2, None]
            assert events[1].violation_rules == ["sensitive_requires_approval"]
            assert events[3].execution_status == "completed"
        else:
            assert [event.event_type for event in events] == [
                "decision", "decision", "decision", "decision",
            ]
            assert [event.decision for event in events] == [
                None, "block", "block", None,
            ]
            assert not any(event.event_type == "tool_completed" for event in events)

        print(run_id, attempts, result.state, len(events))
```

La primera corrida termina en `block → block` y confirma cero envíos después de ambos intentos. La segunda recibe aprobación del host y termina en `block → allow`, con un envío registrado tras el segundo intento. En ambos casos el último evento es la decisión post y la corrida queda `finished`. El JSONL acredita decisiones y orden; `destination.sent` acredita los efectos observados por la aplicación. El `run_ledger` opcional de `run_notification` se entrega a `finish` como resumen del host cuando el contrato lo exige; ese resumen no reemplaza los eventos ni la comprobación del destino.

## Elegir el modo y gestionar el flujo

| Modo | Regla infringida en runtime | Qué hace la aplicación |
| --- | --- | --- |
| `no_contract` | No se evalúan reglas; se registra el modo | Continúa como control experimental. No interpretes cero violaciones como cumplimiento. |
| `advisory` | `allow_with_warning`; se invoca la herramienta | Muestra o registra la advertencia. |
| `guarded` | `block`; no se invoca la herramienta | Puede ofrecer el bloqueo como feedback al agente y aceptar otra propuesta. |
| `strict` | `abort`; no se invoca la herramienta | Termina la corrida; no llames a `finish`. |

Después de `begin` y de cada `execute`, consulta `controller.state`. Una violación pre en `strict` deja la corrida en `aborted`; un bloqueo en `guarded` la mantiene en `active`. `finish` solo acepta una corrida activa. Si `finish` detecta una violación en `strict`, el estado pasa a `failed_post`: la comprobación informa el fallo, pero no revierte efectos que ya ocurrieron. Las excepciones de la herramienta se propagan y dejan el estado en `aborted`; un efecto externo puede haber quedado en estado incierto.

## Crear tu contrato y reglas

Usa [notification_contract_v2.yaml](examples/notification_contract_v2.yaml) como plantilla: cambia `contract_id`, `approved_agent_configurations`, `declared_tools`, `runtime_rules`, `postconditions` y `response_schema` según tu agente. Los identificadores de reglas incluidas están en [rules.py](src/vogtcon/rules.py). Un contrato v2 requiere las tres fases de validación y un `contract_fingerprint` válido. Cada vez que cambies el contenido del YAML, recalcula ese fingerprint sobre los valores parseados, sin incluir el propio campo:

```python
import hashlib
import json
from pathlib import Path

import yaml

path = Path("mi_contrato.yaml")
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data.pop("contract_fingerprint", None)
canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
data["contract_fingerprint"] = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
```

Para una regla propia, registra un handler que devuelva `True` cuando haya infracción y usa **el mismo catálogo** al cargar y evaluar el contrato:

```python
from vogtcon import RuleCatalog, WorkflowController, EnforcementPolicy

def public_note_requires_approval(request):
    return (
        request.action.tool_name == "save_note"
        and request.action.arguments.get("public") is True
        and request.context.state.get("approval_granted") is not True
    )

catalog = RuleCatalog(runtime_rules={"note.public_requires_approval": public_note_requires_approval})
controller = WorkflowController.from_contract_path(
    "mi_contrato.yaml", "run-001",
    policy=EnforcementPolicy(mode="guarded"),
    rule_catalog=catalog,
)
```

El YAML debe incluir `note.public_requires_approval` en `runtime_rules`. La función se llama solo para una propuesta runtime. Puedes consultar una implementación completa en [custom_agent.py](examples/custom_agent.py), donde la herramienta `save_note` de Pydantic AI recibe `RunContext` y llama a `controller.execute` antes de guardar.

## Registros y trazas

Pasa `JsonlDecisionLog(path)` si necesitas evidencia local de cada decisión. El JSONL contiene `run_id`, fase, modo, nombre de herramienta, decisión, reglas infringidas y, si hay un span activo, `trace_id` y `span_id`; no guarda prompts, argumentos ni resultados completos. La decisión se escribe antes de invocar la herramienta. Este registro local está pensado para un proceso secuencial; si tu aplicación tiene varios workers, implementa `RunRecorder` con un almacenamiento apropiado.

Para añadir trazas, configura un `TracerProvider` en tu aplicación y pásalo al observador:

```python
from opentelemetry.sdk.trace import TracerProvider
from vogtcon import EnforcementPolicy, TelemetryObserver, WorkflowController

provider = TracerProvider()  # Configura aquí tu exporter y procesador de spans.
telemetry = TelemetryObserver(provider)
controller = WorkflowController.from_contract_path(
    "examples/notification_contract_v2.yaml", "run-002",
    policy=EnforcementPolicy(mode="guarded"),
    telemetry=telemetry,
)
with telemetry.run(controller.run_id, controller.contract.contract_id):
    # Aquí van begin(...), cada execute(...) y finish(...) de esta corrida.
    ...
```

La telemetría observa las comprobaciones y correlaciona los registros; la decisión que permite o bloquea una herramienta se toma sincrónicamente. Para ver spans en consola y un agente Pydantic AI instrumentado, ejecuta [el ejemplo del README](README.md#probar-la-integración).

## Integración con LangChain (create_agent)

El patrón probado en [langchain_rag_agent.py](examples/langchain_rag_agent.py), [langchain_rag_contract.yaml](examples/langchain_rag_contract.yaml) y el corpus de referencia [examples/rag_corpus/](examples/rag_corpus/) muestra cómo gobernar agentes basados en LangChain (`create_agent`) sin requerir adaptadores propietarios:

- **Herramientas de solo lectura fuera de la puerta**: `retrieve_context` consulta el almacén vectorial sin modificar el mundo exterior y anota los identificadores observados (`retrieved_doc_ids`) directamente en la copia del host de `ExecutionContext.state`. El modelo nunca tiene acceso de escritura a este estado.
- **Herramientas con efectos a través de la puerta**: `publish_brief` canaliza toda escritura con efectos externos a través de `WorkflowController.execute(ActionProposal(...), context, tool)`. Si el Governor bloquea o aborta la acción, la función subyacente nunca se ejecuta.
- **Reglas basadas en estado confiable**: Las reglas personalizadas `brief.citations_retrieved` y `brief.approval_required` registradas en `RuleCatalog` validan exclusivamente contra `ExecutionContext.state` (hechos verificados por el host), nunca contra argumentos o afirmaciones generadas por el modelo.

### Patrón mínimo de conexión

```python
from langchain.agents import create_agent
from langchain_core.messages import HumanMessage
from langchain_core.tools import tool
from vogtcon import (
    ActionProposal,
    EnforcementPolicy,
    ExecutionContext,
    RuleCatalog,
    WorkflowController,
)

# 1. Reglas personalizadas registradas en el catálogo
rules = RuleCatalog(
    runtime_rules={
        "brief.citations_retrieved": brief_citations_retrieved,
        "brief.approval_required": brief_approval_required,
    }
)

# 2. Inicialización del controlador por corrida
controller = WorkflowController.from_contract_path(
    "examples/langchain_rag_contract.yaml",
    run_id="rag-run-001",
    policy=EnforcementPolicy(mode="guarded"),
    rule_catalog=rules,
)

# 3. Estado confiable mantenido por la aplicación host
context = ExecutionContext(
    state={"approval_granted": True, "retrieved_doc_ids": []},
    available_tools=["publish_brief"],
    observed_agent_fingerprint="langchain-rag-brief-agent-v1",
    observed_contract_fingerprint=controller.contract.contract_fingerprint,
)
controller.begin(context)

# 4. Herramienta de lectura: registra IDs en el host fuera de la puerta
@tool
def retrieve_context(query: str) -> str:
    docs = vector_store.similarity_search(query, k=3)
    for doc in docs:
        cid = doc.metadata.get("doc_id")
        if cid and cid not in context.state["retrieved_doc_ids"]:
            context.state["retrieved_doc_ids"].append(cid)
    return "\n\n".join(f"[{d.metadata['doc_id']}] {d.page_content}" for d in docs)

# 5. Herramienta con efectos: interceptada síncronamente por el Governor
@tool
def publish_brief(title: str, claims: list[str], citation_ids: list[str]) -> str:
    proposal = ActionProposal(
        tool_name="publish_brief",
        arguments={"title": title, "claims": claims, "citation_ids": citation_ids},
    )
    outcome = controller.execute(proposal, context, host_publish_sink)
    if not outcome.executed:
        return f"blocked by Governor: {', '.join(v.rule for v in outcome.decision.violations)}"
    return f"published at {outcome.result[0]}"

# 6. Ejecutar agente LangChain y verificar postcondición
agent = create_agent(model, [retrieve_context, publish_brief])
agent.invoke({"messages": [HumanMessage(content="Genera un brief técnico.")]})
if controller.state == "active":
    controller.finish(context, {"status": "published", "published": True, ...})
```

### Entorno probado y ejecución offline

Las dependencias exactas probadas (registradas en [requirements-langchain-rag.txt](examples/requirements-langchain-rag.txt)) son:

- `vogtcon==0.1.0`
- `langchain==1.5.0`
- `langchain-core==1.8.1`
- `langchain-huggingface==1.2.3`
- `langgraph==1.2.22`
- `sentence-transformers==4.1.0`
- `transformers==4.49.0`
- `huggingface-hub==0.36.2`
- `tokenizers==0.21.4`
- `torch==2.2.2`
- `numpy==1.26.4`
- `opentelemetry-sdk==1.45.2`
- Python: CPython 3.12.11 (macosx_x86_64)
- Modelo de embeddings: `sentence-transformers/all-MiniLM-L6-v2` (revisión `c9745ed1d9f207416be6d2e6f8de32d1f16199bf`)

Para ejecutar el ejemplo gobernado completamente offline:

```sh
HF_HUB_OFFLINE=1 .venv/bin/python examples/langchain_rag_agent.py
```

## Conciliación CFDI con Pydantic AI

El [consumidor CFDI](examples/cfdi_agent.py) usa un `Agent` con
`output_type=ReconciliationReport`, datos sintéticos y `FunctionModel` sin proveedor.
El host extrae los XML, comprueba el catálogo congelado y calcula los pares candidatos
de factura/movimiento bancario. El agente recibe solamente esos hallazgos minimizados.

La herramienta `mark_reconciled` pasa por `WorkflowController.execute` antes de
escribir. La regla propia `cfdi.exact_match_required` consulta `allowed_pairs` y
`ledger_pairs` en el estado del host. Tras una escritura, el host actualiza los pares
consumidos para impedir otra conciliación de la misma factura o movimiento. El YAML
y la regla están en el consumidor; la biblioteca no contiene reglas del SAT.

Instala primero `vogtcon` desde PyPI (`pip install vogtcon==0.1.0`), su wheel local o checkout y luego las dependencias
del consumidor. Desde la raíz del proyecto:

```sh
uv pip install --python .venv/bin/python -r examples/requirements-cfdi.txt
PYDANTIC_AI_NO_BANNER=1 .venv/bin/python examples/cfdi_agent.py --output-dir /tmp/cfdi-demo
PYDANTIC_AI_NO_BANNER=1 .venv/bin/python -m unittest discover -s tests -p 'test_cfdi_agent.py' -q
sh tests/smoke_cfdi_consumer.sh        # verificación con wheel local
sh tests/smoke_pypi_consumer.sh        # verificación con vogtcon==0.1.0 desde PyPI
```

La demostración crea una subcarpeta nueva por ejecución y muestra JSONL de decisiones,
`action_index`, `trace_id` y resultados comprobados leyendo el libro local. Bajo
`guarded`, A escribe una fila; B–E intentan escribir y quedan bloqueados; F y la
variante de versión incorrecta se rechazan antes del agente. `--mode advisory`,
`--mode strict` y `--mode no_contract` permiten comparar políticas con los mismos datos.
Las filas permitidas sin respaldo en el host llevan `authorized_by_host: false`.

Para procesar un lote propio, pasa los tres archivos/directorios de entrada juntos:

```sh
PYDANTIC_AI_NO_BANNER=1 .venv/bin/python examples/cfdi_agent.py \
  --xml-dir /ruta/al/lote/xml \
  --profile /ruta/al/lote/profile.json \
  --bank /ruta/al/lote/bank.csv \
  --output-dir /tmp/cfdi-lote
```

El perfil tiene `receiver_rfc`, `person_type` (`fisica` o `moral`) y `fiscal_regime`.
El CSV lleva las columnas `transaction_id,date,amount_mxn,description`, en ese orden;
fecha `YYYY-MM-DD` e importes de egresos negativos, sin separadores de miles. La carpeta
se lee sin recursión. Se valida todo el lote antes de iniciar el agente: un XML inválido
o un identificador duplicado rechaza el lote sin escrituras. Todos los XML válidos
comparten controlador y libro; si dos facturas compiten por el mismo movimiento,
ambas pasan a revisión por ambigüedad. En este modo se proponen solo los candidatos
del host, sin forzar intentos adversarios como en la demostración A–F. Sigue siendo
un modelo programado local; no envía datos a un LLM. Usa primero datos sintéticos y
consulta el alcance del parser en la documentación de fixtures.

Para conectar otro modelo, llama `run_reconciliation(..., model=tu_modelo)` con las
rutas de entrada, `run_id`, ruta del libro, política, recorder y telemetry. La salida
tipada también se contrasta con los hechos del host: un esquema válido no demuestra
que la conciliación sea verdadera. En esta iteración se exige conservar esos
hallazgos exactamente; no se evalúa generación libre de explicaciones. El ejemplo
no instrumenta llamadas al modelo; sus spans son de gobernanza y herramienta.

El libro es una demostración para un proceso secuencial. Para múltiples workers
se necesita almacenamiento transaccional con unicidad y bloqueo. Las escrituras
ya realizadas no se revierten si falla la salida final del agente, tampoco en `strict`.
No se demuestra aquí un buffer de commit/descarte tras postcheck. Consulta el
[reporte CFDI](examples/REPORTE_CFDI_SAT.md) y la [procedencia de fixtures](examples/cfdi_fixtures/README.md).

## Alcance actual

La biblioteca incluye una puerta determinista, contratos v1 y v2, reglas propias, registro local y observación OpenTelemetry. No incluye todavía un CLI de producto, un adaptador automático para cualquier framework de agentes ni un Governor basado en LLM. La integración requiere conectar explícitamente cada herramienta con efectos a la puerta. Los contratos v1 históricos conservan `mode` dentro del YAML; con v2 el modo se pasa mediante `EnforcementPolicy` por corrida.
