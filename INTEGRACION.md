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

La telemetría observa las comprobaciones y correlaciona los registros; la decisión que permite o bloquea una herramienta se toma sincrónicamente. Para ver spans en consola y un agente Pydantic AI instrumentado, ejecuta [el ejemplo de pruebas](PRUEBAS.md).

## Alcance actual

La biblioteca incluye una puerta determinista, contratos v1 y v2, reglas propias, registro local y observación OpenTelemetry. No incluye todavía un CLI de producto, un adaptador automático para cualquier framework de agentes ni un Governor basado en LLM. La integración requiere conectar explícitamente cada herramienta con efectos a la puerta. Los contratos v1 históricos conservan `mode` dentro del YAML; con v2 el modo se pasa mediante `EnforcementPolicy` por corrida.
