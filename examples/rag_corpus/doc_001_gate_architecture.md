<!-- Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
SPDX-License-Identifier: Apache-2.0 -->

# Arquitectura de puerta sincrona en WorkflowController

El componente central de gobernanza en Governor Contracts es `WorkflowController`. Este controlador implementa una puerta síncrona y determinista que intercepta cada invocación de herramientas efectuada por el agente.

## Evaluación síncrona en `execute`

El método `WorkflowController.execute(action, context, tool)` opera como una barrera de control estricta:

1. **Evaluación previa a la ejecución**: Antes de invocar la función real de la herramienta (`tool`), el controlador evalúa las reglas de tiempo de ejecución (`runtime_rules`) configuradas en el catálogo y declaradas en el contrato.
2. **Decisiones restrictivas**:
   - Cuando la evaluación resulta en una decisión de tipo `block` (bajo política `guarded`) o `abort` (bajo política `strict`), la función real `tool` **nunca es llamada**.
   - El resultado devuelto refleja explícitamente `executed=False`.
3. **Registro de auditoría**:
   - `JsonlDecisionLog` registra de manera inmediata y síncrona el evento `decision` correspondiente, estableciendo el estado `execution_status="not_started"`.
   - Dado que la herramienta no llegó a ejecutarse, no se genera ni persiste ningún evento de tipo `tool_completed`.

Esta garantía asegura que ningún efecto secundario no autorizado, invocación externa o mutación de estado pueda ocurrir si las reglas de gobernanza rechazan la propuesta de acción.
