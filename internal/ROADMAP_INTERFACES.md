# Roadmap de interfaces de vogtcon: CLI, skill y MCP

**Estado: propuesta, 23 de noviembre de 2026.** La gobernanza en Python ya es integrable. Esta fase busca que un desarrollador pueda **validar un contrato y explicar qué pasó con una acción sin escribir Python ni instalar el benchmark**. La prioridad es CLI → skill → evaluar si hace falta MCP. No reabre los hitos del MVP ni la ampliación de la campaña.

## Punto de partida y límites

- El CLI reutiliza `load_contract()` y lee los eventos `RunEvent` v1 que escribe `JsonlDecisionLog`. No duplica validadores ni importa escenarios o métricas del benchmark.
- La evidencia disponible permite correlacionar decisiones y eventos de herramienta por `run_id` y `action_index`. No incluye argumentos, resultados ni confirmaciones de negocio. `tool_completed` confirma que terminó la invocación registrada, no que el destino aplicó el efecto. `tool_error` o un final ausente después de `allow` dejan el efecto indeterminado.
- CLI, skill y MCP de consulta no son puertas de ejecución. Las acciones reales siguen pasando por `WorkflowController.execute()` o `GovernedToolExecutor.execute()` en el host, con estado y autorizaciones que el modelo no puede otorgarse.

## Fases y criterios de salida

| Fase | Entregable | Criterio de salida |
| --- | --- | --- |
| **1. CLI local** | Dos comandos propuestos: `vogtcon validate <contrato>` y `vogtcon explain <registro.jsonl>`. Salida legible y `--json` para scripts. Solo lectura, sin red y sin LLM. | Desde un wheel instalado en un entorno limpio y sin benchmark, validar contratos v1/v2 y explicar una traza con bloqueo, reintento y finalizador de herramienta. Cubrir entradas inválidas, trazas parciales y errores. |
| **2. Skill de revisión** | Skill opcional de Codex que usa el CLI para revisar un contrato y explicar una traza, citando reglas e intentos concretos. La documentación indica qué hacer si el CLI o la evidencia faltan. | Una persona nueva sigue el flujo en el ejemplo de notificaciones y en un segundo consumidor, sin importar el benchmark. La skill conserva diferencias entre bloqueo, reintento, invocación y efecto desconocido; no ejecuta el flujo inspeccionado. |
| **3. Decisión MCP** | Solo si hay un consumidor concreto sin terminal o una necesidad real de consulta compartida: prototipo separado que expone las mismas operaciones de lectura. Sin dependencia MCP en el núcleo. | Identificar cliente, fuente de datos y permisos antes de construir. Si se implementa, probar paridad con el CLI y acceso solo a contratos o registros autorizados, sin rutas arbitrarias, herramientas de escritura ni concesión de permisos. Si no hay consumidor, queda diferido. |

## Alcance del primer corte

- **`validate`:** usar el cargador público. Informar ID, versión y verificación de huella v2 cuando aplique. Distinguir contrato inválido de regla no disponible en el catálogo del CLI; una regla propia puede requerir el catálogo del host. No cargar código del proyecto ni reescribir la huella para hacer pasar un contrato.
- **`explain`:** admitir el registro de decisiones de `vogtcon`, no cualquier JSONL del benchmark. Mostrar fase, regla, intento y estado de ejecución registrado. Un bloqueo es un resultado válido, no un error del comando. Si falta evidencia o se contradice, reportarlo; no inferir ni una autorización ni un efecto.
- **Prueba de aceptación:** generar trazas pequeñas con el controlador real. En el caso de notificación, distinguir el intento bloqueado del reintento permitido y terminado. Para confirmar que hubo un envío y que precedió una autorización válida, usar además los eventos del host y el destino como evidencia externa; no atribuir esa conclusión al JSONL estándar. Repetir la lectura con otro consumidor para detectar supuestos específicos del ejemplo.
- **Fuera de alcance:** `run` genérico, shell gobernado, aprobación desde el agente, evaluación automática de cumplimiento, servidor remoto y corridas nuevas del benchmark.

## Siguiente decisión

Empezar solo con la fase 1, desde una base limpia de `main`, tras aprobar la [especificación consolidada y el plan TDD](SPEC_CLI_SDD.md). El SDD fija el formato JSON, los códigos de salida y el tratamiento de trazas parciales o contradictorias. Un intento posterior sobre la misma herramienta no demuestra que sea el mismo reintento ni que haya autorización del host. No abrir la fase MCP hasta que el CLI y la skill muestren una necesidad que la terminal no resuelva.
