<!-- Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
SPDX-License-Identifier: Apache-2.0 -->

# Registro JSONL y correlacion de trazas OpenTelemetry

La observabilidad y auditoría forense en Governor Contracts se implementan mediante dos componentes complementarios: `JsonlDecisionLog` y `TelemetryObserver`.

## Correlación estructurada

1. **Identificadores de correlación**:
   - Cada decisión de gobernanza y span de ejecución se correlaciona inequívocamente a través de `trace_id`, `span_id` y la tupla `(run_id, action_index)`.
   - `run_id` identifica de forma única la ejecución completa del flujo de trabajo, mientras que `action_index` determina la posición ordinal de cada propuesta de acción evaluada dentro de dicha corrida.
2. **Integración con OpenTelemetry**:
   - `TelemetryObserver` asocia los eventos del controlador con spans activos en el contexto de rastreo distribuido de OpenTelemetry, permitiendo la visualización unificada de decisiones de gobernanza junto con las operaciones de la aplicación host.

## Principio de mínima persistencia y privacidad

Tanto `JsonlDecisionLog` como `TelemetryObserver` siguen estrictamente el principio de no persistir información sensible:
- **No se almacenan prompts completos**: Los textos de entrada o prompts generados para el LLM no se guardan en el registro de decisiones.
- **No se almacenan fragmentos de documentos**: Ni los pasajes recuperados en RAG ni los extractos de documentos citados se persisten en las trazas de auditoría.
- **No se almacenan secretos ni credenciales**: Claves de API, tokens o parámetros confidenciales quedan excluidos de los registros estructurados.

El registro conserva únicamente metadatos de gobernanza: identificadores, nombres de herramientas, decisión adoptada (`allow`, `block`, `abort`), códigos de violaciones y marcas temporales.
