# SDD — CLI local de vogtcon

**Propuesta consolidada del 23 de noviembre de 2026.** Cubre la fase 1 del [roadmap de interfaces](ROADMAP_INTERFACES.md). Esta es la referencia para la implementación y su revisión.

## Resultado esperado

Desde un wheel instalado fuera del repositorio, una persona o CI puede validar un contrato y explicar una corrida usando dos comandos locales de solo lectura. La demostración inicial usa una notificación bloqueada, seguida de otro intento permitido cuya función retorna. El CLI debe explicar esa secuencia **sin afirmar que recibió autorización del host, que se envió la notificación o que la tarea se completó**: para eso hacen falta fuentes adicionales al registro estándar.

## Decisiones de la consolidación

Gemini redactó la primera propuesta e implementó el prototipo del CLI. Esta consolidación conserva sus ejemplos de consola y los criterios AC1–AC10. La revisión de Codex ajustó la especificación al cargador de contratos, al registro de eventos y al smoke del wheel que ya ejecuta CI. Las dos copias de la revisión intermedia tenían el mismo contenido que se incorporó aquí.

El reporte de implementación de Gemini, compartido por Carlos, identifica como entregables el comando de consola en `pyproject.toml`, el módulo `src/vogtcon/cli.py`, las 14 pruebas de `tests/test_cli.py` y el smoke de `tests/smoke_cli.sh`. Gemini señala que siguió la especificación existente en esta ruta. Los cuatro entregables están presentes y las 14 pruebas del CLI pasaron en la comprobación local de esta revisión. Gemini también reportó 211 pruebas y dos smokes exitosos en su ejecución original.

| Tema | Propuesta adoptada | Motivo y verificación |
| --- | --- | --- |
| Experiencia de consola | Del borrador anterior se recuperan la cronología legible, ejemplos de uso y criterios AC1–AC10 enlazados a pruebas. Del SDD local se conserva un único resultado versionado para texto y JSON. | Una persona puede localizar el intento y la regla. CI puede verificar campos y códigos sin depender de la redacción. |
| Validación | Mantener la precedencia de `load_contract()` y el código diferenciado de regla desconocida. | El cargador comprueba catálogo y fases antes de la huella v2. En v1 conserva la huella declarada. V1–V3 ejercitan ambos caminos. |
| Trazas | Conservar orden físico y correlación por intento. Mostrar cuándo vuelve a aparecer el nombre de una herramienta bloqueada y qué finalizador se registró. | El registro carece de argumentos y de concesiones del host. Ordenarlo por secuencia antes de buscar anomalías ocultaría inversiones. E1 y E4 cubren estos casos. |
| Integridad y cierre | Usar los estados por corrida del SDD local y ejemplos contrastantes del borrador. Un aborto observable o un error de herramienta pueden cerrar legítimamente una corrida sin post. | E2–E4 distinguen un ciclo terminado, información ausente y una contradicción. |
| Empaquetado | Adoptar la prueba del comando instalado que proponía el borrador y reutilizar la preparación del wheel ya ejecutada en CI. | P1 verifica el binario desde un directorio consumidor y conserva la prueba por import. |

## Contrato de la interfaz

```text
vogtcon --help
vogtcon --version
vogtcon validate <contract_path> [--json]
vogtcon explain <log_path> [--run-id <run_id>] [--json]
```

- `--help` y `--version` escriben en `stdout` y retornan 0. La versión proviene de los metadatos de la distribución instalada.
- Con argumentos válidos y `--json`, cada ejecución emite exactamente un objeto JSON en `stdout`, incluida una falla de lectura o validación. En estos casos no se mezcla texto de diagnóstico con el JSON. Un error de sintaxis del comando escribe uso en `stderr` y deja `stdout` vacío, incluso si se pasó `--json`.
- En modo humano, resultados y advertencias de análisis van a `stdout`; errores del comando, a `stderr`. La salida humana no es una API estable. No imprimir contenidos crudos de entradas inválidas ni tracebacks en errores esperados.

| Salida | `validate` | `explain` |
| --- | --- | --- |
| **0** | `valid` | `ok`: registro coherente, completo o parcial, incluso con bloqueos o errores de herramienta. |
| **1** | `invalid_contract`: sintaxis, documento, versión, fases o huella rechazados por el cargador. | `invalid_log`: línea, esquema, codificación o archivo vacío inválidos; `inconsistent_log`: semántica contradictoria del registro seleccionado. |
| **2** | `unsupported_rules`: el cargador encontró un identificador no disponible para esa fase en el catálogo estándar; validación no concluida. | `run_not_found`: no existe la corrida pedida en un archivo con eventos legibles. |
| **3** | `io_error` ante error de lectura; argumentos inválidos según la regla de uso anterior. | Igual. |

### `validate`

1. Delegar en `load_contract()` con el catálogo estándar. v1 es un documento **sin** `schema_version`; un valor explícito distinto del entero 2 es inválido. Respetar la excepción existente para v1 `no_contract`, incluida `validation_phases: not_enforced`. No exigir política de ejecución para cargar v2; el modo lo aporta el host en runtime.
2. Para distinguir reglas no soportadas sin inspeccionar mensajes ni reimplementar la carga, el cambio mínimo propuesto es un subtipo de `ValueError`, interno al módulo de contratos, que conserve mensaje y precedencia actuales y lleve campo e IDs ordenados. Código 2 informa **el primer campo** rechazado. Si se rechaza el catálogo antes de verificar fases o huella, no afirmar que esas comprobaciones pasaron.
3. En v2 válido informar huella presente y verificada. En v1 mostrar la huella declarada como no verificada por el cargador. Ante discrepancia v2, usar el diagnóstico del cargador: no recalcular por duplicado ni prometer un valor esperado que la API no devuelve. No cargar catálogos, módulos ni plugins definidos por el usuario en este corte.

### `explain`

1. Leer UTF-8, ignorar líneas en blanco y validar **todas** las líneas físicas no vacías con `RunEvent.model_validate_json()`. Informar el número de la primera línea inválida. Un archivo sin eventos es inválido. `--run-id` filtra el análisis semántico, no el parseo. Sin filtro, devolver corridas en orden de primera aparición.
2. Procesar por corrida en orden físico; **no ordenar por `sequence`** para reparar la evidencia. Los eventos deben compartir contrato y modo y tener una secuencia ascendente desde 1. Una brecha ascendente o un comienzo posterior a 1 son evidencia faltante, no corrupción demostrada. Una secuencia duplicada o descendente es inconsistente.
3. Enlazar decisiones runtime y finalizadores por `(run_id, action_index)` y comprobar nombre y orden. Para cada intento se admite una decisión y como máximo un finalizador. Los índices de decisión crecen; una brecha se marca parcial. Dos decisiones o finalizadores para el mismo intento, nombre discordante o finalizador después de `block`/`abort` son inconsistencias, incluso con huecos. Un finalizador sin decisión es inconsistente en un registro sin hueco previo que pudiera contenerla; si hay ese hueco, marcar la acción `unknown` y el registro parcial. Un finalizador seguido de su propia decisión es inconsistente.
4. Debe haber como máximo un evento de pre y uno de post. Si aparecen, pre va primero y post al final de su corrida. Reportar `violation_rules` en ambos; su decisión es **`null`**, nunca un `allow` inferido. Un post tras un terminal observable, o tras un permiso sin finalizador con secuencia continua, es inconsistente para un registro del controlador.
5. Clasificar cada acción según la tabla. Una acción posterior sobre el mismo nombre después de un bloqueo puede listar el último índice bloqueado anterior en `prior_same_tool_block_action_index`; esa relación es solo por nombre, **no comprueba** igualdad de argumentos, reintento de la misma solicitud ni autorización. Una decisión `allow_with_warning` se trata como permiso para correlación, pero se muestra sin perder las advertencias.

| Decisión observada | Finalizador | `tool_outcome` | `effect_evidence` |
| --- | --- | --- | --- |
| `block` / `abort` | Ninguno | `prevented` | `prevented_by_recorded_decision` |
| `allow` / `allow_with_warning` | `tool_completed` | `completed` | `not_verified` |
| `allow` / `allow_with_warning` | `tool_error` | `error` | `indeterminate` |
| `allow` / `allow_with_warning` | Ninguno | `unfinalized` | `indeterminate` |
| Decisión ausente y hueco compatible | Finalizador registrado | `unknown` | `indeterminate` |

6. Reportar integridad por corrida:
   - **`complete`** si hay pre, no hay huecos ni intentos sin cerrar y se observa un terminal. Terminales posibles: `post_execution`, `pre_abort` en strict con violaciones en pre, `runtime_abort` por `abort` o violación runtime en strict, o `tool_error`. No exigir un post cuando el controlador aborta. `complete` describe la evidencia del ciclo, no el éxito de la tarea.
   - **`partial`** si faltan pre, eventos, finalizador o terminal, sin contradicción demostrable. Si solo se registra un `allow`, no deducir si se inició la herramienta, si el proceso terminó o si hubo efecto. `terminal` queda en `null` cuando no es observable.
   - **`inconsistent`** ante contradicción, incluidas acciones posteriores a un terminal observable. No presentar estados de acción ni conteos como confiables para esa corrida. Si otras corridas son coherentes, conservar sus resultados y retornar 1 para el archivo.

### JSON v1

Campos del sobre en **todo** resultado JSON: `output_version: 1`, `command` (`validate` o `explain`), `status` (tabla de salidas), `path` (argumento original), `data` y `diagnostics` (lista). Cada diagnóstico contiene `code`, `message`, `line` (línea física positiva o `null`) y `run_id` (string o `null`). Los mensajes no forman parte del contrato de automatización.

| Resultado | Campos y convenciones |
| --- | --- |
| `validate / valid` | `data`: `contract_id`, `contract_version` (1 o 2, etiqueta de la salida, no un campo agregado al contrato), `mode` (v1 o `null`), `validation_phases` (lista o `not_enforced`), `fingerprint: {value, verified}`, `declared_tools`, `runtime_rules`, `postconditions`. Listas en orden del contrato. |
| `validate / unsupported_rules` | `data: {field, unsupported_ids}`; diagnóstico `unsupported_rule`. No incluir un estado de verificación de huella. |
| `explain / ok` o `inconsistent_log` | `data: {runs: [...]}`. Cada corrida contiene `run_id`, `contract_id`, `mode`, `trace_integrity`, `terminal`, `pre_execution`, `post_execution`, `actions` y `counts`. Los dos checkpoints son `null` o `{sequence, decision: null, violation_rules}`. |
| Acción de una corrida coherente | `action_index`, `tool_name`, `decision` (o `null` si falta), `decision_sequence` y `tool_event_sequence` (o `null`), `violation_rules` (o `null` si falta la decisión), `prior_same_tool_block_action_index`, `tool_outcome` y `effect_evidence`. `counts` enumera los cinco valores de `tool_outcome`, incluidos ceros. |
| Corrida inconsistente | Identificarla por `run_id`; `trace_integrity: "inconsistent"`. Los demás campos se mantienen presentes con `null`; explicar la contradicción en `diagnostics`. |
| Otros errores | `data: null` y al menos un diagnóstico. |

Códigos mínimos de diagnóstico: `invalid_contract`, `unsupported_rule`, `io_error`, `invalid_event`, `empty_log`, `run_not_found`, `partial_log` e `inconsistent_log`. Vincular cada `partial_log` o `inconsistent_log` a su corrida y a la línea cuando haya una línea causante. Sin timestamps agregados ni lecturas de archivos externos referidos por el log. Texto y JSON se renderizan desde el mismo resultado.

## Ejemplos de aceptación

Las salidas siguientes son ejemplos de la interfaz propuesta. Para `vogtcon validate examples/notification_contract_v2.yaml --json`, la fixture del repositorio determina los valores de este resultado.

```json
{
  "output_version": 1,
  "command": "validate",
  "status": "valid",
  "path": "examples/notification_contract_v2.yaml",
  "data": {
    "contract_id": "example.notification",
    "contract_version": 2,
    "mode": null,
    "validation_phases": ["pre_execution", "runtime", "post_execution"],
    "fingerprint": {
      "value": "sha256:ad61db75c5b4ba43868b51cf287180e7b79adf846a012611178ff6382c692cff",
      "verified": true
    },
    "declared_tools": ["send_notification"],
    "runtime_rules": ["tool.declared_only", "sensitive_requires_approval"],
    "postconditions": ["response.schema_complete"]
  },
  "diagnostics": []
}
```

Para `vogtcon explain decisions.jsonl --run-id demo`, usar una traza con los cinco eventos de E1. La prueba compara las observaciones del texto con las del JSON. El espaciado y el idioma del ejemplo son ilustrativos.

```text
demo  ·  guarded  ·  example.notification
1  pre_execution     0 infracciones
2  intento 1         send_notification  block  sensitive_requires_approval
3  intento 2         send_notification  allow  bloqueo previo de esta herramienta en intento 1
4  intento 2         tool_completed     la función retornó
5  post_execution    0 infracciones
Integridad completa. Una invocación completada. Entrega en destino sin verificar.
```

Si el mismo archivo termina justo después de la línea 3, el comando retorna 0, el intento 1 sigue prevenido y el intento 2 figura como `unfinalized`. El resumen contiene `partial_log` en los diagnósticos, `terminal: null` y efecto indeterminado para el segundo intento. Si el finalizador de la línea 4 se atribuye al intento 1 bloqueado, el comando retorna 1 y clasifica la corrida como `inconsistent`.

### Correspondencia con los criterios del borrador

| Criterios | Evidencia de aceptación en la matriz |
| --- | --- |
| AC1 y AC2 · contrato válido v1/v2 | V1 y V5, incluidos los estados de la huella y la salida JSON anterior |
| AC3 y AC4 · huella alterada y regla de catálogo desconocida | V2 y V3, incluida la precedencia cuando coexisten los dos problemas |
| AC5 · entrada ilegible o malformada | V2, V4 y G1 para código y canales de salida |
| AC6 · bloqueo seguido de otro intento permitido | E1 para la cronología y E4 para las contradicciones |
| AC7 y AC8 · finalizador ausente o error de herramienta | E2 y E3 para cierre, integridad y evidencia del efecto |
| AC9 · salida apta para CI | G1 para parseo y aserciones de campos, E5 y E6 para fallas y filtros |
| AC10 · instalación limpia | P1 para el ejecutable instalado y la carga por import |

## Plan TDD por etapas

### Step 1 —
**Goal:** registrar la interfaz y validar contratos a través del cargador real.

**Files to modify:** `pyproject.toml`, `src/vogtcon/contracts.py`, `tests/test_contracts.py`.

**Files to create:** en una base sin CLI, `src/vogtcon/cli.py` y `tests/test_cli.py`. Si el borrador local se incorpora a la base de trabajo, revisar y adaptar esos archivos existentes.

**Files explicitly not to touch:** `src/vogtcon/models.py`, `src/vogtcon/rules.py`, contratos existentes y benchmark.

**Exact change to make:** añadir `[project.scripts]` con `vogtcon = "vogtcon.cli:main"`; interfaz `argparse`, sobre JSON y traducción de errores. Añadir el subtipo de error de catálogo sin cambiar flujo ni mensaje.

**Existing behavior that must remain unchanged:** firmas, semántica, prioridad de fallas, catálogos del host y manejo v1/v2.

**Contracts, schemas, constants, registries, or public interfaces affected:** nueva interfaz de consola y salida JSON v1; el subtipo sigue siendo `ValueError`.

**Tests to add or update:** V1–V5 y G1 de la matriz; el rojo debe fallar por ausencia del CLI o diagnóstico, no por instalación incompleta.

**Exact command(s) to run for verification:** `uv run --no-sync python -m unittest discover -s tests -p test_cli.py -v`; `uv run --no-sync python -m unittest discover -s tests -p test_contracts.py -v`.

**Expected result:** validación y códigos reproducibles sin modificar el archivo de entrada.

**Definition of done:** fixtures válidos, incompatibles y dañados cubiertos; salida JSON y contrato de errores comprobados.

**Risks or compatibility concerns:** catálogo rechazado antes de huella; no confundir resultado inconcluso con contrato válido.

### Step 2 —
**Goal:** explicar evidencia real, huecos y contradicciones sin convertirlos en conclusiones de negocio.

**Files to modify:** `src/vogtcon/cli.py`, `tests/test_cli.py`.

**Files to create:** `src/vogtcon/cli_trace.py` como analizador interno sin API pública.

**Files explicitly not to touch:** `src/vogtcon/records.py`, `src/vogtcon/execution.py`, pilotos y métricas históricas.

**Exact change to make:** parsear `RunEvent` por línea, correlacionar por corrida/intento y renderizar los mismos resultados en texto y JSON. Añadir primero el caso nominal; luego parciales, abortos e inconsistencias.

**Existing behavior that must remain unchanged:** formato JSONL v1, ciclo del controlador y reglas de despacho.

**Contracts, schemas, constants, registries, or public interfaces affected:** subcomando `explain`, filtro, estados y salida JSON v1.

**Tests to add or update:** E1–E6 y G1; generar la traza nominal con el controlador, mutar copias en un directorio temporal para casos negativos.

**Exact command(s) to run for verification:** `uv run --no-sync python -m unittest discover -s tests -p test_cli.py -v`; `uv run --no-sync python -m unittest discover -s tests -p test_records.py -v`; `uv run --no-sync python -m unittest discover -s tests -p test_execution.py -v`.

**Expected result:** un bloqueo no se trata como error; decisiones, invocaciones y evidencia del efecto quedan separadas.

**Definition of done:** pruebas para cada salida y estado, incluido `tool_error` sin post y `allow_with_warning`.

**Risks or compatibility concerns:** completar una invocación no demuestra entrega; ordenar registros ocultaría inconsistencias.

### Step 3 —
**Goal:** verificar la instalación real y documentar el uso sin benchmark.

**Files to modify:** `README.md`, `README.es.md`, `tests/smoke_wheel_consumer.sh`, `tests/wheel_consumer.py`.

**Files to create:** ninguno previsto.

**Files explicitly not to touch:** dependencias runtime, workflows de publicación, contratos del benchmark y artefactos archivados.

**Exact change to make:** ampliar el smoke existente para generar un registro con el paquete instalado y ejecutar ambos subcomandos con y sin JSON, fuera del checkout y sin `PYTHONPATH`. Documentar una sesión de ejemplo y límites del registro.

**Existing behavior that must remain unchanged:** smoke de consumo por import y cobertura CI existente; el CLI no requiere extras del paquete.

**Contracts, schemas, constants, registries, or public interfaces affected:** entrypoint en wheel y ejemplos de uso; no release en esta fase.

**Tests to add or update:** P1 de la matriz y regresiones existentes.

**Exact command(s) to run for verification:** `bash tests/smoke_wheel_consumer.sh`; `uv run --no-sync python -m unittest discover -s tests -v`; `git diff --check`.

**Expected result:** ambos comandos funcionan con el wheel, contratos copiados y una traza generada localmente. El smoke puede aprovisionar dependencias existentes; la ejecución de los comandos no requiere red.

**Definition of done:** smoke verde, JSON parseable con la biblioteca estándar, guías alineadas y sin archivos originales alterados. Registrar cualquier skip real en la entrega.

**Risks or compatibility concerns:** un import editable puede ocultar un entrypoint ausente; la suite que incluye RAG necesita preparar su entorno por separado.

## Current-State Summary

- **Relevant files and their current responsibilities:** se inspeccionó el merge local `5598e9e` del PR #28 como referencia, no como afirmación sobre el HEAD remoto actual. `src/vogtcon/contracts.py` carga JSON/YAML y valida catálogo antes de fases y huella; `src/vogtcon/models.py` discrimina versiones; `src/vogtcon/records.py` valida cada evento, no su secuencia entre líneas; `src/vogtcon/execution.py` registra decisiones antes de invocar y puede abortar sin post. `pyproject.toml` no define un comando `vogtcon` en esa revisión.
- **Current behavior being changed:** agregar acceso por terminal para inspección; no cambiar cómo se gobiernan herramientas. La rama actual tiene cambios ajenos; no usarla para implementar.
- **Existing tests relevant to the change:** `tests/test_contracts.py`, `tests/test_records.py`, `tests/test_execution.py`, `tests/wheel_consumer.py` y `tests/smoke_wheel_consumer.sh`.
- **Baseline commands that should pass before implementation:** en un checkout limpio de `main` y siguiendo sus instrucciones, preparar `uv sync --locked --extra pydantic-ai --group test`, ejecutar las tres suites focales existentes indicadas arriba y `bash tests/smoke_wheel_consumer.sh`. Para la regresión completa, usar el entorno documentado por CI para CFDI y RAG, o verificar ambos jobs separados de CI; no presentar una suite sin sus extras como equivalente. Comandos propuestos para implementación, no ejecutados para redactar el SDD.

### Trabajo local que puede reutilizarse

El checkout inspeccionado contiene el prototipo de `src/vogtcon/cli.py`, pruebas en `tests/test_cli.py` y un smoke en `tests/smoke_cli.sh`. Reaprovechar el parser, las pruebas de entrada y las invocaciones al binario después de contrastarlos con esta especificación.

| Discrepancia del prototipo | Criterio para cerrar |
| --- | --- |
| `validate` duplica la carga, rechaza v1 `no_contract` con `not_enforced` y marca la huella v1 como verificada. | Usar `load_contract()` y comprobar compatibilidad y precedencia con V1–V3. |
| `explain` ordena eventos por secuencia, puede presentar un checkpoint ausente con `decision: "allow"` y etiqueta `is_retry` por coincidencia de nombre. | Conservar el orden físico, representar checkpoints ausentes como `null` y reportar únicamente el índice del bloqueo previo para la misma herramienta. Cubrir con E1, E3 y E4. |
| `explain` sobre un registro vacío devuelve 0 y `validate` sin ruta devuelve 2. Ambos resultados se confirmaron al invocar el prototipo. | Exigir 1 con `invalid_log` y 3 con diagnóstico de uso, respectivamente. Cubrir con E5 y G1. |
| El smoke encadena el binario con un parser JSON. | Comprobar primero el código de salida del binario y después parsear la salida capturada. Cubrir con P1. |

## Invariants

- No hay red, modelos, ejecución de herramientas, firma, reparación, ni escritura de contratos o registros en los comandos.
- La biblioteca sigue siendo utilizable sin el CLI ni el benchmark. No hay cambios de modos, fingerprint canónico, schemas de origen, eventos, autoridades o reglas de dominio.
- La lectura no eleva evidencia incompleta a éxito ni concede permisos. El formato JSON del CLI tiene versión propia, distinta de la versión de contratos y eventos.

## Test Matrix

| ID | Caso exigido | Resultado verificable |
| --- | --- | --- |
| V1 | YAML/JSON v1 y v2; v1 `no_contract` con `not_enforced` | 0; huella verificada solo en v2; modo v2 `null`. |
| V2 | YAML roto, versión explícita sin soporte, fase faltante en contrato enforced, huella v2 alterada | 1; error del cargador sin corregir el original. |
| V3 | ID desconocido o de otra fase; ID desconocido más huella incorrecta; validación con catálogo del host por API | CLI 2 si el catálogo falla primero; nada de «huella verificada». La API conserva su comportamiento previo. |
| V4 | Archivo inexistente, directorio como entrada o error de permisos simulado | 3; mismo contrato de stdout/stderr en ambos comandos. |
| V5 | Validar dos veces las mismas entradas | Mismo JSON y mismos bytes de entrada. |
| E1 | Pre → block → allow → tool_completed → post generado por el controlador | 0; primer intento prevenido, segundo completado; pre/post con decisión `null`; efecto no verificado. |
| E2 | `allow_with_warning` y terminación; `tool_error` sin post; aborto strict pre/runtime sin post | 0; motivo de cierre correcto, error de herramienta con efecto indeterminado. |
| E3 | Permiso sin finalizador ni post, falta de pre, hueco recuperable y bloqueo sin post | 0; parciales, diagnósticos, sin atribuir resultados ausentes. |
| E4 | Secuencia duplicada/descendente, terminal duplicado, finalizador tras bloqueo, nombre discordante, finalizador huérfano sin hueco | 1; no emitir conteos confiables para esa corrida. |
| E5 | JSONL ajeno, línea dañada entre líneas válidas, versión de evento no soportada, archivo en blanco | 1; número de línea cuando aplica, incluido si hay filtro de corrida. |
| E6 | Dos corridas intercaladas, selección válida y selección ausente | 0 para selección válida o todas; 2 si no existe; no mezclar intentos. Una corrida inválida semánticamente fuera del filtro no invalida la seleccionada. |
| G1 | Ayuda, versión instalada, falta de argumentos, opción desconocida y `--json` en éxito y error esperado | 0 para ayuda/versión, 3 para uso inválido; un único objeto JSON donde corresponde. |
| P1 | Wheel en directorio externo, sin dependencias opcionales ni checkout en imports | Ambos comandos presentes; pasar el smoke y mantener el consumidor Python previo operativo. |

## Scope Control

No incluye skill, MCP, modo servidor, nuevos formatos históricos, streaming, reglas personalizadas cargadas por CLI, consulta de destinos, evaluación con LLM ni campaña. Una traza puede tener varias corridas, pero no se garantiza lectura consistente de un archivo en escritura concurrente. El contrato que se valida no se vincula automáticamente a la traza: esta registra un ID, no prueba la huella del contrato cargado durante la corrida.

## Final Execution Order

1. Aprobar esta especificación y confirmar base limpia de `main` e instrucciones de ese checkout.
2. Verificar baseline del cargador, ejecución, registros y wheel. Si falta un prerrequisito, reportarlo antes de atribuir una falla al CLI.
3. Implementar etapas 1 y 2 en ciclos rojo → verde → refactor. Verificar puntos focales tras cada etapa.
4. Cerrar con etapa 3, smoke aislado, regresiones y revisión del diff. Presentar resultados y desviaciones antes de decidir skill o MCP.
