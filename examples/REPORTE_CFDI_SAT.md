<!-- Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
SPDX-License-Identifier: Apache-2.0 -->

# Reporte de adopción — CFDI con Pydantic AI y vogtcon

Fecha: 2026-11-15. **Integración local implementada y verificada.** El consumidor
lee fixtures CFDI 4.0 y movimientos bancarios, obtiene hallazgos deterministas,
ejecuta un `Agent` de Pydantic AI con salida tipada y controla la escritura del
libro mediante `vogtcon`. Las propuestas del modelo son programadas. No se ha
medido calidad de un LLM real ni validez fiscal de facturas.

## Motivo y objetivo de esta prueba

El objetivo del proyecto es ofrecer `vogtcon` como biblioteca que una aplicación
pueda incorporar para gobernar las herramientas de sus agentes mediante contratos.
El conciliador CFDI se eligió como segundo consumidor, complementario al RAG de
LangChain: utiliza Pydantic AI, entradas estructuradas y un efecto local verificable.
Así se prueba la integración en otro framework y dominio sin introducir reglas
fiscales en el núcleo de la biblioteca.

La pregunta que responde esta etapa es: **¿puede una aplicación Pydantic AI conectar
sus reglas y herramientas a `vogtcon`, permitir una acción autorizada y bloquear una
incorrecta antes de que produzca un efecto, dejando evidencia trazable?**

Los XML y movimientos sintéticos permiten repetir exactamente las propuestas y
comparar políticas. El uso de un modelo programado elimina variación del LLM en
esta prueba del control de ejecución. Esto no mide el razonamiento de un modelo ni
la utilidad de un asistente fiscal para usuarios reales.

## Alcance y criterio de cierre local

La unidad evaluada es el consumidor completo: entradas locales → hechos calculados
por el host → agente con salida tipada → herramienta gobernada → libro local y
registro de decisiones. La aplicación conserva parser, catálogo, matcher y escritura;
`vogtcon` evalúa el contrato en los checkpoints. OpenTelemetry observa esas operaciones.

El cierre local exige cumplir los casos A–F, admitir corrección tras bloqueo en
`guarded`, impedir duplicados, verificar efectos leyendo el libro y ejecutar el
consumidor con una distribución instalada fuera del checkout. También exige conservar las
pruebas anteriores y no modificar el núcleo por necesidades de este ejemplo.
La entrada por lotes amplía ese mismo alcance a una carpeta de XML con un perfil,
un CSV y un único controlador/libro por ejecución.

**Resultado: criterio local y consumo desde PyPI satisfechos.** La última verificación de esta etapa
registró 185 pruebas en verde, de las cuales 24 son de CFDI, y el smoke aislado del
consumidor pasó con las conexiones de red deshabilitadas. El detalle y los comandos
se conservan más abajo. El smoke desde PyPI se repitió el 2026-11-17 y pasó;
esto no cierra la validación de producción.

## Qué se implementó y cuánto modifica la integración

| Pieza | Responsabilidad |
| --- | --- |
| [cfdi_agent.py](cfdi_agent.py) | Parser seguro, validación de perfil/catálogo, matcher, modelos Pydantic, agente y libro local. |
| [cfdi_contract.yaml](cfdi_contract.yaml) | Contrato v2 `example.cfdi_reconciliation`, herramienta y reglas declaradas. |
| [cfdi_fixtures/](cfdi_fixtures/) | XML/CSV/perfil sintéticos, escenarios esperados, extracción SAT y procedencia. |
| [requirements-cfdi.txt](requirements-cfdi.txt) | Dependencias del consumidor, separadas del núcleo. |
| [test_cfdi_agent.py](../tests/test_cfdi_agent.py) | Pruebas de escenarios, límites, fallos y lotes por consola. |
| [smoke_cfdi_consumer.sh](../tests/smoke_cfdi_consumer.sh) | Wheel instalado y consumidor copiado a un entorno temporal, sin acceso a red. |

**Cero cambios en `src/vogtcon/`, `pyproject.toml` o `uv.lock`.** El código del ejemplo
es una aplicación nueva: no existe una aplicación CFDI previa medida con la que
afirmar «solo N líneas de invasividad». La integración añade un controlador por
corrida, contexto confiable, una regla propia, una puerta en la herramienta y los
checkpoints pre/post. Parser, catálogo y matcher son trabajo de la aplicación.

La regla `cfdi.exact_match_required` comprueba el par completo factura/movimiento
contra `allowed_pairs` y excluye facturas o movimientos ya presentes en `ledger_pairs`.
Ambas listas pertenecen al host. El YAML referencia la regla; `RuleCatalog` registra
su implementación en Python. `mark_reconciled` nunca recibe autorizaciones del LLM.
Después de cada efecto se actualiza el estado consumido. El libro también exige
unicidad y se reemplaza atómicamente, para un único proceso.

El agente recibe hallazgos minimizados y devuelve `ReconciliationReport`. Además
de la validación de tipos, un `output_validator` exige concordancia con los hallazgos
del host. No se presenta la frase del modelo como confirmación del efecto: el resultado
verificado lee las filas del libro local. Una propuesta incorrecta vuelve como feedback
en `guarded`; en `strict` termina la corrida. Los intentos se relacionan mediante
`run_id` y `action_index`.

## Escenarios observados

La demostración A–F de la CLI fuerza propuestas de escritura incluso en B–E para demostrar el bloqueo.
En el uso normal de `run_reconciliation`, el modelo programado solo propone los
candidatos del host; `force_attempt` y `repeat_attempt` son controles de prueba.

| Caso | Hecho del host | Resultado en `guarded` | Filas escritas |
| --- | --- | --- | --- |
| A | Receptor/uso/régimen compatibles, un egreso exacto | `allow`, `matched`, corrida `finished` | 1 |
| B | RFC receptor diferente al perfil | `block`, `mismatch` | 0 |
| C | `D01` incompatible con persona moral/régimen `601` de la fixture | `block`, `mismatch` | 0 |
| D | Dos egresos del mismo importe dentro de la ventana | `block`, `ambiguous` | 0 |
| E | PPD y movimiento parcial | `block`, `needs_review` | 0 |
| F | XML malformado | Rechazo de entrada antes del agente y del Governor | 0 |
| F_VERSION | Versión 3.3 con namespace 4.0 | Rechazo de entrada antes del agente y del Governor | 0 |

Se ejecutaron también los mismos A–E con las otras tres políticas:

| Política | A | B–E |
| --- | --- | --- |
| `no_contract` | Una fila | Una fila por caso, `authorized_by_host: false`; sin evaluación de reglas. |
| `advisory` | Una fila | Una fila por caso con `allow_with_warning`; `authorized_by_host: false`. |
| `guarded` | Una fila | Bloqueo, cero filas; admite otra propuesta. |
| `strict` | Una fila | Aborto, cero filas, sin postcheck. |

Esta comparación usa `no_contract` como control **dentro de la biblioteca**; no es
una medición antes/después de quitar físicamente `vogtcon` de la aplicación.

Las pruebas adicionales verifican: corrección tras feedback con índices 1 y 2;
reintento duplicado y reutilización del libro; dos facturas compitiendo por un mismo
movimiento; argumentos que intentan falsificar autorización; esquema de salida inválido
y salida tipada falsa; importes exactos y signos; fechas en los límites 0/7 días y fuera
de ellos; XML con DTD/entidades; códigos de catálogo desconocidos; catálogos alterados;
UUID/transaction IDs duplicados; fingerprint alterado; y fallo de escritura con evento
`tool_error`, estado de ejecución `unknown` y excepción propagada.

## Evidencia de ejecución

Entorno: CPython 3.12.11, `vogtcon==0.1.0`, `pydantic-ai-slim==2.68.0`,
`pydantic==2.14.3`, `defusedxml==0.7.1`, `opentelemetry-sdk==1.45.2`.

```sh
PYDANTIC_AI_NO_BANNER=1 .venv/bin/python examples/cfdi_agent.py --output-dir /tmp/vogtcon-cfdi-acceptance
PYDANTIC_AI_NO_BANNER=1 .venv/bin/python examples/cfdi_agent.py --output-dir /tmp/vogtcon-cfdi-acceptance --mode no_contract
PYDANTIC_AI_NO_BANNER=1 .venv/bin/python examples/cfdi_agent.py --output-dir /tmp/vogtcon-cfdi-acceptance --mode advisory
PYDANTIC_AI_NO_BANNER=1 .venv/bin/python examples/cfdi_agent.py --output-dir /tmp/vogtcon-cfdi-acceptance --mode strict
PYDANTIC_AI_NO_BANNER=1 GOVERNOR_BENCHMARK_ROOT=/Users/carlos/git/agent-contracts-benchmark .venv/bin/python -m unittest discover -s tests -p 'test*.py' -q
sh tests/smoke_cfdi_consumer.sh
sh tests/smoke_wheel_consumer.sh
```

Resultados de la entrega inicial: **181 pruebas en verde** (161 de base, incluyendo LangChain, y 20 nuevas),
smoke del consumidor CFDI **OK**, smoke histórico del wheel **OK**.
El smoke CFDI instala la distribución en otro entorno, verifica que `vogtcon` procede
de ese entorno, deshabilita solicitudes de modelos reales y bloquea conexiones de
sockets. Copia únicamente consumidor, contrato y fixtures; no copia el benchmark.

Extracto literal de auditoría de A, corrida de aceptación local:

```json
{"schema_version":1,"run_id":"cfdi-d3c3ff9d-23d8-46d9-ba49-11f46d76dfb8-A","sequence":2,"contract_id":"example.cfdi_reconciliation","mode":"guarded","phase":"runtime","event_type":"decision","action_index":1,"tool_name":"mark_reconciled","decision":"allow","violation_rules":[],"execution_status":"not_started","trace_id":"9891cf236c4da84a24ad2c6f9b34fbfd","span_id":"981804772c9aee16"}
{"schema_version":1,"run_id":"cfdi-d3c3ff9d-23d8-46d9-ba49-11f46d76dfb8-A","sequence":3,"contract_id":"example.cfdi_reconciliation","mode":"guarded","phase":"runtime","event_type":"tool_completed","action_index":1,"tool_name":"mark_reconciled","decision":null,"violation_rules":[],"execution_status":"completed","trace_id":"9891cf236c4da84a24ad2c6f9b34fbfd","span_id":"81afd73e2b975516"}
```

En B, la decisión fue `block`, regla `cfdi.exact_match_required`, sin `tool_completed`.
La consola también imprime `host_verified_result` con contadores, hallazgos y filas
realmente presentes. Cada ejecución crea una subcarpeta UUID y muestra dónde quedó
su `events.jsonl`, evitando sobrescribir evidencia de otra corrida. Las trazas cambian
entre ejecuciones; las decisiones y los efectos esperados permanecen iguales.

## Datos y límites de lo demostrado

La ampliación del consumidor admite `--xml-dir`, `--profile` y `--bank` juntos
para procesar un lote con un solo controlador y libro. Sin esas opciones conserva
la demostración A–F. Hay pruebas de lote A–E completo (solo A se escribe), entradas
incompletas, carpeta vacía y rechazo del lote entero antes de cualquier efecto si
contiene XML inválido. En modo lote el modelo programado solo solicita candidatos
calculados por el host. La [guía de integración](../INTEGRACION.md#conciliación-cfdi-con-pydantic-ai)
incluye el comando y formato de entradas. El CLI sigue siendo del ejemplo, no un
CLI de producto de la biblioteca.

Verificación tras la ampliación: **185 pruebas en verde** (161 de base y 24 de
CFDI); smoke aislado del consumidor **OK**, con la misma distribución local.

El [manifest del catálogo](cfdi_fixtures/catalog_manifest.json) fija la extracción
de `c_UsoCFDI`/`c_RegimenFiscal` del SAT: 24 usos y 19 regímenes. Se verifican sus
fechas de vigencia para la fecha de emisión. Consulta la
[procedencia y transformación](cfdi_fixtures/README.md) antes de reutilizar estos datos.
La [documentación oficial de Pydantic AI](https://pydantic.dev/docs/ai/guides/testing/)
describe `FunctionModel` para probar flujo, herramientas y validación sin solicitar
un modelo real; esa es la modalidad utilizada aquí.

- `matched` significa candidato por importe y ventana de fecha, no confirmación
  bancaria ni validez fiscal. Los XML son sintéticos, no validan XSD ni sellos.
- Alcance: I/MXN/PUE, un egreso por factura, fecha local desde emisión hasta +7 días
  calendario. PPD, otras monedas, retenciones, CFDI relacionados y complementos
  adicionales pasan a revisión. No se infieren pagos conjuntos ni comisiones a
  partir de descripciones bancarias.
- El libro requiere un solo proceso propietario. No ofrece bloqueo distribuido,
  transacciones bancarias ni compensación de efectos externos.
- No hay buffer de efectos hasta el postcheck. Una salida final inválida puede
  aparecer después de una escritura autorizada: se prueba que esa fila permanece.
  Ni Pydantic ni `strict` implican rollback automático.
- Las trazas verificadas son del Governor y su herramienta, no de llamadas al modelo.
  El agente recibe solo hallazgos; no se habilita captura automática de contenido.
- La prueba de consumo se ejecutó inicialmente con un wheel local y fue posteriormente
  reproducida instalando `vogtcon==0.1.0` directamente desde PyPI en un entorno limpio
  mediante `tests/smoke_pypi_consumer.sh` con conexiones de red deshabilitadas durante la
  ejecución de los casos. Evaluar un LLM real sigue siendo un paso posterior, no demostrado aquí.

## Conclusiones y decisiones que deja la prueba

| Conclusión respaldada | Evidencia y límite |
| --- | --- |
| La biblioteca admite este consumidor Pydantic AI sin cambios en su núcleo. | Contrato y regla propios en el ejemplo; consumo comprobado mediante wheel local y paquete publicado en PyPI, ambos en entornos aislados. No demuestra integración automática con cualquier agente. |
| La puerta controla el efecto antes de escribir. | A se permite; B–E se bloquean en `guarded`; los eventos de decisión preceden a la ejecución. La aplicación debe seguir canalizando todas las escrituras por la puerta. |
| Los modos producen comportamientos distintos y observables. | Comparación de `no_contract`, `advisory`, `guarded` y `strict`, más prueba de corrección con un nuevo `action_index`. No implica rollback de efectos previos. |
| Los hechos del host prevalecen sobre las propuestas del modelo. | Intentos de falsificar pares y salidas tipadas falsas son rechazados. El catálogo, los datos y el matcher del host siguen siendo parte de la base de confianza. |
| La ejecución deja evidencia correlacionada. | JSONL y spans de gobernanza/herramienta comparten identidad de corrida y traza. No se evaluaron trazas de llamadas a un proveedor LLM. |

La decisión de diseño que se conserva es mantener las reglas del dominio y el
control de efectos en el consumidor. No se necesita ampliar el núcleo de `vogtcon`
para sostener este ejemplo. Tampoco se justifica ampliar ahora el alcance a un
sistema fiscal completo para demostrar la integración de la biblioteca.

## Pendientes y siguiente evaluación propuesta

1. **Definir una tarea útil para un LLM real.** Explicar discrepancias y sugerir
   revisión, separando esas explicaciones de los hechos y autorizaciones del host.
   Actualmente se exige devolver exactamente los hallazgos deterministas; sustituir
   el modelo sin cambiar esa tarea aportaría poca evidencia sobre su utilidad.
2. **Ejecutar un piloto controlado con datos sintéticos.** Registrar modelo y versión,
   intentos, bloqueos, recuperaciones, efectos, latencia y tokens; correlacionar las
   llamadas al modelo con la corrida sin capturar datos sensibles. Comparar con el
   control programado, sin exigir igualdad exacta entre respuestas de un LLM real.
La adopción desde PyPI ya se comprobó con [smoke_pypi_consumer.sh](../tests/smoke_pypi_consumer.sh):
`vogtcon==0.1.0` se instaló en un entorno virtual aislado con CPython 3.12 y
pasaron los casos A–F bajo `guarded` con sockets bloqueados durante la ejecución.

Los puntos 1 y 2 siguen pendientes; los resultados actuales no los sustituyen. Validar
XSD, sellos, estado ante el SAT, pagos complejos o concurrencia del libro requeriría
otro alcance y criterios propios. Docker puede facilitar distribución futura, pero
no es requisito del cierre local ya comprobado.
