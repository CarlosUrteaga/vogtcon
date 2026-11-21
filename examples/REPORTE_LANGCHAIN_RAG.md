<!-- Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
SPDX-License-Identifier: Apache-2.0 -->

# Comparativa del Agente RAG en LangChain: Antes (`pre`) vs Después (con `vogtcon`)

Este documento muestra exactamente **qué cambió dentro del agente RAG** al conectarlo a `vogtcon`, comparando la versión base sin gobernanza ([examples/pre/langchain_rag_agent.py](pre/langchain_rag_agent.py)) contra la versión gobernada ([examples/langchain_rag_agent.py](langchain_rag_agent.py)), junto con los outputs reales de ejecutar ambas sobre los mismos escenarios.

---

## 1. Las dos versiones disponibles en el repositorio

| Versión | Archivo | Líneas | Qué hace |
| :--- | :--- | :---: | :--- |
| **Antes (`Pre`)** | [examples/pre/langchain_rag_agent.py](pre/langchain_rag_agent.py) | 491 | LangChain RAG puro (`create_agent` + `InMemoryVectorStore` + `HuggingFaceEmbeddings`). Ejecuta `publish_brief` directamente en disco sin reglas ni verificación. |
| **Después (Gobernado)** | [examples/langchain_rag_agent.py](langchain_rag_agent.py) | 890 | Mismo agente, corpus, vector store y escenarios, pero conectado a `WorkflowController`, reglas `brief.citations_retrieved` / `brief.approval_required`, `JsonlDecisionLog`, `TelemetryObserver` y contrato [langchain_rag_contract.yaml](langchain_rag_contract.yaml). |

Al correr `git diff --no-index --stat examples/pre/langchain_rag_agent.py examples/langchain_rag_agent.py`, el delta total es **`510 insertions(+), 111 deletions(-)`** (+399 líneas netas), repartido así:

| Bloque modificado en el RAG | Qué cambió | Líneas en el diff |
| :--- | :--- | :--- |
| **Corpus, embeddings y vector store** (`load_frozen_corpus`, `default_local_embeddings`, `build_vector_store`) | Sin cambios funcionales (idéntico en ambos archivos). | **0 líneas** |
| **Modelo e invocación LangChain** (`ScriptedRagChatModel`, `create_agent`, `agent.invoke`) | Sin cambios en el modelo ni en el grafo de herramientas. | **0 líneas** |
| **Reglas de negocio desacopladas** (`brief_citations_retrieved`, `brief_approval_required`, `RULES`) | 2 funciones puras que validan contra `ExecutionContext.state` del host. | **+50 líneas** |
| **Herramienta `retrieve_context`** (solo lectura, fuera de la puerta) | Añade `doc_id` recuperados a `deps.context.state["retrieved_doc_ids"]`. | **+6 líneas** |
| **Herramienta `publish_brief`** (con efectos en disco) | Cambia llamada directa a `deps.publish_tool(arguments)` por `deps.controller.execute(proposal, deps.context, deps.publish_tool)`, registra el evento `tool_decision` y devuelve feedback si hay bloqueo. | **+55 líneas** *(~6 líneas de puerta + registro de eventos de consola)* |
| **Ciclo de vida en `run_rag_brief`** + trazas + estado verificado | Crea `WorkflowController`, clona `ExecutionContext`, ejecuta `begin` / `finish`, captura aborto `strict` / errores y construye `host_verified_result`. | **+165 líneas** *(el núcleo de conexión son ~10 líneas)* |
| **CLI `__main__` (5 corridas con `ExecutionContext`, `JsonlDecisionLog` y `TracerProvider`)** | Reemplaza el bucle simple por los 5 contextos confiables (`ctx_a`..`ctx_e`) + trazas OpenTelemetry y log JSONL. | **+105 líneas** |

---

## 2. Qué cambió exactamente dentro del RAG (`diff` real de las 3 piezas clave)

### 2.1. Herramienta de lectura `retrieve_context` (Pre vs Después)

```diff
     @tool
     def retrieve_context(query: str) -> str:
         """Retrieve relevant reference documents from the verified corpus."""
         retrieved_docs = deps.vector_store.similarity_search(query, k=3)
+        current_retrieved = list(deps.context.state.get("retrieved_doc_ids", []))
+        for doc in retrieved_docs:
+            cid = doc.metadata.get("doc_id")
+            if cid and cid not in current_retrieved:
+                current_retrieved.append(cid)
+        deps.context.state["retrieved_doc_ids"] = current_retrieved
+
         snippets = []
         for doc in retrieved_docs:
             cid = doc.metadata.get("doc_id", "unknown")
             title = doc.metadata.get("title", "Untitled")
             snippets.append(f"[{cid}] {title} (UNTRUSTED DATA):\n{doc.page_content}")
         return "\n\n".join(snippets) if snippets else "No documents found."
```

### 2.2. Herramienta con efectos `publish_brief` (Pre vs Después)

```diff
     @tool
     def publish_brief(title: str, claims: list[str], citation_ids: list[str]) -> str:
-        """Publish a technical brief directly without governance checks."""
-        arguments = {"title": title, "claims": claims, "citation_ids": citation_ids}
-        published_path, published_sha256 = deps.publish_tool(arguments)
-        deps.published.append((published_path, published_sha256, list(citation_ids)))
-        record = {
-            "event": "tool_executed_ungoverned",
-            "run_id": deps.run_id,
-            "published": True,
-            "brief_path": str(published_path),
-            "citation_ids": list(citation_ids),
-        }
-        if deps.emit_console:
-            print(json.dumps(record, ensure_ascii=False))
+        """Publish a verified technical brief through the Governor gate."""
+        proposal = ActionProposal(
+            tool_name="publish_brief",
+            arguments={"title": title, "claims": claims, "citation_ids": citation_ids},
+        )
+        outcome = deps.controller.execute(proposal, deps.context, deps.publish_tool)
+        deps.actions.append(outcome)
+        ...
+        if outcome.executed and outcome.result:
+            published_path, published_sha256 = outcome.result
+            deps.published.append((published_path, published_sha256, list(citation_ids)))
+        ...
+        if deps.emit_console:
+            print(json.dumps(record, ensure_ascii=False))  # evento tool_decision
+        if outcome.decision.decision == "abort":
+            raise _GovernorAbortError("Governor aborted this run")
+        if not outcome.executed:
+            violations_str = ", ".join(v.rule for v in outcome.decision.violations)
+            return f"blocked by Governor: {violations_str}"
         return f"published brief at {published_path}"
```

### 2.3. Orquestación en `run_rag_brief` (Pre vs Después)

```diff
+controller = WorkflowController.from_contract_path(
+    contract_path, run_id,
+    policy=EnforcementPolicy(mode=mode), rule_catalog=RULES,
+    recorder=composite_recorder, telemetry=telemetry,
+)
+with span:
+    run_context = context.model_copy(deep=True)
+    run_context.state.setdefault("retrieved_doc_ids", [])
+    pre = controller.begin(run_context)
+    if controller.state != "active":
+        return ...
     agent = create_agent(model, [retrieve_context, publish_brief])
     agent_result = agent.invoke({"messages": [HumanMessage(content=user_query)]})
+    if controller.state == "active":
+        post = controller.finish(run_context, {...})
```

---

## 3. Comparativa de Outputs Reales: Antes (`/tmp/vogtcon-rag-pre`) vs Después (`/tmp/vogtcon-rag-final`)

Ambas versiones se ejecutaron con el mismo modelo `ScriptedRagChatModel`, el mismo corpus y el mismo `InMemoryVectorStore` offline (`sentence-transformers/all-MiniLM-L6-v2`):

- **Antes (`examples/pre/langchain_rag_agent.py`):**
  ```sh
  HF_HUB_OFFLINE=1 .venv/bin/python examples/pre/langchain_rag_agent.py --output-dir /tmp/vogtcon-rag-pre
  ```
- **Después (`examples/langchain_rag_agent.py`):**
  ```sh
  HF_HUB_OFFLINE=1 .venv/bin/python examples/langchain_rag_agent.py --output-dir /tmp/vogtcon-rag-final --log /tmp/vogtcon-rag-final.jsonl
  ```

### Tabla comparativa por escenario

| Escenario | Output **ANTES (`pre`)** | Output **DESPUÉS (con `vogtcon`, `guarded`)** |
| :--- | :--- | :--- |
| **Caso A** (`rag-case-a-approved`) | Publica `rag-case-a-approved-brief.md` (`["doc-gov-002", "doc-gov-001"]`). | **`allow`** → Publica `rag-case-a-approved-brief.md` (`["doc-gov-002", "doc-gov-001"]`), `sha256:f2d772...`. |
| **Caso B** (`rag-case-b-invalid-citation`) | **Publica `rag-case-b-invalid-citation-brief.md` con la cita alucinada `["doc-inexistente-999"]`** (`sha256:84e44b...`). | **`block`** (`brief.citations_retrieved`) → **0 archivos creados**, `published: false`. |
| **Caso C** (`rag-case-c-unapproved`) | **Publica `rag-case-c-unapproved-brief.md` citando `["doc-gov-004"]` sin permiso humano** (`sha256:6d34a2...`). | **`block`** (`brief.approval_required`) → **0 archivos creados**, `published: false`. |
| **Caso D** (`rag-case-d-replan`) | **Publica `rag-case-d-replan-brief.md` en el intento 1 con la cita errónea `["doc-inexistente-999"]`** (`sha256:beaa6c...`). | **`action_index=1`: `block`** (`brief.citations_retrieved`) → agente corrige a `["doc-gov-003"]` → **`action_index=2`: `allow`** → publica el brief corregido (`sha256:d73f7e...`) bajo `trace_id: 513a3ac3f79f918efa59352225959243`. |
| **Caso E** (`rag-case-e-insufficient-evidence`) | No llama `publish_brief`; `agent_output: "evidencia insuficiente"`. | No llama `publish_brief`; `verified_output: "evidencia insuficiente"`. |
| **Total de archivos escritos** | **4 archivos** (incluyendo 3 inválidos/no autorizados: B, C y D intento 1). | **2 archivos** (únicamente A y D corregido). |

---

## 4. Salida Literal en Consola de Ambas Ejecuciones

### 4.1. Salida de `examples/pre/langchain_rag_agent.py` (Antes)

```json
{"event": "tool_executed_ungoverned", "run_id": "rag-case-a-approved", "published": true, "brief_path": "/tmp/vogtcon-rag-pre/rag-case-a-approved-brief.md", "citation_ids": ["doc-gov-002", "doc-gov-001"]}
{"event": "pre_agent_result", "run_id": "rag-case-a-approved", "published": true, "brief_path": "/tmp/vogtcon-rag-pre/rag-case-a-approved-brief.md", "brief_sha256": "f2d7723f875e9262ddf7af2abaf58dab308e10c29f4ce80a8c9a12b8e1c091b4", "citation_ids": ["doc-gov-002", "doc-gov-001"], "agent_output": "Brief técnico publicado exitosamente con citas verificadas."}
{"event": "tool_executed_ungoverned", "run_id": "rag-case-b-invalid-citation", "published": true, "brief_path": "/tmp/vogtcon-rag-pre/rag-case-b-invalid-citation-brief.md", "citation_ids": ["doc-inexistente-999"]}
{"event": "pre_agent_result", "run_id": "rag-case-b-invalid-citation", "published": true, "brief_path": "/tmp/vogtcon-rag-pre/rag-case-b-invalid-citation-brief.md", "brief_sha256": "84e44be5ec5df9db0d2024311077c00b55185253d729a27ef2a3c46ee3349641", "citation_ids": ["doc-inexistente-999"], "agent_output": "Brief publicado sin bloqueo."}
{"event": "tool_executed_ungoverned", "run_id": "rag-case-c-unapproved", "published": true, "brief_path": "/tmp/vogtcon-rag-pre/rag-case-c-unapproved-brief.md", "citation_ids": ["doc-gov-004"]}
{"event": "pre_agent_result", "run_id": "rag-case-c-unapproved", "published": true, "brief_path": "/tmp/vogtcon-rag-pre/rag-case-c-unapproved-brief.md", "brief_sha256": "6d34a2023ad29da8051380f388aa9dd0f56cfb4369cb2b673aac934911e31362", "citation_ids": ["doc-gov-004"], "agent_output": "Brief publicado sin verificación de aprobación."}
{"event": "tool_executed_ungoverned", "run_id": "rag-case-d-replan", "published": true, "brief_path": "/tmp/vogtcon-rag-pre/rag-case-d-replan-brief.md", "citation_ids": ["doc-inexistente-999"]}
{"event": "pre_agent_result", "run_id": "rag-case-d-replan", "published": true, "brief_path": "/tmp/vogtcon-rag-pre/rag-case-d-replan-brief.md", "brief_sha256": "beaa6ca9f2694a028d9961634a9bfb0ef6f5e83198f72fb8f6b1c787837cf3f6", "citation_ids": ["doc-inexistente-999"], "agent_output": "Brief publicado en el primer intento sin corrección."}
{"event": "pre_agent_result", "run_id": "rag-case-e-insufficient-evidence", "published": false, "brief_path": null, "brief_sha256": null, "citation_ids": [], "agent_output": "evidencia insuficiente"}
```

Ejemplo del archivo que el agente **sí llegó a publicar** sin control en `/tmp/vogtcon-rag-pre/rag-case-b-invalid-citation-brief.md`:
```markdown
# Brief con Cita Inválida

## Claims
- Afirmación no respaldada [doc-inexistente-999].

## Citations
- [doc-inexistente-999]
```

### 4.2. Salida de `examples/langchain_rag_agent.py` (Después, con `vogtcon`)

```json
{"event": "tool_decision", "run_id": "rag-case-a-approved", "mode": "guarded", "action_index": 1, "decision": "allow", "violation_rules": [], "trace_id": "d6411a96b75747a6d876f29641933dab", "published": true, "brief_path": "/tmp/vogtcon-rag-final/rag-case-a-approved-brief.md", "citation_ids": ["doc-gov-002", "doc-gov-001"]}
{"event": "host_verified_result", "run_id": "rag-case-a-approved", "mode": "guarded", "state": "finished", "published": true, "brief_path": "/tmp/vogtcon-rag-final/rag-case-a-approved-brief.md", "brief_sha256": "f2d7723f875e9262ddf7af2abaf58dab308e10c29f4ce80a8c9a12b8e1c091b4", "citation_ids": ["doc-gov-002", "doc-gov-001"], "verified_output": "Publicación verificada en /tmp/vogtcon-rag-final/rag-case-a-approved-brief.md (sha256:f2d7723f875e9262ddf7af2abaf58dab308e10c29f4ce80a8c9a12b8e1c091b4) con citas ['doc-gov-002', 'doc-gov-001']."}
{"event": "tool_decision", "run_id": "rag-case-b-invalid-citation", "mode": "guarded", "action_index": 1, "decision": "block", "violation_rules": ["brief.citations_retrieved"], "trace_id": "dc7b1facedf143a100b87cfb225bc211", "published": false, "brief_path": null, "citation_ids": ["doc-inexistente-999"]}
{"event": "host_verified_result", "run_id": "rag-case-b-invalid-citation", "mode": "guarded", "state": "finished", "published": false, "brief_path": null, "brief_sha256": null, "citation_ids": [], "verified_output": "Publicación bloqueada por Governor; ningún archivo generado."}
{"event": "tool_decision", "run_id": "rag-case-c-unapproved", "mode": "guarded", "action_index": 1, "decision": "block", "violation_rules": ["brief.approval_required"], "trace_id": "e1097757fbe6816b3d2de312680aae76", "published": false, "brief_path": null, "citation_ids": ["doc-gov-004"]}
{"event": "host_verified_result", "run_id": "rag-case-c-unapproved", "mode": "guarded", "state": "finished", "published": false, "brief_path": null, "brief_sha256": null, "citation_ids": [], "verified_output": "Publicación bloqueada por Governor; ningún archivo generado."}
{"event": "tool_decision", "run_id": "rag-case-d-replan", "mode": "guarded", "action_index": 1, "decision": "block", "violation_rules": ["brief.citations_retrieved"], "trace_id": "513a3ac3f79f918efa59352225959243", "published": false, "brief_path": null, "citation_ids": ["doc-inexistente-999"]}
{"event": "tool_decision", "run_id": "rag-case-d-replan", "mode": "guarded", "action_index": 2, "decision": "allow", "violation_rules": [], "trace_id": "513a3ac3f79f918efa59352225959243", "published": true, "brief_path": "/tmp/vogtcon-rag-final/rag-case-d-replan-brief.md", "citation_ids": ["doc-gov-003"]}
{"event": "host_verified_result", "run_id": "rag-case-d-replan", "mode": "guarded", "state": "finished", "published": true, "brief_path": "/tmp/vogtcon-rag-final/rag-case-d-replan-brief.md", "brief_sha256": "d73f7e2842977025d5bced4d3667598cc661831cee4b819c37be72c898082698", "citation_ids": ["doc-gov-003"], "verified_output": "Publicación verificada en /tmp/vogtcon-rag-final/rag-case-d-replan-brief.md (sha256:d73f7e2842977025d5bced4d3667598cc661831cee4b819c37be72c898082698) con citas ['doc-gov-003']."}
{"event": "host_verified_result", "run_id": "rag-case-e-insufficient-evidence", "mode": "guarded", "state": "finished", "published": false, "brief_path": null, "brief_sha256": null, "citation_ids": [], "verified_output": "evidencia insuficiente"}
```

Y el archivo corregido publicado en el intento 2 del Caso D (`/tmp/vogtcon-rag-final/rag-case-d-replan-brief.md`):
```markdown
# Auditoría y Trazas (Corregido)

## Claims
- Registro estructurado en formato JSONL y correlación OpenTelemetry [doc-gov-003].

## Citations
- [doc-gov-003] - Registro JSONL y correlacion de trazas OpenTelemetry, https://github.com/CarlosUrteaga/vogtcon/blob/main/examples/rag_corpus/doc_003_audit_and_traces.md, License: Apache-2.0
```

### 4.3. Evidencia de auditoría en `/tmp/vogtcon-rag-final.jsonl` (Caso D)

```json
{"schema_version":1,"run_id":"rag-case-d-replan","sequence":1,"contract_id":"example.langchain_rag_brief","mode":"guarded","phase":"pre_execution","event_type":"decision","action_index":null,"tool_name":null,"decision":null,"violation_rules":[],"execution_status":"not_started","trace_id":"513a3ac3f79f918efa59352225959243","span_id":"fa15ab4e22f8bed2"}
{"schema_version":1,"run_id":"rag-case-d-replan","sequence":2,"contract_id":"example.langchain_rag_brief","mode":"guarded","phase":"runtime","event_type":"decision","action_index":1,"tool_name":"publish_brief","decision":"block","violation_rules":["brief.citations_retrieved"],"execution_status":"not_started","trace_id":"513a3ac3f79f918efa59352225959243","span_id":"9c465a0d55e3aef9"}
{"schema_version":1,"run_id":"rag-case-d-replan","sequence":3,"contract_id":"example.langchain_rag_brief","mode":"guarded","phase":"runtime","event_type":"decision","action_index":2,"tool_name":"publish_brief","decision":"allow","violation_rules":[],"execution_status":"not_started","trace_id":"513a3ac3f79f918efa59352225959243","span_id":"7bec67a18ec32e85"}
{"schema_version":1,"run_id":"rag-case-d-replan","sequence":4,"contract_id":"example.langchain_rag_brief","mode":"guarded","phase":"runtime","event_type":"tool_completed","action_index":2,"tool_name":"publish_brief","decision":null,"violation_rules":[],"execution_status":"completed","trace_id":"513a3ac3f79f918efa59352225959243","span_id":"926f76c4235104f9"}
{"schema_version":1,"run_id":"rag-case-d-replan","sequence":5,"contract_id":"example.langchain_rag_brief","mode":"guarded","phase":"post_execution","event_type":"decision","action_index":null,"tool_name":null,"decision":null,"violation_rules":[],"execution_status":"not_started","trace_id":"513a3ac3f79f918efa59352225959243","span_id":"d818dbde8ba98e61"}
```

---

## 5. Registro Histórico de Validación (Hito 2 - macOS x86_64, Obsoleto)

> [!NOTE]
> Este registro se conserva únicamente como referencia histórica del entorno original de Hito 2. Ese entorno utilizaba `torch==2.2.2` sobre macOS Intel, el cual presenta 26 vulnerabilidades conocidas y fue reemplazado por el entorno seguro de referencia Linux x86_64 (Sección 6).

- **Entorno histórico probado:** `CPython 3.12.11` (`macosx_x86_64`), `langchain==1.5.0`, `langchain-core==1.8.1`, `langchain-huggingface==1.2.3`, `sentence-transformers==4.1.0`, `transformers==4.49.0`, `torch==2.2.2`, `numpy==1.26.4`, `sentence-transformers/all-MiniLM-L6-v2` (revisión `c9745ed1d9f207416be6d2e6f8de32d1f16199bf`).
- **Tests históricos:** `161` pruebas en verde en `tests/` (`143` existentes + `18` en [tests/test_langchain_rag_agent.py](../tests/test_langchain_rag_agent.py), incluyendo modos `advisory`, `strict`, contrabando de citas, *prompt injection* y `tool_error`) y `sh tests/smoke_wheel_consumer.sh` en verde.

---

## 6. Entorno Seguro de Referencia RAG (Linux x86_64, PyTorch CPU y Contenedor Intel)

### 6.1. Justificación y Decisión de Plataforma

La consulta de seguridad de Dependabot reveló 26 alertas abiertas asociadas al stack RAG original (`torch==2.2.2` y `transformers==4.49.0`), incluyendo la vulnerabilidad crítica [GHSA-53q9-r3pm-6pq6](https://github.com/advisories/GHSA-53q9-r3pm-6pq6) en PyTorch (`<2.6.0`) y vulnerabilidades subsecuentes (`<2.13.0`).

Dado que PyTorch [descontinuó los binarios oficiales para macOS x86_64](https://dev-discuss.pytorch.org/t/pytorch-macos-x86-builds-deprecation-starting-january-2024/1690) tras la versión 2.2.2, actualizar PyTorch a versiones seguras (≥2.13.0 / `2.15.0+cpu`) no es compatible de forma nativa en macOS Intel. Por ello:
1. **Entorno de referencia obligatorio:** Linux `x86_64`, CPython 3.12, PyTorch CPU (`torch==2.15.0+cpu`), con resolución completa y reproducible de dependencias directas y transitivas con hashes SHA-256 (`examples/requirements-langchain-rag.txt`).
2. **Stack acoplado HuggingFace:** `transformers==5.23.0`, `sentence-transformers==5.6.0`, `huggingface-hub==1.33.0`, `tokenizers==0.23.3`, `numpy==1.26.4`.
3. **macOS Intel (Darwin x86_64):** Detección temprana (`check_rag_platform()`) antes de cualquier importación de librerías ML. Ejecución mediante contenedor `linux/amd64` ([examples/Dockerfile.rag](Dockerfile.rag)) o máquina Linux remota vía [scripts/run_rag.sh](../scripts/run_rag.sh).
4. **Aislamiento del núcleo de Vogtcon:** `vogtcon` se instala sin dependencias en el entorno RAG (`--no-deps`), garantizando que la librería base siga libre de dependencias ML en `pyproject.toml` y `uv.lock`.

### 6.2. Preparación y Validación Criptográfica del Modelo

Para garantizar operación 100% offline y prevenir ejecución remota de código en deserialización de checkpoints:
- El script [scripts/prepare_rag_model.py](../scripts/prepare_rag_model.py) descarga de forma estricta únicamente archivos `*.json`, `*.txt` y `*.safetensors`, excluyendo y rechazando cualquier peso serializado con Pickle (`.bin`, `.pt`, `.pth`, `.pkl`).
- Genera el inventario criptográfico `vogtcon_snapshot_manifest.json` con tamaño en bytes y digest SHA-256 de cada archivo del snapshot.
- La función `verify_prepared_embedding_snapshot()` valida dicho manifiesto y los archivos en disco antes de inicializar `HuggingFaceEmbeddings`.
- La carga exige explícitamente CPU, archivos locales y Safetensors mediante `model_kwargs={"use_safetensors": True, "local_files_only": True, "trust_remote_code": False}` anidado.

### 6.3. Comandos de Reproducción y Validación

#### En Linux x86_64 (o CI):
```bash
# Verificar consistencia de los lockfiles compilados con hashes
bash scripts/compile_rag_requirements.sh --check

# Preparar snapshot verificado
python scripts/prepare_rag_model.py --output-dir sentence-transformers/all-MiniLM-L6-v2

# Ejecutar suite de pruebas RAG offline
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 python -m unittest discover -s tests -p 'test_langchain_rag_agent.py' -q

# Ejecutar CLIs
python examples/langchain_rag_agent.py --output-dir /tmp/vogtcon-rag-final --log /tmp/vogtcon-rag-final.jsonl
python examples/pre/langchain_rag_agent.py --output-dir /tmp/vogtcon-rag-pre
```

#### En macOS Intel mediante contenedor:
```bash
# Ejecutar suite de pruebas en contenedor linux/amd64 sin red
bash scripts/run_rag.sh --container test

# Ejecutar ejemplo gobernado con salida en /tmp/vogtcon-rag-output
bash scripts/run_rag.sh --container governed

# Ejecutar ejemplo pre con salida en /tmp/vogtcon-rag-output
bash scripts/run_rag.sh --container pre
```

> [!NOTE]
> Las métricas finales de ejecución en GitHub Actions (incluyendo los reportes de `pip-audit` contra las 26 vulnerabilidades de la línea base y la validación del contenedor Docker) se registrarán tras la validación de CI.
