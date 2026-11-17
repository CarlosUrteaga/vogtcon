# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""LangChain RAG agent governed by a deterministic Vogtcon contract.

Integrates LangChain's create_agent, offline HuggingFace embeddings, and an in-memory
vector store with Governor checkpoints (pre-execution, runtime per effectful action,
and post-execution schema verification).
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from contextlib import nullcontext
from dataclasses import dataclass, field
import hashlib
import json
import logging
import os
from pathlib import Path
import re
from typing import Any, Literal

from langchain.agents import create_agent
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import tool
from langchain_core.vectorstores import InMemoryVectorStore
from langchain_huggingface import HuggingFaceEmbeddings

from vogtcon import (
    ActionProposal,
    EnforcementPolicy,
    ExecutionContext,
    GovernanceDecision,
    GovernorInput,
    JsonlDecisionLog,
    RuleCatalog,
    RunEvent,
    RunRecorder,
    TelemetryObserver,
    ToolExecutionOutcome,
    WorkflowController,
    load_contract,
)

# Suppress verbose offline tokenizer / embedding notices
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
logging.getLogger("sentence_transformers").setLevel(logging.WARNING)
logging.getLogger("transformers").setLevel(logging.WARNING)

CONTRACT_PATH = Path(__file__).resolve().parent / "langchain_rag_contract.yaml"
CORPUS_MANIFEST_PATH = Path(__file__).resolve().parent / "rag_corpus" / "manifest.json"
EMBEDDING_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
EMBEDDING_REVISION = "c9745ed1d9f207416be6d2e6f8de32d1f16199bf"
AGENT_FINGERPRINT = "langchain-rag-brief-agent-v1"

Mode = Literal["no_contract", "advisory", "guarded", "strict"]
INLINE_CITATION_PATTERN = re.compile(r"\[(doc-[A-Za-z0-9_-]+)\]")


def load_frozen_corpus(
    manifest_path: Path = CORPUS_MANIFEST_PATH,
) -> tuple[dict[str, Any], list[Document]]:
    """Load and verify corpus documents against manifest SHA-256 digests."""
    manifest_file = manifest_path.resolve()
    if not manifest_file.exists():
        raise ValueError(f"Corpus manifest does not exist: {manifest_file}")

    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
    documents: list[Document] = []

    for entry in manifest_data.get("documents", []):
        filename = entry.get("file")
        if not filename:
            raise ValueError(f"Corpus entry missing 'file' field: {entry}")
        doc_path = manifest_file.parent / filename
        if not doc_path.exists():
            raise ValueError(f"Corpus document file not found: {doc_path}")

        content_bytes = doc_path.read_bytes()
        digest = hashlib.sha256(content_bytes).hexdigest()
        expected = entry.get("sha256")
        if digest != expected:
            raise ValueError(
                f"SHA-256 mismatch for {filename}: expected {expected}, got {digest}"
            )

        metadata = {
            "doc_id": entry["doc_id"],
            "title": entry.get("title", ""),
            "source_url": entry.get("source_url", ""),
            "license": entry.get("license", ""),
            "revision": entry.get("revision", ""),
            "sha256": digest,
        }
        documents.append(
            Document(
                page_content=content_bytes.decode("utf-8"),
                metadata=metadata,
            )
        )

    return manifest_data, documents


def default_local_embeddings() -> HuggingFaceEmbeddings:
    """Return offline HuggingFace embeddings backed by local cached files."""
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    return HuggingFaceEmbeddings(
        model_name=EMBEDDING_MODEL_NAME,
        model_kwargs={"local_files_only": True},
    )


def build_vector_store(
    documents: Sequence[Document],
    embeddings: Embeddings | None = None,
) -> InMemoryVectorStore:
    """Index verified documents in an in-memory vector store."""
    emb = embeddings or default_local_embeddings()
    vector_store = InMemoryVectorStore(embedding=emb)
    vector_store.add_documents(documents=list(documents))
    return vector_store


def brief_citations_retrieved(request: GovernorInput) -> bool:
    """Ensure all citations and inline claims exist in host-observed retrieved doc IDs."""
    if request.action is None or request.action.tool_name != "publish_brief":
        return False

    retrieved = set(str(x) for x in request.context.state.get("retrieved_doc_ids", []))
    citation_ids = request.action.arguments.get("citation_ids")
    claims = request.action.arguments.get("claims")

    if (
        not isinstance(citation_ids, list)
        or not citation_ids
        or any(not isinstance(cid, str) or not cid.strip() for cid in citation_ids)
    ):
        return True

    if any(cid not in retrieved for cid in citation_ids):
        return True

    if (
        not isinstance(claims, list)
        or not claims
        or any(not isinstance(c, str) or not c.strip() for c in claims)
    ):
        return True

    cited_set = set(citation_ids)
    for claim in claims:
        inline_ids = INLINE_CITATION_PATTERN.findall(claim)
        if not inline_ids:
            return True
        if any(cid not in cited_set for cid in inline_ids):
            return True

    return False


def brief_approval_required(request: GovernorInput) -> bool:
    """Ensure approval is granted strictly in host context state."""
    if request.action is None or request.action.tool_name != "publish_brief":
        return False
    return request.context.state.get("approval_granted") is not True


RULES = RuleCatalog(
    runtime_rules={
        "brief.citations_retrieved": brief_citations_retrieved,
        "brief.approval_required": brief_approval_required,
    }
)


class _GovernorAbortError(RuntimeError):
    """Raised when the Governor aborts a run (e.g. in strict mode)."""


class _CompositeRecorder:
    """Appends every RunEvent to host list and forwards to secondary recorder if provided."""

    def __init__(
        self,
        primary: list[RunEvent],
        secondary: RunRecorder | None = None,
    ) -> None:
        self._primary = primary
        self._secondary = secondary

    def record(self, event: RunEvent) -> None:
        self._primary.append(event)
        if self._secondary is not None:
            self._secondary.record(event)


@dataclass(slots=True)
class LocalBriefPublisher:
    """Host-owned publisher that renders verified briefs to disk."""

    output_dir: Path
    run_id: str
    corpus_metadata: dict[str, dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.corpus_metadata and CORPUS_MANIFEST_PATH.exists():
            manifest_data = json.loads(CORPUS_MANIFEST_PATH.read_text(encoding="utf-8"))
            self.corpus_metadata = {
                doc["doc_id"]: doc for doc in manifest_data.get("documents", [])
            }

    def __call__(self, proposal: ActionProposal) -> tuple[Path, str]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        brief_path = self.output_dir / f"{self.run_id}-brief.md"
        title = str(proposal.arguments.get("title", "Technical Brief"))
        claims = list(proposal.arguments.get("claims", []))
        citation_ids = list(proposal.arguments.get("citation_ids", []))

        lines = [
            f"# {title}",
            "",
            "## Claims",
        ]
        for claim in claims:
            lines.append(f"- {claim}")
        lines.append("")
        lines.append("## Citations")
        for cid in citation_ids:
            meta = self.corpus_metadata.get(cid)
            if meta:
                meta_parts = []
                if "title" in meta:
                    meta_parts.append(meta["title"])
                if "source_url" in meta:
                    meta_parts.append(meta["source_url"])
                if "license" in meta:
                    meta_parts.append(f"License: {meta['license']}")
                meta_str = f" - {', '.join(meta_parts)}" if meta_parts else ""
            else:
                meta_str = ""
            lines.append(f"- [{cid}]{meta_str}")
        lines.append("")
        content = "\n".join(lines)
        brief_path.write_text(content, encoding="utf-8")
        brief_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return brief_path, brief_sha256


@dataclass(frozen=True, slots=True)
class RagRunResult:
    """Outcome of one governed LangChain RAG run."""

    run_id: str
    mode: str
    state: str
    pre: GovernanceDecision
    actions: tuple[ToolExecutionOutcome[Any], ...]
    post: GovernanceDecision | None
    untrusted_agent_output: str | None
    verified_output: str | None
    published: bool
    brief_path: Path | None
    brief_sha256: str | None
    citation_ids: list[str]
    action_logs: list[dict[str, Any]]
    final_record: dict[str, Any]

    @property
    def agent_output(self) -> str | None:
        """Alias pointing to verified host output."""
        return self.verified_output


@dataclass(slots=True)
class _RagDeps:
    """Host-owned state and dependencies for one governed RAG agent run."""

    run_id: str
    mode: str
    controller: WorkflowController
    context: ExecutionContext
    vector_store: InMemoryVectorStore
    publish_tool: Callable[[ActionProposal], tuple[Path, str]]
    actions: list[ToolExecutionOutcome[Any]]
    action_logs: list[dict[str, Any]]
    host_events: list[RunEvent]
    emit_console: bool
    published: list[tuple[Path, str, list[str]]]
    tool_error: BaseException | None = None


def _chat_result(msg: AIMessage) -> ChatResult:
    return ChatResult(generations=[ChatGeneration(message=msg)])


def _tool_call_result(name: str, args: dict[str, Any], call_id: str) -> ChatResult:
    return _chat_result(
        AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": call_id}])
    )


def _extract_retrieved_ids(retrieve_msgs: Sequence[ToolMessage]) -> list[str]:
    if not retrieve_msgs:
        return []
    content = retrieve_msgs[-1].content
    text = content if isinstance(content, str) else str(content)
    return list(dict.fromkeys(INLINE_CITATION_PATTERN.findall(text)))


class ScriptedRagChatModel(BaseChatModel):
    """Deterministic chat model implementing the 5 acceptance scenarios."""

    scenario: str = "case_a_approved_publish"
    responder: Callable[[list[BaseMessage]], AIMessage | str] | None = None

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        if self.responder is not None:
            res = self.responder(messages)
            msg = AIMessage(content=res) if isinstance(res, str) else res
            return _chat_result(msg)

        tool_messages = [m for m in messages if isinstance(m, ToolMessage)]
        retrieve_msgs = [m for m in tool_messages if m.name == "retrieve_context"]
        publish_msgs = [m for m in tool_messages if m.name == "publish_brief"]
        call_id = f"call_{len(tool_messages) + 1}"

        if self.scenario == "case_a_approved_publish":
            if not retrieve_msgs:
                return _tool_call_result(
                    "retrieve_context",
                    {"query": "¿Qué evidencia muestra que una herramienta fue bloqueada antes de causar un efecto?"},
                    call_id,
                )
            if not publish_msgs:
                retrieved_ids = _extract_retrieved_ids(retrieve_msgs)
                preferred = [cid for cid in retrieved_ids if cid != "doc-gov-004"]
                selected = (preferred or retrieved_ids)[:2] or ["doc-gov-001", "doc-gov-002"]
                claims = [
                    f"La puerta síncrona bloquea antes del efecto y registra el evento sin tool_completed [{cid}]."
                    for cid in selected
                ]
                return _tool_call_result(
                    "publish_brief",
                    {
                        "title": "Evidencia de Bloqueo Síncrono",
                        "claims": claims,
                        "citation_ids": selected,
                    },
                    call_id,
                )
            return _chat_result(
                AIMessage(content="Brief técnico publicado exitosamente con citas verificadas.")
            )

        if self.scenario in ("case_b_invalid_citation", "case_b_empty_citation"):
            if not retrieve_msgs:
                return _tool_call_result(
                    "retrieve_context",
                    {"query": "arquitectura de puerta sincrona"},
                    call_id,
                )
            if not publish_msgs:
                bad_citations = [] if self.scenario == "case_b_empty_citation" else ["doc-inexistente-999"]
                return _tool_call_result(
                    "publish_brief",
                    {
                        "title": "Brief con Cita Inválida",
                        "claims": ["Afirmación no respaldada [doc-inexistente-999]."],
                        "citation_ids": bad_citations,
                    },
                    call_id,
                )
            return _chat_result(
                AIMessage(content="Publicación bloqueada debido a cita inválida o faltante.")
            )

        if self.scenario == "case_c_unapproved":
            if not retrieve_msgs:
                return _tool_call_result(
                    "retrieve_context",
                    {"query": "incidente texto no confiable doc-gov-004 prompt injection"},
                    call_id,
                )
            if not publish_msgs:
                retrieved_ids = _extract_retrieved_ids(retrieve_msgs)
                selected = (
                    [cid for cid in retrieved_ids if cid == "doc-gov-004"]
                    or retrieved_ids[:1]
                    or ["doc-gov-004"]
                )
                claims = [
                    f"Análisis de incidente con instrucciones no confiables tratadas como dato [{cid}]."
                    for cid in selected
                ]
                return _tool_call_result(
                    "publish_brief",
                    {
                        "title": "Análisis de Incidente Prompt Injection",
                        "claims": claims,
                        "citation_ids": selected,
                    },
                    call_id,
                )
            return _chat_result(
                AIMessage(content="Publicación no efectuada: el operador no otorgó aprobación.")
            )

        if self.scenario == "case_d_replan_after_block":
            if not retrieve_msgs:
                return _tool_call_result(
                    "retrieve_context",
                    {"query": "registro jsonl y trazas opentelemetry"},
                    call_id,
                )
            if not publish_msgs:
                return _tool_call_result(
                    "publish_brief",
                    {
                        "title": "Auditoría y Trazas",
                        "claims": ["Afirmación no respaldada [doc-inexistente-999]."],
                        "citation_ids": ["doc-inexistente-999"],
                    },
                    call_id,
                )
            pub_content = str(publish_msgs[-1].content)
            if len(publish_msgs) == 1 and "blocked by Governor" in pub_content:
                retrieved_ids = _extract_retrieved_ids(retrieve_msgs)
                selected = (
                    [cid for cid in retrieved_ids if cid == "doc-gov-003"]
                    or retrieved_ids[:1]
                    or ["doc-gov-003"]
                )
                claims = [
                    f"Registro estructurado en formato JSONL y correlación OpenTelemetry [{cid}]."
                    for cid in selected
                ]
                return _tool_call_result(
                    "publish_brief",
                    {
                        "title": "Auditoría y Trazas (Corregido)",
                        "claims": claims,
                        "citation_ids": selected,
                    },
                    call_id,
                )
            return _chat_result(
                AIMessage(content="Brief publicado exitosamente tras corregir las citas bloqueadas.")
            )

        if self.scenario == "case_e_insufficient_evidence":
            if not retrieve_msgs:
                return _tool_call_result(
                    "retrieve_context",
                    {"query": "receta culinaria pastel de chocolate"},
                    call_id,
                )
            return _chat_result(AIMessage(content="evidencia insuficiente"))

        return _chat_result(AIMessage(content="done"))

    def bind_tools(self, tools: Sequence[Any], **kwargs: Any) -> ScriptedRagChatModel:
        return self

    @property
    def _llm_type(self) -> str:
        return "scripted-rag-chat"


def run_rag_brief(
    *,
    run_id: str,
    context: ExecutionContext,
    model: BaseChatModel,
    vector_store: InMemoryVectorStore,
    output_dir: Path | None = None,
    publish_tool: Callable[[ActionProposal], tuple[Path, str]] | None = None,
    mode: Mode = "guarded",
    recorder: RunRecorder | None = None,
    telemetry: TelemetryObserver | None = None,
    emit_console: bool = False,
    contract_path: Path = CONTRACT_PATH,
    user_query: str = "Genera un brief técnico a partir de las fuentes verificadas.",
) -> RagRunResult:
    """Execute a single governed LangChain RAG run."""
    actual_output_dir = output_dir or Path("/tmp/vogtcon-rag-briefs")
    actual_publish_tool = (
        publish_tool if publish_tool is not None else LocalBriefPublisher(actual_output_dir, run_id)
    )

    host_events: list[RunEvent] = []
    composite_recorder = _CompositeRecorder(primary=host_events, secondary=recorder)

    controller = WorkflowController.from_contract_path(
        contract_path,
        run_id,
        policy=EnforcementPolicy(mode=mode),
        rule_catalog=RULES,
        recorder=composite_recorder,
        telemetry=telemetry,
    )

    span = (
        telemetry.run(run_id, controller.contract.contract_id)
        if telemetry is not None
        else nullcontext()
    )

    with span:
        run_context = context.model_copy(deep=True)
        run_context.state.setdefault("retrieved_doc_ids", [])
        pre = controller.begin(run_context)
        if controller.state != "active":
            final_record = {
                "event": "host_verified_result",
                "run_id": run_id,
                "mode": mode,
                "state": controller.state,
                "published": False,
                "brief_path": None,
                "brief_sha256": None,
                "citation_ids": [],
                "verified_output": "Ejecución no iniciada por Governor",
            }
            if emit_console:
                print(json.dumps(final_record, ensure_ascii=False))
            return RagRunResult(
                run_id=run_id,
                mode=mode,
                state=controller.state,
                pre=pre,
                actions=(),
                post=None,
                untrusted_agent_output=None,
                verified_output="Ejecución no iniciada por Governor",
                published=False,
                brief_path=None,
                brief_sha256=None,
                citation_ids=[],
                action_logs=[],
                final_record=final_record,
            )

        actions: list[ToolExecutionOutcome[Any]] = []
        action_logs: list[dict[str, Any]] = []
        published_list: list[tuple[Path, str, list[str]]] = []

        deps = _RagDeps(
            run_id=run_id,
            mode=mode,
            controller=controller,
            context=run_context,
            vector_store=vector_store,
            publish_tool=actual_publish_tool,
            actions=actions,
            action_logs=action_logs,
            host_events=host_events,
            emit_console=emit_console,
            published=published_list,
        )

        @tool
        def retrieve_context(query: str) -> str:
            """Retrieve relevant reference documents from the verified corpus."""
            retrieved_docs = deps.vector_store.similarity_search(query, k=3)
            current_retrieved = list(deps.context.state.get("retrieved_doc_ids", []))
            for doc in retrieved_docs:
                cid = doc.metadata.get("doc_id")
                if cid and cid not in current_retrieved:
                    current_retrieved.append(cid)
            deps.context.state["retrieved_doc_ids"] = current_retrieved

            snippets = []
            for doc in retrieved_docs:
                cid = doc.metadata.get("doc_id", "unknown")
                title = doc.metadata.get("title", "Untitled")
                snippets.append(
                    f"[{cid}] {title} (UNTRUSTED DATA):\n{doc.page_content}"
                )
            return "\n\n".join(snippets) if snippets else "No documents found."

        @tool
        def publish_brief(title: str, claims: list[str], citation_ids: list[str]) -> str:
            """Publish a verified technical brief through the Governor gate."""
            proposal = ActionProposal(
                tool_name="publish_brief",
                arguments={"title": title, "claims": claims, "citation_ids": citation_ids},
            )
            try:
                outcome = deps.controller.execute(proposal, deps.context, deps.publish_tool)
            except Exception as exc:
                deps.tool_error = exc
                raise
            deps.actions.append(outcome)

            runtime_decision_event = next(
                (
                    e
                    for e in reversed(deps.host_events)
                    if e.phase == "runtime"
                    and e.tool_name == "publish_brief"
                    and e.event_type == "decision"
                ),
                None,
            )
            action_index = (
                runtime_decision_event.action_index
                if runtime_decision_event is not None
                and runtime_decision_event.action_index is not None
                else len(deps.actions)
            )
            trace_id = (
                runtime_decision_event.trace_id
                if runtime_decision_event is not None
                else None
            )

            published_path: Path | None = None
            if outcome.executed and outcome.result:
                published_path, published_sha256 = outcome.result
                deps.published.append((published_path, published_sha256, list(citation_ids)))

            record = {
                "event": "tool_decision",
                "run_id": deps.run_id,
                "mode": deps.mode,
                "action_index": action_index,
                "decision": outcome.decision.decision,
                "violation_rules": [v.rule for v in outcome.decision.violations],
                "trace_id": trace_id,
                "published": bool(outcome.executed),
                "brief_path": str(published_path) if published_path else None,
                "citation_ids": list(citation_ids),
            }
            deps.action_logs.append(record)
            if deps.emit_console:
                print(json.dumps(record, ensure_ascii=False))

            if outcome.decision.decision == "abort":
                raise _GovernorAbortError("Governor aborted this run")
            if not outcome.executed:
                violations_str = ", ".join(v.rule for v in outcome.decision.violations)
                return f"blocked by Governor: {violations_str}"
            return f"published brief at {published_path}"

        agent = create_agent(model, [retrieve_context, publish_brief])

        try:
            agent_result = agent.invoke({"messages": [HumanMessage(content=user_query)]})
            messages = agent_result.get("messages", []) if isinstance(agent_result, dict) else []
            untrusted_agent_output = (
                messages[-1].content
                if messages and hasattr(messages[-1], "content")
                else None
            )
        except _GovernorAbortError:
            untrusted_agent_output = None

        if deps.tool_error is not None:
            raise deps.tool_error

        if controller.state == "active":
            if deps.published:
                pub_path, pub_sha, cids = deps.published[-1]
                status = "published"
                published = True
                brief_path = pub_path
                brief_sha256 = pub_sha
                verified_citations = cids
                verified_output = (
                    f"Publicación verificada en {brief_path} (sha256:{brief_sha256}) "
                    f"con citas {verified_citations}."
                )
            elif deps.actions:
                status = "blocked"
                published = False
                brief_path = None
                brief_sha256 = None
                verified_citations = []
                verified_output = "Publicación bloqueada por Governor; ningún archivo generado."
            else:
                status = "insufficient_evidence"
                published = False
                brief_path = None
                brief_sha256 = None
                verified_citations = []
                verified_output = "evidencia insuficiente"

            post = controller.finish(
                run_context,
                {
                    "status": status,
                    "published": published,
                    "brief_path": str(brief_path) if brief_path else None,
                    "citation_ids": verified_citations,
                    "verified_output": verified_output,
                },
            )
        else:
            post = None
            published = False
            brief_path = None
            brief_sha256 = None
            verified_citations = []
            if controller.state == "aborted":
                verified_output = "Publicación bloqueada por Governor; ningún archivo generado."
            else:
                verified_output = "Ejecución no iniciada por Governor"

        final_record = {
            "event": "host_verified_result",
            "run_id": run_id,
            "mode": mode,
            "state": controller.state,
            "published": published,
            "brief_path": str(brief_path) if brief_path else None,
            "brief_sha256": brief_sha256,
            "citation_ids": verified_citations,
            "verified_output": verified_output,
        }
        if emit_console:
            print(json.dumps(final_record, ensure_ascii=False))

        return RagRunResult(
            run_id=run_id,
            mode=mode,
            state=controller.state,
            pre=pre,
            actions=tuple(deps.actions),
            post=post,
            untrusted_agent_output=untrusted_agent_output,
            verified_output=verified_output,
            published=published,
            brief_path=brief_path,
            brief_sha256=brief_sha256,
            citation_ids=verified_citations,
            action_logs=deps.action_logs,
            final_record=final_record,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run the governed LangChain RAG agent offline"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/tmp/vogtcon-rag-briefs"),
        help="Directory to write generated brief markdown files",
    )
    parser.add_argument(
        "--log",
        type=Path,
        default=None,
        help="Append governance events to this JSONL file",
    )
    parser.add_argument(
        "--trace-console",
        action="store_true",
        help="Export OpenTelemetry spans to console",
    )
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    from opentelemetry.sdk.trace import TracerProvider

    provider = TracerProvider()
    if args.trace_console:
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor

        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
    telemetry = TelemetryObserver(provider)
    recorder = JsonlDecisionLog(args.log) if args.log else None

    # Load corpus documents and initialize vector store
    manifest_data, corpus_docs = load_frozen_corpus(CORPUS_MANIFEST_PATH)
    vector_store = build_vector_store(corpus_docs)

    contract_doc = load_contract(CONTRACT_PATH, rule_catalog=RULES)
    contract_fingerprint = contract_doc.contract.contract_fingerprint

    # Case A: Approved publication
    ctx_a = ExecutionContext(
        state={"approval_granted": True, "retrieved_doc_ids": []},
        available_tools=["publish_brief"],
        observed_agent_fingerprint=AGENT_FINGERPRINT,
        observed_contract_fingerprint=contract_fingerprint,
    )
    run_rag_brief(
        run_id="rag-case-a-approved",
        context=ctx_a,
        model=ScriptedRagChatModel(scenario="case_a_approved_publish"),
        vector_store=vector_store,
        output_dir=args.output_dir,
        mode="guarded",
        recorder=recorder,
        telemetry=telemetry,
        emit_console=True,
    )

    # Case B: Blocked publication due to invalid citation
    ctx_b = ExecutionContext(
        state={"approval_granted": True, "retrieved_doc_ids": []},
        available_tools=["publish_brief"],
        observed_agent_fingerprint=AGENT_FINGERPRINT,
        observed_contract_fingerprint=contract_fingerprint,
    )
    run_rag_brief(
        run_id="rag-case-b-invalid-citation",
        context=ctx_b,
        model=ScriptedRagChatModel(scenario="case_b_invalid_citation"),
        vector_store=vector_store,
        output_dir=args.output_dir,
        mode="guarded",
        recorder=recorder,
        telemetry=telemetry,
        emit_console=True,
    )

    # Case C: Blocked publication due to lack of human approval
    ctx_c = ExecutionContext(
        state={"approval_granted": False, "retrieved_doc_ids": []},
        available_tools=["publish_brief"],
        observed_agent_fingerprint=AGENT_FINGERPRINT,
        observed_contract_fingerprint=contract_fingerprint,
    )
    run_rag_brief(
        run_id="rag-case-c-unapproved",
        context=ctx_c,
        model=ScriptedRagChatModel(scenario="case_c_unapproved"),
        vector_store=vector_store,
        output_dir=args.output_dir,
        mode="guarded",
        recorder=recorder,
        telemetry=telemetry,
        emit_console=True,
    )

    # Case D: Replan and recovery after Governor block
    ctx_d = ExecutionContext(
        state={"approval_granted": True, "retrieved_doc_ids": []},
        available_tools=["publish_brief"],
        observed_agent_fingerprint=AGENT_FINGERPRINT,
        observed_contract_fingerprint=contract_fingerprint,
    )
    run_rag_brief(
        run_id="rag-case-d-replan",
        context=ctx_d,
        model=ScriptedRagChatModel(scenario="case_d_replan_after_block"),
        vector_store=vector_store,
        output_dir=args.output_dir,
        mode="guarded",
        recorder=recorder,
        telemetry=telemetry,
        emit_console=True,
    )

    # Case E: Insufficient evidence scenario
    ctx_e = ExecutionContext(
        state={"approval_granted": True, "retrieved_doc_ids": []},
        available_tools=["publish_brief"],
        observed_agent_fingerprint=AGENT_FINGERPRINT,
        observed_contract_fingerprint=contract_fingerprint,
    )
    run_rag_brief(
        run_id="rag-case-e-insufficient-evidence",
        context=ctx_e,
        model=ScriptedRagChatModel(scenario="case_e_insufficient_evidence"),
        vector_store=vector_store,
        output_dir=args.output_dir,
        mode="guarded",
        recorder=recorder,
        telemetry=telemetry,
        emit_console=True,
    )
