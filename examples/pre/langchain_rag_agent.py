# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Baseline LangChain RAG agent WITHOUT vogtcon governance (Pre-vogtcon).

Uses LangChain's create_agent, offline HuggingFace embeddings, and an in-memory
vector store, calling publish_brief directly without contract or gate checks.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
import hashlib
import json
import logging
import os
from pathlib import Path
import platform
import re
import sys
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from langchain_huggingface import HuggingFaceEmbeddings


def check_rag_platform() -> None:
    """Validate that the host platform supports the RAG execution environment.

    Official PyTorch CPU binary support for macOS x86_64 was deprecated after 2.2.2.
    The Vogtcon RAG reference environment requires Linux x86_64 with Python 3.12.
    On macOS Intel (Darwin x86_64), native execution is not supported; use the
    Linux container image (examples/Dockerfile.rag) or a remote Linux x86_64 environment.
    """
    if sys.platform == "darwin" and platform.machine() in ("x86_64", "AMD64"):
        msg = (
            "ERROR: Native RAG execution is not supported on macOS Intel (Darwin x86_64).\n"
            "Official PyTorch CPU binaries for macOS x86_64 were deprecated after version 2.2.2,\n"
            "and newer versions (>=2.13.0) required to address security advisories are only\n"
            "available for Linux x86_64 and macOS ARM64.\n\n"
            "To run the RAG agent on macOS Intel, use the Linux reference environment:\n"
            "  1. Using Docker/Podman container (linux/amd64):\n"
            "     bash scripts/run_rag.sh --container governed\n"
            "     bash scripts/run_rag.sh --container pre\n"
            "     bash scripts/run_rag.sh --container test\n"
            "  2. Or run directly on a remote Linux x86_64 machine with Python 3.12.\n"
        )
        if __name__ == "__main__":
            sys.stderr.write(msg)
            sys.exit(2)
        raise RuntimeError(msg)


if __name__ == "__main__":
    check_rag_platform()

from langchain.agents import create_agent
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import tool
from langchain_core.vectorstores import InMemoryVectorStore

# Suppress verbose offline tokenizer / embedding notices
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
logging.getLogger("sentence_transformers").setLevel(logging.WARNING)
logging.getLogger("transformers").setLevel(logging.WARNING)

CORPUS_MANIFEST_PATH = Path(__file__).resolve().parents[1] / "rag_corpus" / "manifest.json"
EMBEDDING_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
EMBEDDING_REVISION = "c9745ed1d9f207416be6d2e6f8de32d1f16199bf"

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


SNAPSHOT_MANIFEST_FILENAME = "vogtcon_snapshot_manifest.json"
DEFAULT_MODEL_DIR = Path(
    os.environ.get(
        "VOGTCON_RAG_MODEL_DIR",
        Path(__file__).resolve().parents[1] / "sentence-transformers" / "all-MiniLM-L6-v2",
    )
)
ALLOWED_SNAPSHOT_EXTENSIONS = {".json", ".txt", ".safetensors"}
FORBIDDEN_SNAPSHOT_EXTENSIONS = {".bin", ".pt", ".pth", ".pkl"}


def verify_prepared_embedding_snapshot(
    model_dir: Path,
    expected_model: str = EMBEDDING_MODEL_NAME,
    expected_revision: str = EMBEDDING_REVISION,
) -> dict[str, Any]:
    """Verify that model_dir contains a valid vogtcon_snapshot_manifest.json and verified files."""
    if not model_dir.is_dir():
        raise FileNotFoundError(f"Model directory does not exist: {model_dir}")

    manifest_path = model_dir / SNAPSHOT_MANIFEST_FILENAME
    if not manifest_path.is_file():
        raise ValueError(f"Snapshot manifest missing: {manifest_path}")

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"Invalid snapshot manifest JSON: {exc}") from exc

    if not isinstance(manifest, dict):
        raise ValueError("Snapshot manifest must be a JSON object")

    model_name = manifest.get("model_name")
    if model_name != expected_model:
        raise ValueError(
            f"Snapshot model_name mismatch: expected '{expected_model}', got '{model_name}'"
        )

    revision = manifest.get("revision")
    if revision != expected_revision:
        raise ValueError(
            f"Snapshot revision mismatch: expected '{expected_revision}', got '{revision}'"
        )

    files_manifest = manifest.get("files")
    if not isinstance(files_manifest, dict) or not files_manifest:
        raise ValueError("Snapshot manifest must contain a non-empty 'files' mapping")

    has_safetensors = False
    found_files: set[str] = set()

    for path in model_dir.rglob("*"):
        if not path.is_file():
            continue
        rel_path = path.relative_to(model_dir).as_posix()
        if rel_path == SNAPSHOT_MANIFEST_FILENAME or rel_path.startswith(".cache/"):
            continue
        if path.name == ".DS_Store":
            continue

        suffix = path.suffix.lower()
        if suffix in FORBIDDEN_SNAPSHOT_EXTENSIONS:
            raise ValueError(
                f"Forbidden weight format '{suffix}' detected: {rel_path}"
            )
        if suffix not in ALLOWED_SNAPSHOT_EXTENSIONS:
            raise ValueError(
                f"Disallowed file format '{suffix}' detected: {rel_path}"
            )
        if suffix == ".safetensors":
            has_safetensors = True

        if rel_path not in files_manifest:
            raise ValueError(
                f"Unlisted file found in model directory: {rel_path}"
            )

        found_files.add(rel_path)

        expected_entry = files_manifest[rel_path]
        expected_size = expected_entry.get("size")
        actual_size = path.stat().st_size
        if expected_size != actual_size:
            raise ValueError(
                f"File size mismatch for {rel_path}: expected {expected_size}, got {actual_size}"
            )

        expected_sha = expected_entry.get("sha256")
        actual_sha = hashlib.sha256(path.read_bytes()).hexdigest()
        if expected_sha != actual_sha:
            raise ValueError(
                f"SHA-256 mismatch for {rel_path}: expected {expected_sha}, got {actual_sha}"
            )

    if not has_safetensors:
        raise ValueError("Snapshot does not contain any .safetensors files")

    for rel_path in files_manifest:
        if rel_path not in found_files:
            raise ValueError(f"Snapshot file missing from disk: {rel_path}")

    return manifest


def default_local_embeddings(
    model_dir: Path | None = None,
) -> HuggingFaceEmbeddings:
    """Return offline HuggingFace embeddings backed by local verified snapshot."""
    check_rag_platform()

    if model_dir is not None:
        target_dir = Path(model_dir).resolve()
    elif os.environ.get("VOGTCON_RAG_MODEL_DIR"):
        target_dir = Path(os.environ["VOGTCON_RAG_MODEL_DIR"]).resolve()
    elif Path("sentence-transformers/all-MiniLM-L6-v2").is_dir():
        target_dir = Path("sentence-transformers/all-MiniLM-L6-v2").resolve()
    else:
        target_dir = DEFAULT_MODEL_DIR.resolve()

    verify_prepared_embedding_snapshot(
        target_dir,
        expected_model=EMBEDDING_MODEL_NAME,
        expected_revision=EMBEDDING_REVISION,
    )

    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"

    from langchain_huggingface import HuggingFaceEmbeddings

    return HuggingFaceEmbeddings(
        model_name=str(target_dir),
        model_kwargs={
            "device": "cpu",
            "local_files_only": True,
            "trust_remote_code": False,
            "revision": EMBEDDING_REVISION,
            "model_kwargs": {
                "use_safetensors": True,
                "local_files_only": True,
                "trust_remote_code": False,
            },
        },
    )


def build_vector_store(
    documents: Sequence[Document],
    embeddings: Embeddings | None = None,
    model_dir: Path | None = None,
) -> InMemoryVectorStore:
    """Index verified documents in an in-memory vector store."""
    emb = embeddings or default_local_embeddings(model_dir=model_dir)
    vector_store = InMemoryVectorStore(embedding=emb)
    vector_store.add_documents(documents=list(documents))
    return vector_store


@dataclass(slots=True)
class LocalBriefPublisher:
    """Direct file publisher without governance checks."""

    output_dir: Path
    run_id: str
    corpus_metadata: dict[str, dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.corpus_metadata and CORPUS_MANIFEST_PATH.exists():
            manifest_data = json.loads(CORPUS_MANIFEST_PATH.read_text(encoding="utf-8"))
            self.corpus_metadata = {
                doc["doc_id"]: doc for doc in manifest_data.get("documents", [])
            }

    def __call__(self, arguments: dict[str, Any]) -> tuple[Path, str]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        brief_path = self.output_dir / f"{self.run_id}-brief.md"
        title = str(arguments.get("title", "Technical Brief"))
        claims = list(arguments.get("claims", []))
        citation_ids = list(arguments.get("citation_ids", []))

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
class PreRagRunResult:
    """Outcome of one ungoverned LangChain RAG run."""

    run_id: str
    agent_output: str | None
    published: bool
    brief_path: Path | None
    brief_sha256: str | None
    citation_ids: list[str]
    final_record: dict[str, Any]


@dataclass(slots=True)
class _PreRagDeps:
    """Dependencies for one ungoverned RAG agent run."""

    run_id: str
    vector_store: InMemoryVectorStore
    publish_tool: Callable[[dict[str, Any]], tuple[Path, str]]
    emit_console: bool
    published: list[tuple[Path, str, list[str]]]


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
    """Deterministic chat model implementing the same 5 scenarios."""

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
                AIMessage(content="Brief publicado sin bloqueo.")
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
                AIMessage(content="Brief publicado sin verificación de aprobación.")
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
                AIMessage(content="Brief publicado en el primer intento sin corrección.")
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
    model: BaseChatModel,
    vector_store: InMemoryVectorStore,
    output_dir: Path | None = None,
    publish_tool: Callable[[dict[str, Any]], tuple[Path, str]] | None = None,
    emit_console: bool = False,
    user_query: str = "Genera un brief técnico a partir de las fuentes verificadas.",
) -> PreRagRunResult:
    """Execute a single ungoverned LangChain RAG run (Pre-vogtcon baseline)."""
    actual_output_dir = output_dir or Path("/tmp/vogtcon-rag-pre")
    actual_publish_tool = (
        publish_tool if publish_tool is not None else LocalBriefPublisher(actual_output_dir, run_id)
    )
    published_list: list[tuple[Path, str, list[str]]] = []

    deps = _PreRagDeps(
        run_id=run_id,
        vector_store=vector_store,
        publish_tool=actual_publish_tool,
        emit_console=emit_console,
        published=published_list,
    )

    @tool
    def retrieve_context(query: str) -> str:
        """Retrieve relevant reference documents from the verified corpus."""
        retrieved_docs = deps.vector_store.similarity_search(query, k=3)
        snippets = []
        for doc in retrieved_docs:
            cid = doc.metadata.get("doc_id", "unknown")
            title = doc.metadata.get("title", "Untitled")
            snippets.append(f"[{cid}] {title} (UNTRUSTED DATA):\n{doc.page_content}")
        return "\n\n".join(snippets) if snippets else "No documents found."

    @tool
    def publish_brief(title: str, claims: list[str], citation_ids: list[str]) -> str:
        """Publish a technical brief directly without governance checks."""
        arguments = {"title": title, "claims": claims, "citation_ids": citation_ids}
        published_path, published_sha256 = deps.publish_tool(arguments)
        deps.published.append((published_path, published_sha256, list(citation_ids)))
        record = {
            "event": "tool_executed_ungoverned",
            "run_id": deps.run_id,
            "published": True,
            "brief_path": str(published_path),
            "citation_ids": list(citation_ids),
        }
        if deps.emit_console:
            print(json.dumps(record, ensure_ascii=False))
        return f"published brief at {published_path}"

    agent = create_agent(model, [retrieve_context, publish_brief])
    agent_result = agent.invoke({"messages": [HumanMessage(content=user_query)]})
    messages = agent_result.get("messages", []) if isinstance(agent_result, dict) else []
    agent_output = (
        messages[-1].content if messages and hasattr(messages[-1], "content") else None
    )

    if deps.published:
        brief_path, brief_sha256, verified_citations = deps.published[-1]
        published = True
    else:
        brief_path = None
        brief_sha256 = None
        verified_citations = []
        published = False

    final_record = {
        "event": "pre_agent_result",
        "run_id": run_id,
        "published": published,
        "brief_path": str(brief_path) if brief_path else None,
        "brief_sha256": brief_sha256,
        "citation_ids": verified_citations,
        "agent_output": agent_output,
    }
    if emit_console:
        print(json.dumps(final_record, ensure_ascii=False))

    return PreRagRunResult(
        run_id=run_id,
        agent_output=agent_output,
        published=published,
        brief_path=brief_path,
        brief_sha256=brief_sha256,
        citation_ids=verified_citations,
        final_record=final_record,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run the baseline LangChain RAG agent WITHOUT vogtcon offline"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/tmp/vogtcon-rag-pre"),
        help="Directory to write generated brief markdown files",
    )
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    _, corpus_docs = load_frozen_corpus(CORPUS_MANIFEST_PATH)
    vector_store = build_vector_store(corpus_docs)

    for run_id, scenario in (
        ("rag-case-a-approved", "case_a_approved_publish"),
        ("rag-case-b-invalid-citation", "case_b_invalid_citation"),
        ("rag-case-c-unapproved", "case_c_unapproved"),
        ("rag-case-d-replan", "case_d_replan_after_block"),
        ("rag-case-e-insufficient-evidence", "case_e_insufficient_evidence"),
    ):
        run_rag_brief(
            run_id=run_id,
            model=ScriptedRagChatModel(scenario=scenario),
            vector_store=vector_store,
            output_dir=args.output_dir,
            emit_console=True,
        )
