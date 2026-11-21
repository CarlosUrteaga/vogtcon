#!/usr/bin/env bash
# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# scripts/run_rag.sh
# Launcher for Vogtcon LangChain RAG agent and test suite.
# Enforces Linux x86_64 reference environment and provides container delegation for macOS Intel.

OS="$(uname -s)"
ARCH="$(uname -m)"

USE_CONTAINER=0
ACTION=""
OUTPUT_DIR="/tmp/vogtcon-rag-output"
CONTAINER_IMAGE="${VOGTCON_RAG_IMAGE:-vogtcon-rag:latest}"

show_help() {
    cat <<EOF
Usage: $0 [OPTIONS] [COMMAND]

Commands:
  test        Run RAG integration test suite
  governed    Run governed LangChain RAG agent
  pre         Run baseline (pre-governance) LangChain RAG agent

Options:
  --container         Execute within linux/amd64 container
  --output-dir <DIR>  Directory for output briefs (default: /tmp/vogtcon-rag-output)
  -h, --help          Show this help message
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --container)
            USE_CONTAINER=1
            shift
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        test|governed|pre)
            ACTION="$1"
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            show_help
            exit 1
            ;;
    esac
done

if [ -z "$ACTION" ]; then
    echo "Error: No command specified (choose 'test', 'governed', or 'pre')." >&2
    show_help
    exit 1
fi

print_macos_intel_diagnostics() {
    cat >&2 <<EOF
ERROR: Native RAG execution is not supported on macOS Intel (Darwin x86_64).
Official PyTorch CPU binaries for macOS x86_64 were deprecated after version 2.2.2,
and newer versions (>=2.13.0) required to address security advisories are only
available for Linux x86_64 and macOS ARM64.

To run the RAG agent on macOS Intel, use the Linux reference environment:
  1. Using Docker/Podman container (linux/amd64):
     bash scripts/run_rag.sh --container governed
     bash scripts/run_rag.sh --container pre
     bash scripts/run_rag.sh --container test
  2. Or run directly on a remote Linux x86_64 machine with Python 3.12.
EOF
}

# If on Darwin x86_64 and not using container, refuse native run with exit code 2
if [ "$OS" = "Darwin" ] && [ "$ARCH" = "x86_64" ] && [ "$USE_CONTAINER" -eq 0 ]; then
    print_macos_intel_diagnostics
    exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$OUTPUT_DIR"

if [ "$USE_CONTAINER" -eq 1 ]; then
    RUNTIME=""
    if command -v docker >/dev/null 2>&1; then
        RUNTIME="docker"
    elif command -v podman >/dev/null 2>&1; then
        RUNTIME="podman"
    else
        echo "ERROR: Neither docker nor podman was found in PATH." >&2
        echo "Please install Docker Desktop or Podman on macOS Intel to use --container," >&2
        echo "or run on a remote Linux x86_64 host." >&2
        exit 2
    fi

    if ! "$RUNTIME" image inspect "$CONTAINER_IMAGE" >/dev/null 2>&1; then
        echo "Image '$CONTAINER_IMAGE' not found locally. Building from examples/Dockerfile.rag..." >&2
        "$RUNTIME" build --platform linux/amd64 -f "$REPO_ROOT/examples/Dockerfile.rag" -t "$CONTAINER_IMAGE" "$REPO_ROOT"
    fi

    case "$ACTION" in
        test)
            exec "$RUNTIME" run --rm --platform linux/amd64 --network none \
                -e HF_HUB_OFFLINE=1 -e TRANSFORMERS_OFFLINE=1 \
                "$CONTAINER_IMAGE" \
                python -m unittest discover -s tests -p 'test_langchain_rag_agent.py' -q
            ;;
        governed)
            exec "$RUNTIME" run --rm --platform linux/amd64 --network none \
                -v "$OUTPUT_DIR:/out" \
                -e HF_HUB_OFFLINE=1 -e TRANSFORMERS_OFFLINE=1 \
                "$CONTAINER_IMAGE" \
                python examples/langchain_rag_agent.py --output-dir /out
            ;;
        pre)
            exec "$RUNTIME" run --rm --platform linux/amd64 --network none \
                -v "$OUTPUT_DIR:/out" \
                -e HF_HUB_OFFLINE=1 -e TRANSFORMERS_OFFLINE=1 \
                "$CONTAINER_IMAGE" \
                python examples/pre/langchain_rag_agent.py --output-dir /out
            ;;
    esac
else
    cd "$REPO_ROOT"
    PYTHON="${PYTHON:-python3}"
    export HF_HUB_OFFLINE="1"
    export TRANSFORMERS_OFFLINE="1"

    case "$ACTION" in
        test)
            exec "$PYTHON" -m unittest discover -s tests -p 'test_langchain_rag_agent.py' -q
            ;;
        governed)
            exec "$PYTHON" examples/langchain_rag_agent.py --output-dir "$OUTPUT_DIR"
            ;;
        pre)
            exec "$PYTHON" examples/pre/langchain_rag_agent.py --output-dir "$OUTPUT_DIR"
            ;;
    esac
fi
