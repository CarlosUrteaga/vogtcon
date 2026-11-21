#!/usr/bin/env bash
# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# scripts/compile_rag_requirements.sh
# Regenerates or verifies examples/requirements-langchain-rag.txt and examples/requirements-rag-build.txt
# pinned to uv 0.8.23 for Linux x86_64, Python 3.12, and PyTorch CPU.

EXPECTED_UV_VERSION="0.8.23"

if ! command -v uv >/dev/null 2>&1; then
    echo "Error: uv is required but not installed in PATH." >&2
    exit 1
fi

INSTALLED_UV_VERSION=$(uv --version | awk '{print $2}')
if [ "$INSTALLED_UV_VERSION" != "$EXPECTED_UV_VERSION" ]; then
    echo "Warning: uv $EXPECTED_UV_VERSION is recommended, detected $INSTALLED_UV_VERSION" >&2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

RAG_IN="examples/requirements-langchain-rag.in"
RAG_TXT="examples/requirements-langchain-rag.txt"
BUILD_IN="examples/requirements-rag-build.in"
BUILD_TXT="examples/requirements-rag-build.txt"

CHECK_MODE=0
for arg in "$@"; do
    if [ "$arg" = "--check" ]; then
        CHECK_MODE=1
    fi
done

if [ "$CHECK_MODE" -eq 1 ]; then
    if [ ! -f "$RAG_TXT" ] || [ ! -f "$BUILD_TXT" ]; then
        echo "Error: Committed lockfiles $RAG_TXT and $BUILD_TXT must exist for --check mode." >&2
        exit 1
    fi

    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT

    TMP_RAG_TXT="$TMP_DIR/requirements-langchain-rag.txt"
    TMP_BUILD_TXT="$TMP_DIR/requirements-rag-build.txt"
    NORM_RAG_TXT="$TMP_DIR/normalized-rag.txt"
    NORM_BUILD_TXT="$TMP_DIR/normalized-build.txt"

    # Seed temporary output files from committed lockfiles before uv pip compile runs
    cp "$RAG_TXT" "$TMP_RAG_TXT"
    cp "$BUILD_TXT" "$TMP_BUILD_TXT"

    uv pip compile "$RAG_IN" \
        --python-version 3.12 \
        --python-platform x86_64-unknown-linux-gnu \
        --torch-backend cpu \
        --only-binary :all: \
        --generate-hashes \
        --emit-index-url \
        -o "$TMP_RAG_TXT"

    uv pip compile "$BUILD_IN" \
        --python-version 3.12 \
        --python-platform x86_64-unknown-linux-gnu \
        --only-binary :all: \
        --generate-hashes \
        -o "$TMP_BUILD_TXT"

    # Normalize temporary output path in header comment before diffing
    sed -E "s|-o .*|-o $RAG_TXT|" "$TMP_RAG_TXT" > "$NORM_RAG_TXT"
    sed -E "s|-o .*|-o $BUILD_TXT|" "$TMP_BUILD_TXT" > "$NORM_BUILD_TXT"

    DIFF_FAILED=0
    if ! diff -u "$RAG_TXT" "$NORM_RAG_TXT"; then
        echo "Error: $RAG_TXT is out of sync with $RAG_IN" >&2
        DIFF_FAILED=1
    fi
    if ! diff -u "$BUILD_TXT" "$NORM_BUILD_TXT"; then
        echo "Error: $BUILD_TXT is out of sync with $BUILD_IN" >&2
        DIFF_FAILED=1
    fi

    if [ "$DIFF_FAILED" -ne 0 ]; then
        echo "Run 'bash scripts/compile_rag_requirements.sh' to recompile lockfiles." >&2
        exit 1
    fi

    echo "Lockfile check passed: both $RAG_TXT and $BUILD_TXT match sources."
else
    uv pip compile "$RAG_IN" \
        --python-version 3.12 \
        --python-platform x86_64-unknown-linux-gnu \
        --torch-backend cpu \
        --only-binary :all: \
        --generate-hashes \
        --emit-index-url \
        -o "$RAG_TXT"

    uv pip compile "$BUILD_IN" \
        --python-version 3.12 \
        --python-platform x86_64-unknown-linux-gnu \
        --only-binary :all: \
        --generate-hashes \
        -o "$BUILD_TXT"

    echo "Compiled $RAG_TXT and $BUILD_TXT successfully."
fi
