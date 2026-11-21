#!/usr/bin/env python3
# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0
"""Prepare and verify the offline embedding model snapshot for RAG."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
from typing import Any

SNAPSHOT_MANIFEST_FILENAME = "vogtcon_snapshot_manifest.json"
ALLOWED_EXTENSIONS = {".json", ".txt", ".safetensors"}
FORBIDDEN_EXTENSIONS = {".bin", ".pt", ".pth", ".pkl"}


def create_snapshot_manifest(
    model_dir: Path,
    model_name: str,
    revision: str,
) -> dict[str, Any]:
    """Inspect model_dir, enforce allowed extensions and safetensors, and write vogtcon_snapshot_manifest.json."""
    if not model_dir.is_dir():
        raise FileNotFoundError(f"Model directory does not exist: {model_dir}")

    cache_dir = model_dir / ".cache"
    if cache_dir.exists():
        shutil.rmtree(cache_dir, ignore_errors=True)

    files_dict: dict[str, dict[str, Any]] = {}
    has_safetensors = False

    for path in sorted(model_dir.rglob("*")):
        if not path.is_file():
            continue
        rel_path = path.relative_to(model_dir).as_posix()
        if rel_path == SNAPSHOT_MANIFEST_FILENAME or rel_path.startswith(".cache/"):
            continue
        if path.name == ".DS_Store":
            continue

        suffix = path.suffix.lower()
        if suffix in FORBIDDEN_EXTENSIONS:
            raise ValueError(
                f"Forbidden weight format '{suffix}' found in model directory: {rel_path}"
            )
        if suffix not in ALLOWED_EXTENSIONS:
            raise ValueError(
                f"Disallowed file format '{suffix}' found in model directory: {rel_path}"
            )
        if suffix == ".safetensors":
            has_safetensors = True

        data = path.read_bytes()
        files_dict[rel_path] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }

    if not has_safetensors:
        raise ValueError("Model snapshot must contain at least one .safetensors file")

    manifest = {
        "manifest_version": 1,
        "model_name": model_name,
        "revision": revision,
        "files": files_dict,
    }

    manifest_path = model_dir / SNAPSHOT_MANIFEST_FILENAME
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def verify_prepared_embedding_snapshot(
    model_dir: Path,
    expected_model: str,
    expected_revision: str,
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
        if suffix in FORBIDDEN_EXTENSIONS:
            raise ValueError(
                f"Forbidden weight format '{suffix}' detected: {rel_path}"
            )
        if suffix not in ALLOWED_EXTENSIONS:
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare and verify offline RAG embedding model")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("sentence-transformers/all-MiniLM-L6-v2"),
        help="Target directory for embedding model snapshot",
    )
    parser.add_argument(
        "--corpus-manifest",
        type=Path,
        default=Path("examples/rag_corpus/manifest.json"),
        help="Path to corpus manifest.json to inspect model identity and revision",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only verify existing snapshot against manifest without downloading",
    )
    args = parser.parse_args()

    corpus_manifest_file = args.corpus_manifest.resolve()
    if not corpus_manifest_file.is_file():
        raise FileNotFoundError(f"Corpus manifest not found: {corpus_manifest_file}")

    corpus_manifest = json.loads(corpus_manifest_file.read_text(encoding="utf-8"))
    expected_model = corpus_manifest["embedding_model"]
    expected_revision = corpus_manifest["embedding_revision"]

    output_dir = args.output_dir.resolve()

    if not args.verify_only:
        print(f"Preparing model {expected_model} (rev {expected_revision}) in {output_dir}...")
        output_dir.mkdir(parents=True, exist_ok=True)
        from huggingface_hub import snapshot_download

        snapshot_download(
            repo_id=expected_model,
            revision=expected_revision,
            local_dir=str(output_dir),
            allow_patterns=["*.json", "*.txt", "*.safetensors"],
            ignore_patterns=[".cache/*", "*.bin", "*.pt", "*.pth", "*.pkl"],
        )

        create_snapshot_manifest(output_dir, expected_model, expected_revision)
        print(f"Snapshot manifest generated at {output_dir / SNAPSHOT_MANIFEST_FILENAME}")

    verify_prepared_embedding_snapshot(output_dir, expected_model, expected_revision)
    print(f"Snapshot verification passed for {output_dir}")


if __name__ == "__main__":
    main()
