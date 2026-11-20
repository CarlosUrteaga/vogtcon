# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Create and check per-distribution hashes passed through workflow job outputs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


def validate_names(names: list[str]) -> None:
    if len(names) != 2 or any(
        Path(name).name != name or "\\" in name or name in ("", ".", "..")
        for name in names
    ):
        raise ValueError("Expected exactly two distribution basenames")
    if sum(name.endswith(".whl") for name in names) != 1 or sum(
        name.endswith(".tar.gz") for name in names
    ) != 1:
        raise ValueError("Expected one wheel and one source distribution")


def manifest(directory: Path) -> dict[str, str]:
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError("Distribution directory is missing or is a symlink")
    # uv creates this bookkeeping file; upload-artifact excludes it as hidden.
    files = sorted(path for path in directory.iterdir() if path.name != ".gitignore")
    validate_names([path.name for path in files])
    result = {}
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Distribution must be a regular file: {path.name}")
        with path.open("rb") as stream:
            result[path.name] = hashlib.file_digest(stream, "sha256").hexdigest()
    return result


def unique_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate manifest key: {key}")
        result[key] = value
    return result


def check(directory: Path, expected_json: str) -> dict[str, str]:
    expected = json.loads(expected_json, object_pairs_hook=unique_keys)
    if not isinstance(expected, dict):
        raise ValueError("Expected a JSON object mapping filenames to SHA-256 hashes")
    validate_names(list(expected))
    if any(
        not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        for digest in expected.values()
    ):
        raise ValueError("Expected lowercase SHA-256 hashes")
    actual = manifest(directory)
    if actual.keys() != expected.keys():
        raise ValueError("Downloaded distribution filenames do not match the build outputs")
    mismatches = [name for name in actual if actual[name] != expected[name]]
    if mismatches:
        raise ValueError(f"SHA-256 mismatch: {', '.join(mismatches)}")
    return actual


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("manifest", "check"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--expected-json")
    args = parser.parse_args()
    if args.command == "check" and args.expected_json is None:
        parser.error("check requires --expected-json from the build job outputs")
    try:
        result = (
            manifest(args.directory)
            if args.command == "manifest"
            else check(args.directory, args.expected_json)
        )
    except (ValueError, OSError) as error:
        print(f"Distribution verification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
