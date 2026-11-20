# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Validate a release tag against the checked-out project and main history."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tomllib


def git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True, text=True,
    )
    if result.returncode:
        raise ValueError(f"Git validation failed: {result.stderr.strip()}")
    return result.stdout.strip()


def validate_release(repository: Path, event_name: str, ref: str,
                     main_ref: str = "refs/remotes/origin/main") -> dict:
    if event_name != "push" or not ref.startswith("refs/tags/v"):
        return {"validated": False, "event": event_name, "ref": ref}

    metadata = tomllib.loads((repository / "pyproject.toml").read_text())
    project = metadata.get("project")
    version = project.get("version") if isinstance(project, dict) else None
    if not isinstance(version, str) or not version or version != version.strip():
        raise ValueError("Release validation requires a static project.version")
    expected_ref = f"refs/tags/v{version}"
    if ref != expected_ref:
        raise ValueError(f"Expected {expected_ref} from project.version; received {ref}")

    commit = git(repository, "rev-parse", "--verify", f"{ref}^{{commit}}")
    checked_out = git(repository, "rev-parse", "--verify", "HEAD^{commit}")
    if commit != checked_out:
        raise ValueError("The checked-out commit does not match the release tag")
    main_commit = git(repository, "rev-parse", "--verify", f"{main_ref}^{{commit}}")
    ancestry = subprocess.run(
        ["git", "-C", str(repository), "merge-base", "--is-ancestor", commit, main_commit],
        capture_output=True, text=True,
    )
    if ancestry.returncode:
        raise ValueError("The release commit is not reachable from main")
    return {
        "validated": True, "version": version, "tag": ref.removeprefix("refs/tags/"),
        "commit": commit, "main_commit": main_commit,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--main-ref", default="refs/remotes/origin/main")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    try:
        result = validate_release(args.repository, args.event_name, args.ref, args.main_ref)
        if args.github_output:
            with args.github_output.open("a") as stream:
                stream.write(f"validated={str(result['validated']).lower()}\n")
    except (ValueError, OSError) as error:
        print(f"Release validation failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
