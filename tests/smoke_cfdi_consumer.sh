#!/bin/sh
# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

(cd "$repository" && uv build --offline --out-dir "$scratch/dist")
uv venv --python "$repository/.venv/bin/python" "$scratch/venv"
uv pip install --offline --python "$scratch/venv/bin/python" \
    "$scratch/dist/"*.whl -r "$repository/examples/requirements-cfdi.txt"
mkdir "$scratch/consumer"
cp "$repository/examples/cfdi_agent.py" "$repository/examples/cfdi_contract.yaml" "$scratch/consumer/"
cp -R "$repository/examples/cfdi_fixtures" "$scratch/consumer/cfdi_fixtures"
(cd "$scratch/consumer" && env -u PYTHONPATH -u GOVERNOR_BENCHMARK_ROOT \
    PYDANTIC_AI_NO_BANNER=1 "$scratch/venv/bin/python" -I - <<'PY'
import contextlib
import io
import json
from pathlib import Path
import runpy
import socket
import sys
from unittest.mock import patch

import vogtcon
from pydantic_ai import models

assert Path(vogtcon.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
models.ALLOW_MODEL_REQUESTS = False
sys.argv = ["cfdi_agent.py", "--output-dir", "results"]
stdout = io.StringIO()
with patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden")), contextlib.redirect_stdout(stdout):
    runpy.run_path("cfdi_agent.py", run_name="__main__")
events = [json.loads(line) for line in stdout.getvalue().splitlines()]
results = {e["case"]: e for e in events if e.get("event") == "host_verified_result"}
assert results["A"]["ledger_rows"] == 1
assert all(results[c]["ledger_rows"] == 0 for c in "BCDE")
assert all(results[c]["trace_id"] for c in "ABCDE")
assert len([e for e in events if e.get("event") == "input_rejected"]) == 2
assert not any(n.startswith("tools.enforcement") for n in sys.modules)
print("Installed wheel CFDI consumer: A allowed, B-E blocked, F rejected; network disabled; OK")
PY
)
