#!/bin/sh
# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

# 1. Crear entorno virtual aislado e instalar vogtcon==0.1.0 desde PyPI
"$repository/.venv/bin/python" -m venv "$scratch/venv"
"$scratch/venv/bin/pip" install --quiet "vogtcon==0.1.0"

# 2. Prueba de consumo base con wheel_consumer.py (contratos v1 y v2)
mkdir "$scratch/base_consumer"
cp "$repository/tests/wheel_consumer.py" "$scratch/base_consumer/"
cp "$repository/examples/notification_contract.yaml" "$repository/examples/notification_contract_v2.yaml" "$scratch/base_consumer/"
(cd "$scratch/base_consumer" && env -u PYTHONPATH "$scratch/venv/bin/python" -I \
    wheel_consumer.py notification_contract.yaml notification_contract_v2.yaml)

# 3. Instalar dependencias del consumidor CFDI y ejecutar prueba aislada offline
"$scratch/venv/bin/pip" install --quiet -r "$repository/examples/requirements-cfdi.txt"
mkdir "$scratch/cfdi_consumer"
cp "$repository/examples/cfdi_agent.py" "$repository/examples/cfdi_contract.yaml" "$scratch/cfdi_consumer/"
cp -R "$repository/examples/cfdi_fixtures" "$scratch/cfdi_consumer/cfdi_fixtures"
(cd "$scratch/cfdi_consumer" && env -u PYTHONPATH -u GOVERNOR_BENCHMARK_ROOT \
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

installed_file = Path(vogtcon.__file__).resolve()
assert Path(sys.prefix).resolve() in installed_file.parents, f"Expected {installed_file} in {sys.prefix}"
assert hasattr(vogtcon, "WorkflowController")
assert hasattr(vogtcon, "EnforcementPolicy")

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
print("Installed PyPI vogtcon==0.1.0 CFDI consumer: A allowed, B-E blocked, F rejected; network disabled; OK")
PY
)
