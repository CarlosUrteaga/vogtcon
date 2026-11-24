#!/bin/sh
# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

echo "=== Building wheel ==="
(cd "$repository" && uv build --offline --out-dir "$scratch/dist")

echo "=== Creating isolated venv ==="
PYTHON_BIN="${PYTHON:-$repository/.venv/bin/python}"
if [ ! -f "$PYTHON_BIN" ]; then
    PYTHON_BIN="python3"
fi
uv venv --python "$PYTHON_BIN" "$scratch/venv"

echo "=== Installing vogtcon wheel ==="
uv pip install --python "$scratch/venv/bin/python" "$scratch/dist/"*.whl

VOGTCON="$scratch/venv/bin/vogtcon"
PYTHON="$scratch/venv/bin/python"

echo "=== Verifying isolated environment ==="
"$PYTHON" -c '
import importlib.util, sys
assert importlib.util.find_spec("pydantic_ai") is None, "pydantic_ai should not be present"
assert importlib.util.find_spec("pytest") is None, "pytest should not be present"
print("Environment clean: no benchmark, no LLM, no test framework.")
'

echo "=== Testing --version ==="
"$VOGTCON" --version

echo "=== Testing validate ==="
mkdir -p "$scratch/consumer"
cp "$repository/examples/notification_contract.yaml" "$scratch/consumer/"
cp "$repository/examples/notification_contract_v2.yaml" "$scratch/consumer/"

(cd "$scratch/consumer" && "$VOGTCON" validate notification_contract.yaml)
(cd "$scratch/consumer" && "$VOGTCON" validate notification_contract_v2.yaml --json | "$PYTHON" -m json.tool > /dev/null)

echo "=== Testing explain ==="
cat << 'EOF' > "$scratch/consumer/decisions.jsonl"
{"schema_version":1,"run_id":"smoke-run-1","sequence":1,"contract_id":"example.notification","mode":"guarded","phase":"pre_execution","event_type":"decision","action_index":null,"tool_name":null,"decision":null,"violation_rules":[],"execution_status":"not_started","trace_id":null,"span_id":null}
{"schema_version":1,"run_id":"smoke-run-1","sequence":2,"contract_id":"example.notification","mode":"guarded","phase":"runtime","event_type":"decision","action_index":1,"tool_name":"send_notification","decision":"block","violation_rules":["sensitive_requires_approval"],"execution_status":"not_started","trace_id":null,"span_id":null}
{"schema_version":1,"run_id":"smoke-run-1","sequence":3,"contract_id":"example.notification","mode":"guarded","phase":"runtime","event_type":"decision","action_index":2,"tool_name":"send_notification","decision":"allow","violation_rules":[],"execution_status":"not_started","trace_id":null,"span_id":null}
{"schema_version":1,"run_id":"smoke-run-1","sequence":4,"contract_id":"example.notification","mode":"guarded","phase":"runtime","event_type":"tool_completed","action_index":2,"tool_name":"send_notification","decision":null,"violation_rules":[],"execution_status":"completed","trace_id":null,"span_id":null}
{"schema_version":1,"run_id":"smoke-run-1","sequence":5,"contract_id":"example.notification","mode":"guarded","phase":"post_execution","event_type":"decision","action_index":null,"tool_name":null,"decision":null,"violation_rules":[],"execution_status":"not_started","trace_id":null,"span_id":null}
EOF

(cd "$scratch/consumer" && "$VOGTCON" explain decisions.jsonl)
(cd "$scratch/consumer" && "$VOGTCON" explain decisions.jsonl --json | "$PYTHON" -m json.tool > /dev/null)

echo "=== All CLI smoke tests passed successfully ==="
