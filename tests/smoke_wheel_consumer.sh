#!/bin/sh
# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python_bin="$repository/.venv/bin/python"
if [ ! -x "$python_bin" ]; then
    python_bin="${PYTHON:-python3}"
fi

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

(cd "$repository" && uv build --offline --out-dir "$scratch/dist")
uv venv --python "$python_bin" "$scratch/venv"
uv pip install --python "$scratch/venv/bin/python" "$scratch/dist/"*.whl

mkdir "$scratch/consumer"
cp "$repository/tests/wheel_consumer.py" "$scratch/consumer/wheel_consumer.py"
cp "$repository/examples/notification_contract.yaml" "$scratch/consumer/notification_contract.yaml"
cp "$repository/examples/notification_contract_v2.yaml" "$scratch/consumer/notification_contract_v2.yaml"

venv_python="$scratch/venv/bin/python"
cli="$scratch/venv/bin/vogtcon"

(
    cd "$scratch/consumer"
    env -u PYTHONPATH "$venv_python" -I \
        wheel_consumer.py notification_contract.yaml notification_contract_v2.yaml

    env -u PYTHONPATH "$cli" --help > "$scratch/help.txt"
    env -u PYTHONPATH "$cli" --version > "$scratch/version.txt"

    env -u PYTHONPATH "$cli" validate notification_contract.yaml > "$scratch/validate_v1.txt"
    env -u PYTHONPATH "$cli" validate notification_contract.yaml --json > "$scratch/validate_v1.json"

    env -u PYTHONPATH "$cli" validate notification_contract_v2.yaml > "$scratch/validate_v2.txt"
    env -u PYTHONPATH "$cli" validate notification_contract_v2.yaml --json > "$scratch/validate_v2.json"

    env -u PYTHONPATH "$cli" explain recovery-events.jsonl --run-id wheel-recovery > "$scratch/explain_recovery.txt"
    env -u PYTHONPATH "$cli" explain recovery-events.jsonl --run-id wheel-recovery --json > "$scratch/explain_recovery.json"

    env -u PYTHONPATH "$cli" explain notification_contract_v2-events.jsonl --json > "$scratch/explain_v2.json"

    rc=0
    env -u PYTHONPATH "$cli" explain recovery-events.jsonl --run-id missing --json > "$scratch/explain_missing.json" || rc=$?
    [ "$rc" -eq 2 ]

    env -u PYTHONPATH "$venv_python" -I - \
        "$scratch/help.txt" \
        "$scratch/version.txt" \
        "$scratch/validate_v1.txt" \
        "$scratch/validate_v1.json" \
        "$scratch/validate_v2.txt" \
        "$scratch/validate_v2.json" \
        "$scratch/explain_recovery.txt" \
        "$scratch/explain_recovery.json" \
        "$scratch/explain_v2.json" \
        "$scratch/explain_missing.json" <<'PY'
import json
import sys
from pathlib import Path

(
    help_path,
    version_path,
    validate_v1_txt,
    validate_v1_json,
    validate_v2_txt,
    validate_v2_json,
    explain_recovery_txt,
    explain_recovery_json,
    explain_v2_json,
    explain_missing_json,
) = [Path(arg) for arg in sys.argv[1:]]

assert "vogtcon" in help_path.read_text(encoding="utf-8")
assert version_path.read_text(encoding="utf-8").strip().startswith("vogtcon ")

v1_text = validate_v1_txt.read_text(encoding="utf-8")
assert "Contract is valid" in v1_text
assert "not verified" in v1_text

v1 = json.loads(validate_v1_json.read_text(encoding="utf-8"))
assert v1["status"] == "valid"
assert v1["data"]["contract_version"] == 1
assert v1["data"]["fingerprint"]["verified"] is False

v2_text = validate_v2_txt.read_text(encoding="utf-8")
assert "Contract is valid" in v2_text
assert "(verified)" in v2_text

v2 = json.loads(validate_v2_json.read_text(encoding="utf-8"))
assert v2["status"] == "valid"
assert v2["data"]["contract_version"] == 2
assert v2["data"]["fingerprint"]["verified"] is True

rec_text = explain_recovery_txt.read_text(encoding="utf-8")
assert "wheel-recovery" in rec_text
assert "prior same-tool block at action 1" in rec_text

rec = json.loads(explain_recovery_json.read_text(encoding="utf-8"))
assert rec["status"] == "ok"
assert len(rec["data"]["runs"]) == 1
run = rec["data"]["runs"][0]
assert run["run_id"] == "wheel-recovery"
assert run["trace_integrity"] == "complete"
assert run["terminal"] == "post_execution"
assert run["counts"] == {
    "prevented": 1,
    "completed": 1,
    "error": 0,
    "unfinalized": 0,
    "unknown": 0,
}
assert run["actions"][1]["prior_same_tool_block_action_index"] == 1
assert run["actions"][1]["effect_evidence"] == "not_verified"

v2_explain = json.loads(explain_v2_json.read_text(encoding="utf-8"))
assert v2_explain["status"] == "ok"
runs = v2_explain["data"]["runs"]
assert len(runs) == 2
assert all(item["trace_integrity"] == "complete" for item in runs)

missing = json.loads(explain_missing_json.read_text(encoding="utf-8"))
assert missing["status"] == "run_not_found"

print("Installed wheel CLI: validate and explain checks passed")
PY
)
