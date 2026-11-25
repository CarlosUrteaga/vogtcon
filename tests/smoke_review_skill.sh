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
"$python_bin" - "$scratch/dist" <<'PY'
import sys
import zipfile
from pathlib import Path

wheels = list(Path(sys.argv[1]).glob("*.whl"))
assert len(wheels) == 1, f"Expected 1 wheel, found {wheels}"
with zipfile.ZipFile(wheels[0]) as zf:
    agents_entries = [name for name in zf.namelist() if ".agents/" in name or name.startswith(".agents")]
    assert not agents_entries, f"Wheel must not bundle .agents/: {agents_entries}"
PY

uv venv --python "$python_bin" "$scratch/venv"
uv pip install --python "$scratch/venv/bin/python" "$scratch/dist/"*.whl

venv_python="$scratch/venv/bin/python"
cli="$scratch/venv/bin/vogtcon"

env -u PYTHONPATH "$venv_python" -I - "$scratch/venv" <<'PY'
import importlib.util
import sys
from pathlib import Path
import vogtcon

venv_root = Path(sys.argv[1]).resolve()
installed = Path(vogtcon.__file__).resolve()
assert venv_root in installed.parents, f"vogtcon imported from unexpected path: {installed}"
assert importlib.util.find_spec("pydantic_ai") is None, "pydantic_ai must not be installed"
PY

mkdir -p "$scratch/consumer/.agents/skills"
cp -R "$repository/.agents/skills/vogtcon-review" "$scratch/consumer/.agents/skills/vogtcon-review"
cp "$repository/examples/notification_contract.yaml" "$scratch/consumer/notification_contract.yaml"
cp "$repository/examples/notification_contract_v2.yaml" "$scratch/consumer/notification_contract_v2.yaml"
cp "$repository/examples/cfdi_contract.yaml" "$scratch/consumer/cfdi_contract.yaml"

(
    cd "$scratch/consumer"

    env -u PYTHONPATH "$venv_python" -I - "$scratch/before.json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

targets = sorted(
    [str(p) for p in Path(".").glob("*.yaml")]
    + [str(p) for p in Path(".agents/skills/vogtcon-review/examples").glob("*.jsonl")]
)
assert targets, "No contract or trace inputs found in consumer directory"
digests = {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in targets}
Path(sys.argv[1]).write_text(json.dumps(digests, indent=2), encoding="utf-8")
PY

    rc=0
    env -u PYTHONPATH "$cli" --version > "$scratch/version.txt" 2> "$scratch/version.err" || rc=$?
    [ "$rc" -eq 0 ]

    rc=0
    env -u PYTHONPATH "$cli" validate notification_contract.yaml --json > "$scratch/validate_v1.json" 2> "$scratch/validate_v1.err" || rc=$?
    [ "$rc" -eq 0 ]

    rc=0
    env -u PYTHONPATH "$cli" validate notification_contract_v2.yaml --json > "$scratch/validate_v2.json" 2> "$scratch/validate_v2.err" || rc=$?
    [ "$rc" -eq 0 ]

    rc=0
    env -u PYTHONPATH "$cli" explain .agents/skills/vogtcon-review/examples/notification_recovery.jsonl --run-id wheel-recovery --json > "$scratch/explain_recovery.json" 2> "$scratch/explain_recovery.err" || rc=$?
    [ "$rc" -eq 0 ]

    rc=0
    env -u PYTHONPATH "$cli" explain .agents/skills/vogtcon-review/examples/notification_tool_error.jsonl --json > "$scratch/explain_tool_error.json" 2> "$scratch/explain_tool_error.err" || rc=$?
    [ "$rc" -eq 0 ]

    rc=0
    env -u PYTHONPATH "$cli" explain .agents/skills/vogtcon-review/examples/notification_partial.jsonl --json > "$scratch/explain_partial.json" 2> "$scratch/explain_partial.err" || rc=$?
    [ "$rc" -eq 0 ]

    rc=0
    env -u PYTHONPATH "$cli" explain .agents/skills/vogtcon-review/examples/notification_inconsistent.jsonl --json > "$scratch/explain_inconsistent.json" 2> "$scratch/explain_inconsistent.err" || rc=$?
    [ "$rc" -eq 1 ]

    rc=0
    env -u PYTHONPATH "$cli" explain .agents/skills/vogtcon-review/examples/notification_recovery.jsonl --run-id missing --json > "$scratch/explain_missing.json" 2> "$scratch/explain_missing.err" || rc=$?
    [ "$rc" -eq 2 ]

    rc=0
    env -u PYTHONPATH "$cli" validate cfdi_contract.yaml --json > "$scratch/validate_cfdi.json" 2> "$scratch/validate_cfdi.err" || rc=$?
    [ "$rc" -eq 2 ]

    rc=0
    env -u PYTHONPATH "$cli" explain .agents/skills/vogtcon-review/examples/cfdi_reconciliation.jsonl --json > "$scratch/explain_cfdi.json" 2> "$scratch/explain_cfdi.err" || rc=$?
    [ "$rc" -eq 0 ]

    env -u PYTHONPATH "$venv_python" -I - "$scratch" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

scratch = Path(sys.argv[1])

for err_file in scratch.glob("*.err"):
    assert err_file.read_text(encoding="utf-8") == "", f"Unexpected stderr in {err_file.name}: {err_file.read_text()}"

assert (scratch / "version.txt").read_text(encoding="utf-8").strip() == "vogtcon 0.4.0"

def load(name: str) -> dict:
    payload = json.loads((scratch / name).read_text(encoding="utf-8"))
    assert payload["output_version"] == 1
    return payload

v1 = load("validate_v1.json")
assert v1["status"] == "valid"
assert v1["data"]["contract_version"] == 1
assert v1["data"]["fingerprint"]["verified"] is False

v2 = load("validate_v2.json")
assert v2["status"] == "valid"
assert v2["data"]["contract_version"] == 2
assert v2["data"]["fingerprint"]["verified"] is True

rec = load("explain_recovery.json")
assert rec["status"] == "ok"
assert rec["data"]["runs"][0]["run_id"] == "wheel-recovery"
assert rec["data"]["runs"][0]["trace_integrity"] == "complete"
assert rec["data"]["runs"][0]["terminal"] == "post_execution"
assert rec["data"]["runs"][0]["actions"][1]["prior_same_tool_block_action_index"] == 1

terr = load("explain_tool_error.json")
assert terr["status"] == "ok"
assert terr["data"]["runs"][0]["trace_integrity"] == "complete"
assert terr["data"]["runs"][0]["terminal"] == "tool_error"

part = load("explain_partial.json")
assert part["status"] == "ok"
assert part["data"]["runs"][0]["trace_integrity"] == "partial"
assert part["data"]["runs"][0]["terminal"] is None

inc = load("explain_inconsistent.json")
assert inc["status"] == "inconsistent_log"
assert any(r["trace_integrity"] == "inconsistent" for r in inc["data"]["runs"])
assert any(r["trace_integrity"] in ("complete", "partial") for r in inc["data"]["runs"])

missing = load("explain_missing.json")
assert missing["status"] == "run_not_found"

cfdi_val = load("validate_cfdi.json")
assert cfdi_val["status"] == "unsupported_rules"
assert cfdi_val["data"]["field"] == "runtime_rules"
assert "cfdi.exact_match_required" in cfdi_val["data"]["unsupported_ids"]
assert "fingerprint" not in cfdi_val["data"]

cfdi_exp = load("explain_cfdi.json")
assert cfdi_exp["status"] == "ok"
cfdi_run = cfdi_exp["data"]["runs"][0]
assert cfdi_run["contract_id"] == "example.cfdi_reconciliation"
assert any(a["tool_name"] == "mark_reconciled" for a in cfdi_run["actions"])

before = json.loads((scratch / "before.json").read_text(encoding="utf-8"))
after = {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in before}
assert before == after, f"Input files modified: before={before} after={after}"

print("Smoke review skill consumer checks passed")
PY
)
