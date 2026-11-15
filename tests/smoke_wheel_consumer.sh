#!/bin/sh
# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

(cd "$repository" && uv build --offline --out-dir "$scratch/dist")
uv venv --python "$repository/.venv/bin/python" "$scratch/venv"
uv pip install --python "$scratch/venv/bin/python" "$scratch/dist/"*.whl

mkdir "$scratch/consumer"
cp "$repository/tests/wheel_consumer.py" "$scratch/consumer/wheel_consumer.py"
cp "$repository/examples/notification_contract.yaml" "$scratch/consumer/notification_contract.yaml"
cp "$repository/examples/notification_contract_v2.yaml" "$scratch/consumer/notification_contract_v2.yaml"
(cd "$scratch/consumer" && env -u PYTHONPATH "$scratch/venv/bin/python" -I \
    wheel_consumer.py notification_contract.yaml notification_contract_v2.yaml)
