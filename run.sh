#!/usr/bin/env bash
# Bootstrap a venv (first run) and invoke the orchestrator.
#   ./run.sh validate configs/example-lab.yaml
#   ./run.sh plan     configs/example-lab.yaml
#   ./run.sh scan     configs/example-lab.yaml
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
    echo "[setup] creating venv + installing deps..."
    python3 -m venv .venv
    ./.venv/bin/pip install -q -r requirements.txt
fi

exec ./.venv/bin/python -m orchestrator "$@"
