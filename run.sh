#!/usr/bin/env bash
# Bootstrap a venv (first run) and invoke the orchestrator.
#
#   ./run.sh up                      # start the lab        (= lab up)
#   ./run.sh scan                    # scan the example lab (= scan example-lab)
#   ./run.sh scan acme               # scan configs/acme.yaml
#   ./run.sh down                    # stop the lab         (= lab down)
#   ./run.sh install                 # install an `exposure` command on PATH
set -euo pipefail
# Resolve through the symlink so `exposure` (in ~/.local/bin) still finds the
# repo, not the symlink's directory.
cd "$(dirname "$(readlink -f "$0")")"

# `install`: drop a short launcher in ~/.local/bin so you can type
#   exposure up / exposure scan / exposure down   (instead of ./run.sh ...)
if [ "${1:-}" = "install" ]; then
    mkdir -p "$HOME/.local/bin"
    ln -sf "$(pwd)/run.sh" "$HOME/.local/bin/exposure"
    echo "installed: exposure -> $(pwd)/run.sh"
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) echo "~/.local/bin is on PATH. Try:  exposure up" ;;
        *) echo "add ~/.local/bin to PATH, then:  exposure up" ;;
    esac
    exit 0
fi

deps_ok() { ./.venv/bin/python -c 'import yaml' 2>/dev/null; }

setup_venv() {
    # Some pythons create a venv without pip; ensurepip bootstraps it. We use
    # `python -m pip` (not the pip script, which may be missing).
    ./.venv/bin/python -m ensurepip --upgrade >/dev/null 2>&1 || true
    ./.venv/bin/python -m pip install -q -r requirements.txt
}

if [ ! -x .venv/bin/python ]; then
    echo "[setup] creating venv..."
    python3 -m venv .venv
fi
# Self-heal: if deps are missing, install them; if that still fails (e.g. a
# venv built without pip), rebuild the venv from scratch once.
if ! deps_ok; then
    echo "[setup] installing dependencies..."
    setup_venv || true
    if ! deps_ok; then
        echo "[setup] rebuilding venv..."
        rm -rf .venv && python3 -m venv .venv && setup_venv
    fi
fi

exec ./.venv/bin/python -m orchestrator "$@"
