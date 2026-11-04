#!/usr/bin/env bash
# Bootstrap a venv (first run) and invoke the orchestrator.
#
#   ./run.sh up                      # start the lab        (= lab up)
#   ./run.sh scan                    # scan the example lab (= scan example-lab)
#   ./run.sh scan acme               # scan configs/acme.yaml
#   ./run.sh down                    # stop the lab         (= lab down)
#   ./run.sh install                 # install an `exposure` command on PATH
set -euo pipefail
cd "$(dirname "$0")"

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

if [ ! -d .venv ]; then
    echo "[setup] creating venv + installing deps..."
    python3 -m venv .venv
    ./.venv/bin/pip install -q -r requirements.txt
fi

exec ./.venv/bin/python -m orchestrator "$@"
