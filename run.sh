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

if [ ! -x .venv/bin/python ]; then
    echo "[setup] creating venv..."
    python3 -m venv .venv
fi
# Self-heal: (re)install deps whenever a required module is missing, so a
# half-built venv from an interrupted first run fixes itself.
if ! ./.venv/bin/python -c 'import yaml' 2>/dev/null; then
    echo "[setup] installing dependencies..."
    ./.venv/bin/pip install -q -r requirements.txt
fi

exec ./.venv/bin/python -m orchestrator "$@"
