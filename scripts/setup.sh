#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "$(uname -s)" == Linux ]] && ! python3 -c 'import ctypes; ctypes.CDLL("libEGL.so.1")' 2>/dev/null; then
    if [[ "$(id -u)" == 0 ]]; then
        apt-get update
        apt-get install -y --no-install-recommends libegl1
    elif command -v sudo >/dev/null && sudo -n true; then
        sudo apt-get update
        sudo apt-get install -y --no-install-recommends libegl1
    else
        echo 'Qt requires libEGL.so.1. Install your distribution package libegl1, then rerun setup.' >&2
        exit 1
    fi
fi
uv sync --frozen --group dev --group build
QT_QPA_PLATFORM=offscreen uv run python -c 'from PySide6.QtWidgets import QApplication; app = QApplication([]); print("Qt ready")'
