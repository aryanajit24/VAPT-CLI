#!/usr/bin/env bash
# VAPT CLI installer — Python 3.10+, system deps, Go tools, venv setup.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_MIN="3.10"

print_banner() {
    echo "============================================"
    echo "  VAPT CLI — Installer"
    echo "============================================"
    echo ""
}

check_python() {
    if ! command -v python3 &>/dev/null; then
        echo "[ERROR] python3 not found. Please install Python ${PYTHON_MIN}+." >&2
        exit 1
    fi
    PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    IFS='.' read -r major minor <<<"${PY_VER}"
    MIN_MAJOR=3; MIN_MINOR=10
    if (( major < MIN_MAJOR || (major == MIN_MAJOR && minor < MIN_MINOR) )); then
        echo "[ERROR] Python ${PYTHON_MIN}+ required (found ${PY_VER})." >&2
        exit 1
    fi
    echo "[OK] Python ${PY_VER} detected."
}

install_system_deps() {
    echo "[INFO] Installing system dependencies..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y nmap libxml2-dev libxslt1-dev \
            libffi-dev libssl-dev build-essential python3-dev python3-pip python3-venv \
            libpango-1.0-0 libpangoft2-1.0-0 libcairo2 2>/dev/null || true
    elif command -v yum &>/dev/null; then
        sudo yum install -y nmap openssl-devel libffi-devel gcc python3-devel python3-pip \
            pango cairo 2>/dev/null || true
    elif command -v brew &>/dev/null; then
        brew install nmap openssl libffi pango cairo 2>/dev/null || true
    else
        echo "[WARN] Could not detect package manager.  Please install nmap manually."
    fi
}

install_go_tools() {
    echo "[INFO] Installing Go-based security tools (nuclei, subfinder, naabu)..."

    # We need Go ≥ 1.21 for 'go install' to work with these tools.
    if ! command -v go &>/dev/null; then
        echo "[WARN] Go not found — skipping nuclei/subfinder/naabu installation."
        echo "       Install Go from https://go.dev/dl/ and re-run this script."
        return 0
    fi

    # Make sure $GOPATH/bin is on the PATH so the binaries are usable.
    export GOPATH="${GOPATH:-$HOME/go}"
    export PATH="${GOPATH}/bin:${PATH}"

    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && \
        echo "[OK] nuclei installed." || echo "[WARN] nuclei install failed."

    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null && \
        echo "[OK] subfinder installed." || echo "[WARN] subfinder install failed."

    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null && \
        echo "[OK] naabu installed." || echo "[WARN] naabu install failed."

    echo "[INFO] Go tools step complete."
}

setup_venv() {
    VENV_DIR="${REPO_DIR}/venv"
    echo "[INFO] Creating virtual environment at ${VENV_DIR}..."
    python3 -m venv "${VENV_DIR}"
    # shellcheck source=/dev/null
    source "${VENV_DIR}/bin/activate"
    pip install --upgrade pip --quiet
}

install_python_deps() {
    echo "[INFO] Installing Python dependencies..."
    pip install --quiet -r "${REPO_DIR}/requirements.txt"
}

install_vapt_cli() {
    echo "[INFO] Installing VAPT CLI package..."
    pip install --quiet -e "${REPO_DIR}"
}

seed_database() {
    echo "[INFO] Seeding knowledge base..."
    python3 "${REPO_DIR}/vapt/database/seed_kb.py" || \
        echo "[WARN] Knowledge base seeding failed.  Run manually: python3 vapt/database/seed_kb.py"
}

run_selftest() {
    echo "[INFO] Running quick self-test..."

    # 1. Check the CLI loads without import errors.
    if python3 -c "from vapt.main import app; print('[OK] CLI imports clean.')" 2>/dev/null; then
        : # success
    else
        echo "[WARN] CLI import check failed — check for missing dependencies."
    fi

    # 2. Verify knowledge base has entries.
    if python3 -c "
from vapt.database.db import get_session, init_db
from vapt.database.models import KnowledgeEntry
init_db()
s = get_session()
count = s.query(KnowledgeEntry).count()
s.close()
assert count >= 10, f'Only {count} KB entries'
print(f'[OK] Knowledge base has {count} entries.')
" 2>/dev/null; then
        : # success
    else
        echo "[WARN] Knowledge base verification failed."
    fi

    echo "[INFO] Self-test complete."
}

verify_install() {
    echo ""
    if vapt --version &>/dev/null; then
        echo "[OK] VAPT CLI installed successfully."
        echo ""
        echo "To activate the environment in new shells:"
        echo "  source ${REPO_DIR}/venv/bin/activate"
        echo ""
        echo "Run your first scan:"
        echo "  vapt scan --target example.com"
    else
        echo "[WARN] 'vapt' command not found in PATH.  Try:"
        echo "  source ${REPO_DIR}/venv/bin/activate && vapt --version"
    fi
}

main() {
    print_banner
    check_python
    install_system_deps
    install_go_tools
    setup_venv
    install_python_deps
    install_vapt_cli
    seed_database
    run_selftest
    verify_install
}

main "$@"
