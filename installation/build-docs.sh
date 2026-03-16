#!/usr/bin/env bash
#
# build-docs.sh
#
# Installs the MkDocs toolchain into an isolated Python virtual environment
# and builds the documentation site to the ./site/ output directory.
#
# The virtual environment is created at .venv-docs/ in the repository root
# and is reused on subsequent runs. Pass --clean to force a fresh install.
#
# Usage:
#   chmod +x build-docs.sh
#   ./build-docs.sh           # Build docs (reuse existing venv if present)
#   ./build-docs.sh --clean   # Wipe and recreate the venv before building
#   ./build-docs.sh --serve   # Build then serve locally on http://127.0.0.1:8000
#
# The Kroki plugin requires outbound HTTPS access to https://kroki.io
# (or a locally hosted Kroki instance configured in mkdocs.yml).

set -euo pipefail

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

VENV_DIR=".venv-docs"
DOCS_REQUIREMENTS="docs/requirements.txt"
MKDOCS_CONFIG="mkdocs.yml"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

CLEAN=false
SERVE=false

for arg in "$@"; do
    case "$arg" in
        --clean) CLEAN=true ;;
        --serve) SERVE=true ;;
        *) die "Unknown argument: $arg. Valid options: --clean, --serve" ;;
    esac
done

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

preflight() {
    info "Checking prerequisites..."

    # Verifies the script is being run from the repository root.
    if [ ! -f "$MKDOCS_CONFIG" ]; then
        die "mkdocs.yml not found. Run this script from the repository root."
    fi

    # Confirms Python 3 is available on the host.
    if ! command -v python3 &>/dev/null; then
        die "python3 is not installed. Install it with: sudo apt install python3 python3-venv"
    fi

    # Confirms the venv module is available.
    if ! python3 -m venv --help &>/dev/null; then
        die "python3-venv is not available. Install it with: sudo apt install python3-venv"
    fi

    # Confirms the docs requirements file exists.
    if [ ! -f "$DOCS_REQUIREMENTS" ]; then
        die "$DOCS_REQUIREMENTS not found. It should be present in the repository."
    fi

    success "Preflight checks passed."
}

# ---------------------------------------------------------------------------
# Virtual environment
# ---------------------------------------------------------------------------

setup_venv() {
    # Removes the existing virtual environment if --clean was requested.
    if [ "$CLEAN" = true ] && [ -d "$VENV_DIR" ]; then
        info "Removing existing virtual environment ($VENV_DIR)..."
        rm -rf "$VENV_DIR"
    fi

    # Creates the virtual environment if it does not already exist.
    if [ ! -d "$VENV_DIR" ]; then
        info "Creating Python virtual environment at $VENV_DIR..."
        python3 -m venv "$VENV_DIR"
        success "Virtual environment created."
    else
        info "Reusing existing virtual environment at $VENV_DIR."
    fi

    # Upgrades pip inside the venv to avoid outdated resolver warnings.
    info "Upgrading pip..."
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip
}

# ---------------------------------------------------------------------------
# Install MkDocs dependencies
# ---------------------------------------------------------------------------

install_docs_deps() {
    info "Installing MkDocs dependencies from $DOCS_REQUIREMENTS..."
    "$VENV_DIR/bin/pip" install --quiet -r "$DOCS_REQUIREMENTS"
    success "MkDocs dependencies installed."
}

# ---------------------------------------------------------------------------
# Build the documentation
# ---------------------------------------------------------------------------

build_docs() {
    info "Building documentation site..."

    # Passes --strict so that any broken links or plugin errors are treated
    # as failures rather than warnings, keeping the docs in a known-good state.
    "$VENV_DIR/bin/mkdocs" build --strict --config-file "$MKDOCS_CONFIG"

    success "Documentation built successfully."
    info "Output is in: ./site/"
}

# ---------------------------------------------------------------------------
# Serve locally (optional)
# ---------------------------------------------------------------------------

serve_docs() {
    info "Starting local development server on http://127.0.0.1:8000"
    info "Press Ctrl+C to stop."
    "$VENV_DIR/bin/mkdocs" serve --config-file "$MKDOCS_CONFIG"
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

main() {
    echo "============================================================"
    echo "  IoT Security Gateway - Documentation Build"
    echo "  $(date)"
    echo "============================================================"
    echo ""

    preflight
    setup_venv
    install_docs_deps
    build_docs

    if [ "$SERVE" = true ]; then
        serve_docs
    fi

    echo ""
    echo "============================================================"
    echo "  Done. Open ./site/index.html to browse offline."
    echo "============================================================"
}

main "$@"
