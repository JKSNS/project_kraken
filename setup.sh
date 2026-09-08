#!/usr/bin/env bash
# setup.sh -- KRAKEN environment setup (root-updates-target-venv, non-interactive, dual-user ready)
#
# Usage:
#   sudo -E bash setup.sh
#   KRAKEN_TARGET_VENV=$HOME/venv sudo -E bash setup.sh
#
# Model:
# - Root updates a specific target venv (often $HOME/venv)
# - Runtime user (default: claude) uses that same venv
# - Non-interactive: installs optional components by default
# - Deterministic Ghidra install fallback (no URL guessing)
# - Shared .NET tools path for BOTH root and runtime user
# - Docker Compose plugin fallback install (manual system-wide plugin)
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

ok()      { echo -e "  ${GREEN}[+]${NC}  $*"; }
warn()    { echo -e "  ${YELLOW}!${NC}  $*"; }
fail()    { echo -e "  ${RED}[x]${NC}  $*"; }
section() { echo -e "\n${BLUE}[$1]${NC} $2"; }

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$REPO_ROOT/.env"
LOG_DIR="$REPO_ROOT/.setup-logs"

# Default runtime user: whoever invoked sudo, or the repo owner, or current user
_DEFAULT_RUNTIME_USER="${SUDO_USER:-$(stat -c '%U' "$REPO_ROOT" 2>/dev/null || whoami)}"
RUNTIME_USER="${KRAKEN_RUNTIME_USER:-$_DEFAULT_RUNTIME_USER}"
TARGET_VENV="${KRAKEN_TARGET_VENV:-${VIRTUAL_ENV:-$REPO_ROOT/venv}}"

# Non-interactive defaults
INSTALL_ANGR="${INSTALL_ANGR:-1}"
INSTALL_GHIDRA="${INSTALL_GHIDRA:-1}"
INSTALL_DOTNET_TOOLS="${INSTALL_DOTNET_TOOLS:-1}"
AUTO_REBUILD_BROKEN_VENV="${AUTO_REBUILD_BROKEN_VENV:-1}"

# Deterministic Ghidra pin (override in env if needed)
# Official releases page currently lists 12.0.3 and 12.0.2 tags; pin explicitly here.
GHIDRA_VER="${GHIDRA_VER:-12.0.2}"
GHIDRA_BUILD_TAG="${GHIDRA_BUILD_TAG:-Ghidra_${GHIDRA_VER}_build}"
GHIDRA_ZIP="${GHIDRA_ZIP:-ghidra_12.0.2_PUBLIC_20260129.zip}"
GHIDRA_URL="${GHIDRA_URL:-https://github.com/NationalSecurityAgency/ghidra/releases/download/${GHIDRA_BUILD_TAG}/${GHIDRA_ZIP}}"

# Shared tools / plugin locations (dual-user)
DOTNET_TOOL_PATH_SHARED="${DOTNET_TOOL_PATH_SHARED:-/opt/kraken-dotnet-tools}"
DOCKER_CLI_PLUGIN_DIR_SYSTEM="${DOCKER_CLI_PLUGIN_DIR_SYSTEM:-/usr/local/lib/docker/cli-plugins}"
DOCKER_COMPOSE_PLUGIN_PATH="${DOCKER_CLI_PLUGIN_DIR_SYSTEM}/docker-compose"

echo "========================================"
echo "  KRAKEN Setup (root updates target venv)"
echo "========================================"
echo "Repo: $REPO_ROOT"
echo "Target venv: $TARGET_VENV"
echo "Runtime user: $RUNTIME_USER"
echo "Logs: $LOG_DIR"
echo "Shared .NET tools: $DOTNET_TOOL_PATH_SHARED"

IS_WSL=false
if grep -qi microsoft /proc/version 2>/dev/null; then
    IS_WSL=true
    echo "Platform: WSL"
else
    echo "Platform: Linux"
fi

if [ "$(id -u)" -ne 0 ]; then
    fail "This setup mode requires root. Run: sudo -E bash setup.sh"
    echo "  Or: KRAKEN_TARGET_VENV=$HOME/venv sudo -E bash setup.sh"
    exit 1
fi

mkdir -p "$LOG_DIR"

# ---------- Ensure runtime user exists ----------
if ! id "$RUNTIME_USER" >/dev/null 2>&1; then
    # Only auto-create if explicitly requested via KRAKEN_RUNTIME_USER
    if [ -n "${KRAKEN_RUNTIME_USER:-}" ]; then
        echo -e "\n${YELLOW}!${NC}  Runtime user '$RUNTIME_USER' not found -- creating with home directory"
        useradd -m -s /bin/bash "$RUNTIME_USER"
        echo "${RUNTIME_USER}:${RUNTIME_USER}" | chpasswd
        ok "Created user '$RUNTIME_USER' (password: $RUNTIME_USER)"
    else
        warn "Auto-detected runtime user '$RUNTIME_USER' not found; falling back to root"
        RUNTIME_USER="root"
    fi
else
    ok "Runtime user '$RUNTIME_USER' exists"
fi

# ---------- Logging helpers ----------
run_logged() {
    local name="$1"
    shift
    local log="$LOG_DIR/${name}.log"
    echo "  [log] $log"
    "$@" 2>&1 | tee "$log"
    local rc=${PIPESTATUS[0]}
    return "$rc"
}

run_with_heartbeat_logged() {
    local name="$1"
    shift

    local heartbeat_pid=""
    (
        while true; do
            sleep 10
            echo "  ...still working ($(date +%H:%M:%S))"
        done
    ) &
    heartbeat_pid=$!

    local rc=0
    set +e
    run_logged "$name" "$@"
    rc=$?
    set -e

    kill "$heartbeat_pid" >/dev/null 2>&1 || true
    wait "$heartbeat_pid" 2>/dev/null || true

    return "$rc"
}

# ---------- Package manager helpers ----------
HAS_APT=false
if command -v apt-get >/dev/null 2>&1; then
    HAS_APT=true
fi

apt_install() {
    local pkgs=("$@")
    if [ "${#pkgs[@]}" -eq 0 ]; then
        return 0
    fi
    if [ "$HAS_APT" != true ]; then
        warn "apt-get not available; cannot auto-install: ${pkgs[*]}"
        return 1
    fi

    local uniq_pkgs=()
    mapfile -t uniq_pkgs < <(printf '%s\n' "${pkgs[@]}" | awk 'NF' | sort -u)

    echo "  Installing apt packages: ${uniq_pkgs[*]}"
    run_logged "apt_update_$(date +%s)" apt-get update -qq || return 1
    run_logged "apt_install_$(date +%s)" apt-get install -y "${uniq_pkgs[@]}" || return 1
}

# ---------- Multi-user runtime helpers ----------
ensure_path_line_in_bashrc() {
    local user_home="$1"
    local line="$2"
    local rcfile="${user_home}/.bashrc"

    mkdir -p "$user_home"
    touch "$rcfile"

    if ! grep -Fqx "$line" "$rcfile" 2>/dev/null; then
        echo "$line" >> "$rcfile"
    fi
}

configure_shared_tool_paths_for_users() {
    mkdir -p "$DOTNET_TOOL_PATH_SHARED"
    chmod 755 "$DOTNET_TOOL_PATH_SHARED"

    # System-wide shell profile for login shells
    mkdir -p /etc/profile.d
    cat > /etc/profile.d/kraken-tools-path.sh <<EOF
# Added by KRAKEN setup
export PATH="$DOTNET_TOOL_PATH_SHARED:\$PATH"
EOF
    chmod 644 /etc/profile.d/kraken-tools-path.sh
    ok "Installed /etc/profile.d/kraken-tools-path.sh"

    # Also patch bashrc for non-login shells
    ensure_path_line_in_bashrc "/root" "export PATH=\"$DOTNET_TOOL_PATH_SHARED:\$PATH\""

    if id "$RUNTIME_USER" >/dev/null 2>&1; then
        local user_home
        user_home="$(getent passwd "$RUNTIME_USER" | cut -d: -f6)"
        [ -n "$user_home" ] || user_home="/home/$RUNTIME_USER"
        ensure_path_line_in_bashrc "$user_home" "export PATH=\"$DOTNET_TOOL_PATH_SHARED:\$PATH\""
        chown "$RUNTIME_USER":"$RUNTIME_USER" "$user_home/.bashrc" 2>/dev/null || true
    fi

    ok "Configured shared tool PATH for root and ${RUNTIME_USER}"
}

verify_command_for_user() {
    local user="$1"
    local cmd="$2"

    if ! id "$user" >/dev/null 2>&1; then
        warn "User '$user' not found; skipping verification: $cmd"
        return 0
    fi

    if su -s /bin/bash "$user" -c "source /etc/profile >/dev/null 2>&1 || true; $cmd" >/dev/null 2>&1; then
        ok "User '$user' can run: $cmd"
    else
        warn "User '$user' cannot run: $cmd"
        return 1
    fi
}

# ---------- Python / venv / pip helpers ----------
SYSTEM_PYTHON=""
PYTHON_BIN=""
PIP_CMD=()

ensure_system_python() {
    if [ -x /usr/bin/python3 ]; then
        SYSTEM_PYTHON="/usr/bin/python3"
    elif command -v python3 >/dev/null 2>&1; then
        SYSTEM_PYTHON="$(command -v python3)"
    else
        fail "python3 not found -- install Python 3.11+"
        exit 1
    fi

    local py_ver
    py_ver="$("$SYSTEM_PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')"
    ok "base python3 ${py_ver} (${SYSTEM_PYTHON})"

    if ! "$SYSTEM_PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)'; then
        warn "Python < 3.11 detected. Some dependencies/features may fail."
    fi
}

ensure_venv_module() {
    if "$SYSTEM_PYTHON" -m venv -h >/dev/null 2>&1; then
        ok "venv module available"
        return 0
    fi

    warn "python3 venv module missing; installing python3-venv"
    apt_install python3-venv || { fail "Failed to install python3-venv"; exit 1; }
    "$SYSTEM_PYTHON" -m venv -h >/dev/null 2>&1 || { fail "venv still unavailable"; exit 1; }
    ok "venv module installed"
}

target_venv_python() { echo "$TARGET_VENV/bin/python"; }

venv_exists_and_python_runs() {
    [ -x "$(target_venv_python)" ] || return 1
    "$(target_venv_python)" -c 'import sys; print(sys.version)' >/dev/null 2>&1
}

create_or_repair_target_venv_shell() {
    local need_recreate=false

    if [ ! -d "$TARGET_VENV" ] || [ ! -x "$(target_venv_python)" ]; then
        need_recreate=true
    elif ! venv_exists_and_python_runs; then
        warn "Target venv python is broken"
        need_recreate=true
    fi

    if [ "$need_recreate" = true ]; then
        warn "Creating/recreating target venv at $TARGET_VENV"
        rm -rf "$TARGET_VENV"
        mkdir -p "$(dirname "$TARGET_VENV")"
        run_logged "create_venv" "$SYSTEM_PYTHON" -m venv "$TARGET_VENV" || {
            fail "Failed to create venv at $TARGET_VENV"
            exit 1
        }
        ok "Created target venv"
    else
        ok "Target venv exists"
    fi

    PYTHON_BIN="$(target_venv_python)"
    PIP_CMD=("$PYTHON_BIN" "-m" "pip")
    ok "Using venv python: $PYTHON_BIN"
}

ensure_pip_presence() {
    if "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; then
        PIP_CMD=("$PYTHON_BIN" "-m" "pip")
        ok "pip available via $PYTHON_BIN -m pip"
        return 0
    fi

    warn "pip not found for $PYTHON_BIN"
    if "$PYTHON_BIN" -m ensurepip --upgrade >/dev/null 2>&1; then
        PIP_CMD=("$PYTHON_BIN" "-m" "pip")
        ok "Bootstrapped pip via ensurepip"
        return 0
    fi

    fail "pip unavailable in target venv"
    exit 1
}

pip_healthcheck() {
    "${PIP_CMD[@]}" --version >/dev/null 2>&1
}

rebuild_target_venv_if_pip_broken() {
    if pip_healthcheck; then
        return 0
    fi

    fail "pip in target venv is present but broken (corrupted bytecode / version mismatch likely)"
    if [ "$AUTO_REBUILD_BROKEN_VENV" != "1" ]; then
        exit 1
    fi

    warn "Auto-rebuilding target venv at $TARGET_VENV"
    rm -rf "$TARGET_VENV"
    run_logged "recreate_venv_after_pip_break" "$SYSTEM_PYTHON" -m venv "$TARGET_VENV" || {
        fail "Failed to recreate venv"
        exit 1
    }

    PYTHON_BIN="$(target_venv_python)"
    PIP_CMD=("$PYTHON_BIN" "-m" "pip")

    ensure_pip_presence
    pip_healthcheck || { fail "pip still broken after target venv rebuild"; exit 1; }
    ok "Rebuilt target venv and restored pip"
}

set_target_venv_permissions() {
    # Root-managed writes; runtime-user reads/executes.
    chown -R root:root "$TARGET_VENV"
    find "$TARGET_VENV" -type d -exec chmod 755 {} \;
    find "$TARGET_VENV" -type f -exec chmod 644 {} \;
    # Make everything in bin/ executable (files AND symlinks + their targets)
    chmod 755 "$TARGET_VENV/bin"/* 2>/dev/null || true
    # Also chase symlinks to ensure the actual binaries are executable
    find "$TARGET_VENV/bin" -maxdepth 1 -type l -exec sh -c 'chmod 755 "$(readlink -f "$1")"' _ {} \; 2>/dev/null || true
    ok "Target venv permissions set (root-owned, world-readable/executable)"
}

verify_runtime_user_can_use_venv() {
    if ! id "$RUNTIME_USER" >/dev/null 2>&1; then
        warn "Runtime user '$RUNTIME_USER' not found; skipping runtime-user verification"
        return 0
    fi

    if su -s /bin/bash "$RUNTIME_USER" -c "\"$TARGET_VENV/bin/python\" -m pip --version >/dev/null"; then
        ok "Runtime user '$RUNTIME_USER' can use target venv"
    else
        warn "Runtime user '$RUNTIME_USER' cannot use target venv yet (permissions/path issue)"
    fi
}

# ---------- Docker Compose plugin manual install ----------
install_docker_compose_plugin_manual_systemwide() {
    mkdir -p "$DOCKER_CLI_PLUGIN_DIR_SYSTEM"
    chmod 755 /usr/local/lib /usr/local/lib/docker "$DOCKER_CLI_PLUGIN_DIR_SYSTEM" 2>/dev/null || true

    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *)
            fail "Unsupported architecture for manual docker compose plugin: $arch"
            return 1
            ;;
    esac

    # Pin version for reproducibility (override if needed)
    local compose_ver="${DOCKER_COMPOSE_PLUGIN_VERSION:-v2.40.3}"
    local compose_url="${DOCKER_COMPOSE_PLUGIN_URL:-https://github.com/docker/compose/releases/download/${compose_ver}/docker-compose-linux-${arch}}"

    ok "Installing docker compose plugin manually (system-wide)"
    ok "Pinned Compose plugin URL: $compose_url"

    if command -v wget >/dev/null 2>&1; then
        run_with_heartbeat_logged "docker_compose_plugin_download" wget -O "$DOCKER_COMPOSE_PLUGIN_PATH" "$compose_url" || return 1
    elif command -v curl >/dev/null 2>&1; then
        run_with_heartbeat_logged "docker_compose_plugin_download" curl -fL -o "$DOCKER_COMPOSE_PLUGIN_PATH" "$compose_url" || return 1
    else
        fail "Need wget or curl to download docker compose plugin"
        return 1
    fi

    chmod 755 "$DOCKER_COMPOSE_PLUGIN_PATH"
    return 0
}

# ---------- Ghidra helpers ----------
is_valid_ghidra_dir() {
    local d="$1"
    [ -n "$d" ] && [ -d "$d" ] && [ -f "$d/support/analyzeHeadless" ]
}

discover_existing_ghidra() {
    local candidates=(
        "${GHIDRA_INSTALL_DIR:-}"
        "${KRAKEN_DOCKER_GHIDRA_INSTALL_DIR:-}"
        "$HOME/tools/ghidra_12.0.3_PUBLIC"
        "$HOME/tools/ghidra_12.0.2_PUBLIC"
        "$HOME/tools/ghidra_12.0.1_PUBLIC"
        "$HOME/tools/ghidra"
        "$HOME/ghidra"
        "/opt/ghidra"
        "/opt/ghidra_12.0.3_PUBLIC"
        "/opt/ghidra_12.0.2_PUBLIC"
        "/usr/local/ghidra"
    )

    local c
    for c in "${candidates[@]}"; do
        if is_valid_ghidra_dir "$c"; then
            echo "$c"
            return 0
        fi
    done

    # Broader scan fallback (bounded)
    local found=""
    found="$(find "$HOME" /opt /usr/local -maxdepth 3 -type f -name analyzeHeadless 2>/dev/null | head -1 || true)"
    if [ -n "$found" ]; then
        dirname "$(dirname "$found")"
        return 0
    fi

    return 1
}

# ---------- Start ----------
echo

# ── [1] Python package install ─────────────────────────────────────────
section "1/7" "Python dependencies (root-updated target venv)"

if [ -n "${VIRTUAL_ENV:-}" ]; then
    ok "Inherited VIRTUAL_ENV detected: $VIRTUAL_ENV"
fi
ok "Resolved target venv: $TARGET_VENV"

ensure_system_python
ensure_venv_module
create_or_repair_target_venv_shell
ensure_pip_presence
rebuild_target_venv_if_pip_broken

echo "  Upgrading pip/setuptools/wheel in target venv..."
if run_with_heartbeat_logged "pip_upgrade_tooling" "${PIP_CMD[@]}" install -U pip setuptools wheel; then
    ok "pip/setuptools/wheel upgraded in target venv"
else
    fail "Failed to upgrade pip/setuptools/wheel in target venv"
    exit 1
fi

if [ ! -f "$REPO_ROOT/pyproject.toml" ] && [ ! -f "$REPO_ROOT/setup.py" ]; then
    fail "No pyproject.toml or setup.py found in $REPO_ROOT"
    exit 1
fi

if "$PYTHON_BIN" -c "import kraken" >/dev/null 2>&1; then
    ok "kraken already installed in target venv"
else
    echo "  Running: $PYTHON_BIN -m pip install -e \"$REPO_ROOT\""
    if run_with_heartbeat_logged "pip_install_kraken" "${PIP_CMD[@]}" install -e "$REPO_ROOT"; then
        ok "kraken installed in target venv"
    else
        fail "kraken install failed (see $LOG_DIR/pip_install_kraken.log)"
        exit 1
    fi
fi

echo "  Ensuring helper-script runtime packages are present (angr, z3-solver, pycryptodome, pwntools)..."
if run_with_heartbeat_logged "pip_install_solver_helpers" "${PIP_CMD[@]}" install -U angr z3-solver pycryptodome pwntools; then
    ok "helper-script runtime packages installed in target venv"
else
    fail "Failed to install helper-script runtime packages (see $LOG_DIR/pip_install_solver_helpers.log)"
    exit 1
fi

if [ "$INSTALL_ANGR" = "1" ]; then
    if ! "$PYTHON_BIN" -c "import angr" >/dev/null 2>&1; then
        echo "  Installing angr extras into target venv..."
        if run_with_heartbeat_logged "pip_install_angr" "${PIP_CMD[@]}" install -e "$REPO_ROOT[angr]"; then
            ok "angr installed in target venv"
        else
            fail "angr install failed (see $LOG_DIR/pip_install_angr.log)"
            exit 1
        fi
    else
        ok "angr already installed in target venv"
    fi
else
    warn "INSTALL_ANGR=0 -- skipping angr"
fi

set_target_venv_permissions
verify_runtime_user_can_use_venv

# ── [2] LLM backend ────────────────────────────────────────────────────
section "2/7" "LLM backend"

if command -v claude >/dev/null 2>&1; then
    ok "claude CLI -- backend=claude ready (check: claude auth status)"
elif command -v ollama >/dev/null 2>&1; then
    ok "ollama -- set KRAKEN_BACKEND=ollama, pull a model: ollama pull glm-4.7-flash"
else
    warn "No LLM backend found"
    echo "    Option A (recommended): https://docs.anthropic.com/en/docs/claude-code"
    echo "    Option B: https://ollama.com"
fi

# ── [3] Java + Ghidra ──────────────────────────────────────────────────
section "3/7" "Java & Ghidra"

JAVA_HOME_DETECTED=""
if [ -n "${JAVA_HOME:-}" ] && [ -d "$JAVA_HOME" ]; then
    JAVA_HOME_DETECTED="$JAVA_HOME"
    ok "JAVA_HOME=$JAVA_HOME"
elif command -v java >/dev/null 2>&1; then
    JAVA_HOME_DETECTED="$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")"
    ok "java $(java -version 2>&1 | head -1)"
else
    warn "Java not found -- required for Ghidra; installing OpenJDK 21"
    if apt_install openjdk-21-jdk; then
        JAVA_HOME_DETECTED="$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")"
        ok "Java installed"
    else
        fail "Java install failed"
        exit 1
    fi
fi

FOUND_GHIDRA=""
if FOUND_GHIDRA="$(discover_existing_ghidra)"; then
    ok "Ghidra already installed: $FOUND_GHIDRA"
else
    warn "No existing Ghidra installation found"
    if [ "$INSTALL_GHIDRA" = "1" ]; then
        ok "Will install pinned Ghidra only because check failed"
        ok "Pinned Ghidra URL: $GHIDRA_URL"

        mkdir -p "$HOME/tools"
        if ! command -v wget >/dev/null 2>&1 && ! command -v curl >/dev/null 2>&1; then
            apt_install wget || apt_install curl || { fail "Need wget or curl to download Ghidra"; exit 1; }
        fi
        if ! command -v unzip >/dev/null 2>&1; then
            apt_install unzip || { fail "Need unzip to extract Ghidra"; exit 1; }
        fi

        echo "  Downloading Ghidra..."
        if command -v wget >/dev/null 2>&1; then
            if ! run_with_heartbeat_logged "ghidra_download" wget -O "$HOME/tools/$GHIDRA_ZIP" "$GHIDRA_URL"; then
                fail "Ghidra download failed (see $LOG_DIR/ghidra_download.log)"
                echo "  Check GHIDRA_URL/GHIDRA_ZIP pin."
                exit 1
            fi
        else
            if ! run_with_heartbeat_logged "ghidra_download" curl -fL -o "$HOME/tools/$GHIDRA_ZIP" "$GHIDRA_URL"; then
                fail "Ghidra download failed (see $LOG_DIR/ghidra_download.log)"
                echo "  Check GHIDRA_URL/GHIDRA_ZIP pin."
                exit 1
            fi
        fi

        echo "  Extracting Ghidra..."
        if ! run_logged "ghidra_unzip" unzip -q "$HOME/tools/$GHIDRA_ZIP" -d "$HOME/tools/"; then
            fail "Ghidra extraction failed (see $LOG_DIR/ghidra_unzip.log)"
            exit 1
        fi
        rm -f "$HOME/tools/$GHIDRA_ZIP"

        if FOUND_GHIDRA="$(discover_existing_ghidra)"; then
            ok "Ghidra installed: $FOUND_GHIDRA"
        else
            fail "Ghidra install incomplete -- analyzeHeadless not found after extraction"
            exit 1
        fi
    else
        warn "INSTALL_GHIDRA=0 -- skipping Ghidra install"
    fi
fi

# ── [4] System binary tools ────────────────────────────────────────────
section "4/7" "System binary tools"

MISSING_PKGS=()
for tool in strings readelf objdump; do
    if command -v "$tool" >/dev/null 2>&1; then
        ok "$tool"
    else
        fail "$tool"
        MISSING_PKGS+=("binutils")
    fi
done
if command -v file >/dev/null 2>&1; then
    ok "file"
else
    fail "file"
    MISSING_PKGS+=("file")
fi

if [ "${#MISSING_PKGS[@]}" -gt 0 ]; then
    apt_install "${MISSING_PKGS[@]}" && ok "Installed required system tools" || warn "Could not auto-install all system tools"
fi

# ── [5] .NET / CIL tools ───────────────────────────────────────────────
section "5/7" ".NET tools (for CIL/dotnet challenges)"
echo "  Note: installing pre-reqs automatically (non-interactive mode)."

DOTNET_APT_MISSING=()
if command -v mono >/dev/null 2>&1; then
    ok "mono $(mono --version 2>/dev/null | awk 'NR==1{print $NF}')"
else
    warn "mono not found"
    DOTNET_APT_MISSING+=("mono-runtime")
fi
if command -v monodis >/dev/null 2>&1; then
    ok "monodis"
else
    warn "monodis not found"
    DOTNET_APT_MISSING+=("mono-utils")
fi

if [ "${#DOTNET_APT_MISSING[@]}" -gt 0 ]; then
    apt_install "${DOTNET_APT_MISSING[@]}" && ok "Mono tools installed" || warn "Mono tool install failed"
fi

configure_shared_tool_paths_for_users

if [ "$INSTALL_DOTNET_TOOLS" = "1" ]; then
    if [ -x "$DOTNET_TOOL_PATH_SHARED/ilspycmd" ]; then
        ok "ilspycmd present at $DOTNET_TOOL_PATH_SHARED/ilspycmd"
    else
        if ! command -v dotnet >/dev/null 2>&1; then
            warn "dotnet SDK not installed; attempting apt install dotnet-sdk-8.0"
            apt_install dotnet-sdk-8.0 || warn "Could not install dotnet-sdk-8.0"
        fi

        if command -v dotnet >/dev/null 2>&1; then
            echo "  Installing ilspycmd into shared tool path: $DOTNET_TOOL_PATH_SHARED"
            if run_with_heartbeat_logged "dotnet_install_ilspycmd_shared" dotnet tool install --tool-path "$DOTNET_TOOL_PATH_SHARED" ilspycmd; then
                ok "ilspycmd installed (shared)"
            else
                if run_with_heartbeat_logged "dotnet_update_ilspycmd_shared" dotnet tool update --tool-path "$DOTNET_TOOL_PATH_SHARED" ilspycmd; then
                    ok "ilspycmd updated (shared)"
                else
                    warn "ilspycmd install/update failed"
                fi
            fi
            chmod 755 "$DOTNET_TOOL_PATH_SHARED" "$DOTNET_TOOL_PATH_SHARED/ilspycmd" 2>/dev/null || true
        else
            warn "dotnet unavailable; skipping ilspycmd"
        fi
    fi

    verify_command_for_user root "command -v ilspycmd"
    verify_command_for_user "$RUNTIME_USER" "command -v ilspycmd"
else
    warn "INSTALL_DOTNET_TOOLS=0 -- skipping ilspycmd"
fi

# ── [6] Docker + ctfnet ────────────────────────────────────────────────
section "6/7" "Docker & ctfnet (for benchmark challenges)"

if command -v docker >/dev/null 2>&1; then
    ok "docker $(docker --version 2>&1 | awk '{print $3}' | tr -d ',')"

    if docker compose version >/dev/null 2>&1; then
        ok "docker compose v2"
    elif command -v docker-compose >/dev/null 2>&1; then
        ok "docker-compose v1 (legacy)"
    else
        warn "Docker Compose not found -- trying apt package first"
        if apt_install docker-compose-plugin; then
            if docker compose version >/dev/null 2>&1; then
                ok "docker compose v2 (apt package)"
            fi
        else
            warn "docker-compose-plugin package unavailable in current apt repos"
            warn "Falling back to manual system-wide plugin install"
            if install_docker_compose_plugin_manual_systemwide && docker compose version >/dev/null 2>&1; then
                ok "docker compose v2 (manual plugin)"
            else
                warn "Manual docker compose plugin install failed"
            fi
        fi
    fi

    # Optional compatibility wrapper for legacy scripts
    if docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
        cat > /usr/local/bin/docker-compose <<'EOF'
#!/usr/bin/env bash
exec docker compose "$@"
EOF
        chmod 755 /usr/local/bin/docker-compose
        ok "Installed docker-compose wrapper -> docker compose"
    fi

    verify_command_for_user root "docker compose version"
    verify_command_for_user "$RUNTIME_USER" "docker compose version"

    # ctfnet creation requires daemon access
    if docker info >/dev/null 2>&1; then
        if docker network ls --format '{{.Name}}' | grep -qx 'ctfnet'; then
            ok "ctfnet network exists"
        else
            docker network create ctfnet >/dev/null 2>&1 && ok "ctfnet network created" || warn "Failed to create ctfnet"
        fi
    else
        warn "Docker daemon not running or permission denied -- skipping ctfnet"
        if [ -S /var/run/docker.sock ]; then
            ls -l /var/run/docker.sock || true
        else
            warn "/var/run/docker.sock not present in this environment"
        fi
        echo "    This environment has Docker CLI but no daemon access."
        echo "    To fix (host/WSL): start Docker Desktop and enable WSL integration."
        echo "    To fix (container): mount /var/run/docker.sock and ensure socket/group permissions."
        if id "$RUNTIME_USER" >/dev/null 2>&1; then
            getent group docker >/dev/null 2>&1 || groupadd docker || true
            usermod -aG docker "$RUNTIME_USER" || true
            ok "Ensured ${RUNTIME_USER} is in docker group (re-login required if daemon/socket exists)"
        fi
    fi
else
    warn "Docker not installed (needed for NYU CTF Bench challenges)"
    if [ "$IS_WSL" = true ]; then
        echo "    Install Docker Desktop for Windows + enable WSL integration:"
        echo "    https://docs.docker.com/desktop/install/windows-install/"
    else
        apt_install docker.io || warn "Failed to install docker.io"
        if id "$RUNTIME_USER" >/dev/null 2>&1; then
            getent group docker >/dev/null 2>&1 || groupadd docker || true
            usermod -aG docker "$RUNTIME_USER" || warn "Failed to add $RUNTIME_USER to docker group"
        fi
    fi
fi

# ── [7] Write .env ─────────────────────────────────────────────────────
section "7/7" "Environment file"

{
    echo "# KRAKEN environment -- auto-generated by setup.sh (root-updated target venv, dual-user, non-interactive)"
    echo "# Runtime user should source this before running kraken"
    echo ""
    echo "export KRAKEN_TARGET_VENV=\"$TARGET_VENV\""
    echo "export VIRTUAL_ENV=\"$TARGET_VENV\""
    echo "export DOTNET_TOOL_PATH_SHARED=\"$DOTNET_TOOL_PATH_SHARED\""
    echo "export PATH=\"$DOTNET_TOOL_PATH_SHARED:$TARGET_VENV/bin:\$PATH\""
    [ -n "${FOUND_GHIDRA:-}" ] && echo "export GHIDRA_INSTALL_DIR=\"$FOUND_GHIDRA\""
    [ -n "${FOUND_GHIDRA:-}" ] && echo "export KRAKEN_DOCKER_GHIDRA_INSTALL_DIR=\"$FOUND_GHIDRA\""
    [ -n "${JAVA_HOME_DETECTED:-}" ] && echo "export JAVA_HOME=\"$JAVA_HOME_DETECTED\""
} > "$ENV_FILE"

chmod 644 "$ENV_FILE"
ok "Wrote $ENV_FILE"

# Final verification summary for both users
section "VERIFY" "Dual-user command visibility"

verify_command_for_user root "source \"$ENV_FILE\" >/dev/null 2>&1 || true; python -m pip --version"
verify_command_for_user "$RUNTIME_USER" "source \"$ENV_FILE\" >/dev/null 2>&1 || true; python -m pip --version"
verify_command_for_user root "source \"$ENV_FILE\" >/dev/null 2>&1 || true; command -v ilspycmd"
verify_command_for_user "$RUNTIME_USER" "source \"$ENV_FILE\" >/dev/null 2>&1 || true; command -v ilspycmd"
verify_command_for_user root "docker compose version"
verify_command_for_user "$RUNTIME_USER" "docker compose version"

if [ -n "${FOUND_GHIDRA:-}" ]; then
    verify_command_for_user root "test -f \"$FOUND_GHIDRA/support/analyzeHeadless\""
    verify_command_for_user "$RUNTIME_USER" "test -f \"$FOUND_GHIDRA/support/analyzeHeadless\""
fi

echo
echo "========================================"
echo -e "  ${GREEN}Setup complete!${NC}"
echo "========================================"
echo
echo "Target venv (root-updated):"
echo "  $TARGET_VENV"
echo
echo "Shared tools path:"
echo "  $DOTNET_TOOL_PATH_SHARED"
echo
echo "As ${RUNTIME_USER}, use:"
echo "  source $ENV_FILE"
echo "  which python"
echo "  python -m pip --version"
echo "  command -v ilspycmd && ilspycmd --version"
echo "  docker compose version"
echo "  test -f \"\$GHIDRA_INSTALL_DIR/support/analyzeHeadless\" && echo ghidra-ok"
echo "  kraken init"
echo "  kraken solve challenge.json"
echo
echo "Important:"
echo "  - Update the target venv only by rerunning setup as root"
echo "  - Do NOT run pip install as ${RUNTIME_USER} into $TARGET_VENV"
echo "  - Logs are in: $LOG_DIR"
echo "  - ctfnet creation requires a reachable Docker daemon (CLI alone is not enough)"
echo
echo "Benchmark:"
echo "  kraken-bench run --dataset ctftiny --category rev"
