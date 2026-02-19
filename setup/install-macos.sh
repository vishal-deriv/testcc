#!/usr/bin/env bash
set -euo pipefail

# SafeSkillAgent macOS Installer
# Fully self-contained: installs ALL dependencies on a fresh machine
# Supports: macOS 12+ (Monterey and later), Intel and Apple Silicon

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="/etc/safeskill"
LOG_DIR="/var/log/safeskill"
PLIST_SRC="$SCRIPT_DIR/com.safeskill.agent.plist"
PLIST_DST="/Library/LaunchDaemons/com.safeskill.agent.plist"
VENV_DIR="/opt/safeskill/venv"
MIN_PYTHON_MINOR=10

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step()  { echo -e "${CYAN}[STEP]${NC} $*"; }

# ---------- Root check ----------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This installer must be run as root (use sudo)"
        exit 1
    fi
}

# ---------- Xcode CLI tools ----------
install_xcode_cli() {
    if xcode-select -p &>/dev/null; then
        log_info "Xcode Command Line Tools already installed"
        return
    fi

    log_step "Installing Xcode Command Line Tools (required for build tools)..."
    xcode-select --install 2>/dev/null || true

    log_warn "A dialog may have appeared to install Xcode CLI tools."
    log_warn "Please complete the installation, then re-run this script."
    echo ""
    read -rp "Press Enter once Xcode CLI tools are installed (or Ctrl+C to abort)..."

    if ! xcode-select -p &>/dev/null; then
        log_error "Xcode Command Line Tools still not found. Cannot continue."
        exit 1
    fi
    log_info "Xcode Command Line Tools installed"
}

# ---------- Homebrew ----------
install_homebrew() {
    if command -v brew &>/dev/null; then
        log_info "Homebrew already installed"
        return
    fi

    log_step "Installing Homebrew (package manager)..."
    NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

    if [[ -f /opt/homebrew/bin/brew ]]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [[ -f /usr/local/bin/brew ]]; then
        eval "$(/usr/local/bin/brew shellenv)"
    fi

    if ! command -v brew &>/dev/null; then
        log_error "Homebrew installation failed"
        exit 1
    fi
    log_info "Homebrew installed successfully"
}

# ---------- Python ----------
get_python_bin() {
    # Try to find a suitable Python >= 3.10
    for candidate in python3.14 python3.13 python3.12 python3.11 python3.10 python3; do
        if command -v "$candidate" &>/dev/null; then
            local ver
            ver=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null) || continue
            local major minor
            major=$(echo "$ver" | cut -d. -f1)
            minor=$(echo "$ver" | cut -d. -f2)
            if [[ "$major" -eq 3 ]] && [[ "$minor" -ge $MIN_PYTHON_MINOR ]]; then
                echo "$candidate"
                return 0
            fi
        fi
    done

    # Check Homebrew paths explicitly
    for bp in /opt/homebrew/bin /usr/local/bin; do
        for candidate in python3.14 python3.13 python3.12 python3.11 python3.10 python3; do
            if [[ -x "$bp/$candidate" ]]; then
                local ver
                ver=$("$bp/$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null) || continue
                local major minor
                major=$(echo "$ver" | cut -d. -f1)
                minor=$(echo "$ver" | cut -d. -f2)
                if [[ "$major" -eq 3 ]] && [[ "$minor" -ge $MIN_PYTHON_MINOR ]]; then
                    echo "$bp/$candidate"
                    return 0
                fi
            fi
        done
    done

    return 1
}

install_python() {
    local python_bin
    if python_bin=$(get_python_bin); then
        local ver
        ver=$("$python_bin" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        log_info "Python $ver found at $python_bin"
        PYTHON_BIN="$python_bin"
        return
    fi

    log_step "Python 3.10+ not found. Installing via Homebrew..."
    install_homebrew
    brew install python@3.12

    if python_bin=$(get_python_bin); then
        local ver
        ver=$("$python_bin" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        log_info "Python $ver installed at $python_bin"
        PYTHON_BIN="$python_bin"
        return
    fi

    log_error "Failed to install Python 3.10+. Please install manually and re-run."
    exit 1
}

# ---------- Verify venv module ----------
ensure_venv_module() {
    if "$PYTHON_BIN" -m venv --help &>/dev/null; then
        log_info "Python venv module available"
        return
    fi

    log_step "Python venv module not found. Installing..."
    brew install python@3.12 || true

    if ! "$PYTHON_BIN" -m venv --help &>/dev/null; then
        log_error "Cannot get venv module working. Please install: brew install python@3.12"
        exit 1
    fi
}

# ---------- Verify pip ----------
ensure_pip() {
    if "$PYTHON_BIN" -m pip --version &>/dev/null; then
        log_info "pip available"
        return
    fi

    log_step "pip not found. Installing..."
    "$PYTHON_BIN" -m ensurepip --upgrade 2>/dev/null || {
        curl -fsSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
        "$PYTHON_BIN" /tmp/get-pip.py
        rm -f /tmp/get-pip.py
    }

    if ! "$PYTHON_BIN" -m pip --version &>/dev/null; then
        log_error "Failed to install pip"
        exit 1
    fi
    log_info "pip installed"
}

# ---------- curl ----------
ensure_curl() {
    if command -v curl &>/dev/null; then
        return
    fi
    log_step "curl not found. Installing via Homebrew..."
    install_homebrew
    brew install curl
}

# ---------- Create venv and install agent ----------
install_agent() {
    log_step "Creating isolated virtual environment at $VENV_DIR..."
    mkdir -p "$(dirname "$VENV_DIR")"

    if [[ -d "$VENV_DIR" ]]; then
        log_warn "Existing venv found. Removing and recreating..."
        rm -rf "$VENV_DIR"
    fi

    "$PYTHON_BIN" -m venv "$VENV_DIR"

    log_step "Upgrading pip inside venv..."
    "$VENV_DIR/bin/python" -m pip install --upgrade pip

    log_step "Installing SafeSkillAgent and all Python dependencies into venv..."
    "$VENV_DIR/bin/pip" install "$PROJECT_DIR"

    # Verify installation
    if ! "$VENV_DIR/bin/safeskill" --version &>/dev/null; then
        log_error "SafeSkillAgent installation verification failed"
        exit 1
    fi

    log_info "SafeSkillAgent installed inside $VENV_DIR"

    mkdir -p /usr/local/bin
    ln -sf "$VENV_DIR/bin/safeskill" /usr/local/bin/safeskill
    ln -sf "$VENV_DIR/bin/safeskill" /usr/local/bin/safeskill-agent
    log_info "Symlinked safeskill -> /usr/local/bin/safeskill"
}

# ---------- Config ----------
setup_config() {
    log_step "Setting up configuration at $CONFIG_DIR..."
    mkdir -p "$CONFIG_DIR/environments"
    mkdir -p "$LOG_DIR"

    "$VENV_DIR/bin/safeskill" init --config-dir "$CONFIG_DIR"

    chown -R root:wheel "$CONFIG_DIR"
    chmod 750 "$CONFIG_DIR"
    chmod 640 "$CONFIG_DIR"/*.yaml 2>/dev/null || true
    chmod 750 "$CONFIG_DIR/environments"
    chmod 640 "$CONFIG_DIR/environments"/*.yaml 2>/dev/null || true

    chown -R root:wheel "$LOG_DIR"
    chmod 700 "$LOG_DIR"

    log_info "Config ready at $CONFIG_DIR"
}

# ---------- launchd ----------
install_launchd() {
    log_step "Installing LaunchDaemon..."

    if launchctl list 2>/dev/null | grep -q "com.safeskill.agent"; then
        log_warn "Unloading existing agent..."
        launchctl unload "$PLIST_DST" 2>/dev/null || true
    fi

    cp "$PLIST_SRC" "$PLIST_DST"
    chown root:wheel "$PLIST_DST"
    chmod 644 "$PLIST_DST"

    log_info "Loading LaunchDaemon..."
    launchctl load -w "$PLIST_DST"

    sleep 2
    if launchctl list 2>/dev/null | grep -q "com.safeskill.agent"; then
        log_info "SafeSkillAgent is running"
    else
        log_warn "Agent may not have started. Check: sudo launchctl list | grep safeskill"
    fi
}

# ---------- Clone source repo for auto-updates ----------
install_git_source() {
    local src_dir="/opt/safeskill/src"

    log_step "Setting up source repo for auto-updates..."

    if ! command -v git &>/dev/null; then
        log_warn "git not found. Installing Xcode CLI tools should provide git."
        install_xcode_cli
    fi

    if [[ -d "$src_dir/.git" ]]; then
        log_info "Source repo already exists at $src_dir"
        cd "$src_dir" && git pull --quiet 2>/dev/null || true
        return
    fi

    if [[ -d "$PROJECT_DIR/.git" ]]; then
        local remote_url
        remote_url=$(cd "$PROJECT_DIR" && git remote get-url origin 2>/dev/null || echo "")

        if [[ -n "$remote_url" ]]; then
            log_info "Cloning from git remote: $remote_url"
            mkdir -p "$(dirname "$src_dir")"
            git clone "$remote_url" "$src_dir" --quiet
            log_info "Source cloned to $src_dir"
            return
        fi
    fi

    log_info "No git remote found. Copying project to $src_dir"
    mkdir -p "$src_dir"
    rsync -a --exclude='.venv' --exclude='__pycache__' --exclude='*.egg-info' \
        --exclude='.pytest_cache' --exclude='logs' \
        "$PROJECT_DIR/" "$src_dir/"

    cd "$src_dir" && git init --quiet && git add -A && \
        git commit -m "Initial SafeSkill deployment" --quiet 2>/dev/null || true
    log_info "Source copied to $src_dir (local-only, set a remote for auto-updates)"
}

# ---------- Install auto-update timer ----------
install_updater_timer() {
    log_step "Installing auto-update timer..."

    local plist_src="$SCRIPT_DIR/com.safeskill.updater.plist"
    local plist_dst="/Library/LaunchDaemons/com.safeskill.updater.plist"

    if [[ ! -f "$plist_src" ]]; then
        log_warn "Updater plist not found. Skipping."
        return
    fi

    if launchctl list 2>/dev/null | grep -q "com.safeskill.updater"; then
        launchctl unload "$plist_dst" 2>/dev/null || true
    fi

    cp "$plist_src" "$plist_dst"
    chown root:wheel "$plist_dst"
    chmod 644 "$plist_dst"
    chmod +x /opt/safeskill/src/setup/update.sh 2>/dev/null || true

    launchctl load -w "$plist_dst"

    log_info "Auto-update timer enabled (checks every 30 min)"
}

# ---------- OpenClaw integration ----------
integrate_openclaw() {
    local openclaw_dir="${OPENCLAW_HOME:-$HOME/.openclaw}"
    local integration_script="$SCRIPT_DIR/../openclaw-skill/install.sh"

    if [[ ! -f "$integration_script" ]]; then
        log_warn "OpenClaw integration script not found. Skipping."
        return
    fi

    # Detect if the real user's home is different (running under sudo)
    local real_home="$HOME"
    if [[ -n "${SUDO_USER:-}" ]]; then
        real_home=$(eval echo "~$SUDO_USER")
        openclaw_dir="${real_home}/.openclaw"
    fi

    echo ""
    log_step "OpenClaw Integration"
    echo ""

    if [[ -d "$openclaw_dir" ]] || command -v openclaw &>/dev/null; then
        log_info "OpenClaw detected. Installing security enforcement layers..."
        if [[ -n "${SUDO_USER:-}" ]]; then
            sudo -u "$SUDO_USER" OPENCLAW_HOME="$openclaw_dir" bash "$integration_script" </dev/tty
        else
            OPENCLAW_HOME="$openclaw_dir" bash "$integration_script" </dev/tty
        fi
    else
        log_info "OpenClaw not detected at $openclaw_dir"
        log_info "To integrate later, run: ./openclaw-skill/install.sh"
    fi
}

# ---------- Main ----------
main() {
    echo ""
    echo "============================================"
    echo "   SafeSkillAgent macOS Installer (Full)"
    echo "============================================"
    echo ""
    echo "This installer will set up everything needed"
    echo "on a fresh macOS machine, including:"
    echo "  - Xcode Command Line Tools"
    echo "  - Homebrew (if Python not found)"
    echo "  - Python 3.10+"
    echo "  - pip and venv"
    echo "  - All Python dependencies (in isolated venv)"
    echo "  - SafeSkillAgent as a LaunchDaemon"
    echo ""

    check_root
    install_xcode_cli
    ensure_curl
    install_python
    ensure_venv_module
    ensure_pip
    install_agent
    setup_config
    install_launchd
    install_git_source
    install_updater_timer
    integrate_openclaw

    echo ""
    echo "============================================"
    log_info "Installation complete!"
    echo "============================================"
    echo ""
    echo "  Python:  $PYTHON_BIN"
    echo "  Venv:    $VENV_DIR"
    echo "  Config:  $CONFIG_DIR"
    echo "  Logs:    $LOG_DIR"
    echo "  Socket:  /tmp/safeskill.sock"
    echo ""
    echo "Usage:"
    echo "  safeskill status              # Check agent status"
    echo "  safeskill check 'rm -rf /'    # Test a command"
    echo "  safeskill set-trust strict    # Change trust mode"
    echo "  safeskill set-env production  # Change environment"
    echo "  safeskill reload              # Reload policies"
    echo ""
    echo "OpenClaw integration:"
    echo "  Restart OpenClaw to activate: openclaw stop && openclaw start"
    echo ""
}

main "$@"
