#!/usr/bin/env bash
set -euo pipefail

# SafeSkillAgent Linux Installer
# Fully self-contained: installs ALL dependencies on a fresh machine
# Supports: Debian/Ubuntu, Fedora/RHEL/CentOS/Rocky/Alma, Arch, openSUSE

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="/etc/safeskill"
LOG_DIR="/var/log/safeskill"
SERVICE_SRC="$SCRIPT_DIR/safeskill-agent.service"
SERVICE_DST="/etc/systemd/system/safeskill-agent.service"
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

DISTRO=""
PKG_MANAGER=""

# ---------- Root check ----------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This installer must be run as root (use sudo)"
        exit 1
    fi
}

# ---------- Detect distro ----------
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian|linuxmint|pop|elementary|zorin)
                DISTRO="debian"
                PKG_MANAGER="apt-get"
                ;;
            fedora)
                DISTRO="fedora"
                PKG_MANAGER="dnf"
                ;;
            centos|rhel|rocky|almalinux|ol)
                DISTRO="rhel"
                if command -v dnf &>/dev/null; then
                    PKG_MANAGER="dnf"
                else
                    PKG_MANAGER="yum"
                fi
                ;;
            arch|manjaro|endeavouros)
                DISTRO="arch"
                PKG_MANAGER="pacman"
                ;;
            opensuse*|sles)
                DISTRO="suse"
                PKG_MANAGER="zypper"
                ;;
            *)
                log_warn "Unknown distro: $ID. Will attempt Debian-style install."
                DISTRO="debian"
                PKG_MANAGER="apt-get"
                ;;
        esac
    elif command -v apt-get &>/dev/null; then
        DISTRO="debian"
        PKG_MANAGER="apt-get"
    elif command -v dnf &>/dev/null; then
        DISTRO="fedora"
        PKG_MANAGER="dnf"
    elif command -v yum &>/dev/null; then
        DISTRO="rhel"
        PKG_MANAGER="yum"
    elif command -v pacman &>/dev/null; then
        DISTRO="arch"
        PKG_MANAGER="pacman"
    else
        log_error "Cannot detect package manager. Please install Python 3.10+ manually."
        exit 1
    fi

    log_info "Detected distro family: $DISTRO (package manager: $PKG_MANAGER)"
}

# ---------- Install system packages ----------
install_system_packages() {
    log_step "Installing system dependencies..."

    case "$DISTRO" in
        debian)
            apt-get update -y
            apt-get install -y \
                curl \
                ca-certificates \
                gnupg \
                build-essential \
                libffi-dev \
                libssl-dev
            ;;
        fedora)
            dnf install -y \
                curl \
                ca-certificates \
                gcc \
                gcc-c++ \
                make \
                libffi-devel \
                openssl-devel
            ;;
        rhel)
            $PKG_MANAGER install -y \
                curl \
                ca-certificates \
                gcc \
                gcc-c++ \
                make \
                libffi-devel \
                openssl-devel
            # EPEL may be needed on older RHEL/CentOS for newer Python
            if ! $PKG_MANAGER repolist 2>/dev/null | grep -qi epel; then
                $PKG_MANAGER install -y epel-release 2>/dev/null || true
            fi
            ;;
        arch)
            pacman -Sy --noconfirm --needed \
                curl \
                base-devel \
                openssl \
                libffi
            ;;
        suse)
            zypper install -y \
                curl \
                ca-certificates \
                gcc \
                gcc-c++ \
                make \
                libffi-devel \
                libopenssl-devel
            ;;
    esac

    log_info "System dependencies installed"
}

# ---------- Python ----------
get_python_bin() {
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
    return 1
}

install_python() {
    local python_bin
    if python_bin=$(get_python_bin); then
        local ver
        ver=$("$python_bin" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        log_info "Python $ver found at $(command -v "$python_bin")"
        PYTHON_BIN="$python_bin"
        return
    fi

    log_step "Python 3.10+ not found. Installing via $PKG_MANAGER..."

    case "$DISTRO" in
        debian)
            # Try the distro's default python3 first
            apt-get install -y python3 python3-venv python3-pip python3-dev 2>/dev/null || true
            if python_bin=$(get_python_bin); then
                PYTHON_BIN="$python_bin"
                local ver
                ver=$("$python_bin" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
                log_info "Python $ver installed"
                return
            fi

            # If distro default is too old, use deadsnakes PPA (Ubuntu)
            if command -v add-apt-repository &>/dev/null; then
                log_step "Adding deadsnakes PPA for newer Python..."
                apt-get install -y software-properties-common
                add-apt-repository -y ppa:deadsnakes/ppa
                apt-get update -y
                apt-get install -y python3.12 python3.12-venv python3.12-dev
            else
                # Debian: try installing specific versions
                for pyver in python3.12 python3.11 python3.10; do
                    apt-get install -y "$pyver" "${pyver}-venv" "${pyver}-dev" 2>/dev/null && break || true
                done
            fi
            ;;
        fedora)
            dnf install -y python3 python3-pip python3-devel
            ;;
        rhel)
            # Try default python3
            $PKG_MANAGER install -y python3 python3-pip python3-devel 2>/dev/null || true
            if python_bin=$(get_python_bin); then
                PYTHON_BIN="$python_bin"
                return
            fi
            # Try specific versions
            for pyver in python3.12 python3.11 python3.10; do
                $PKG_MANAGER install -y "$pyver" "${pyver}-pip" "${pyver}-devel" 2>/dev/null && break || true
            done
            ;;
        arch)
            pacman -Sy --noconfirm python python-pip
            ;;
        suse)
            zypper install -y python3 python3-pip python3-devel
            ;;
    esac

    if python_bin=$(get_python_bin); then
        local ver
        ver=$("$python_bin" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        log_info "Python $ver installed at $(command -v "$python_bin")"
        PYTHON_BIN="$python_bin"
        return
    fi

    log_error "Failed to install Python 3.10+."
    log_error "Please install manually and re-run this script."
    log_error "  Debian/Ubuntu: sudo apt install python3.12 python3.12-venv python3.12-dev"
    log_error "  Fedora:        sudo dnf install python3.12"
    log_error "  RHEL/CentOS:   sudo dnf install python3.12"
    log_error "  Arch:          sudo pacman -S python"
    exit 1
}

# ---------- Verify venv module ----------
ensure_venv_module() {
    if "$PYTHON_BIN" -m venv --help &>/dev/null; then
        log_info "Python venv module available"
        return
    fi

    log_step "Python venv module not available. Installing..."

    local pyver
    pyver=$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')

    case "$DISTRO" in
        debian)
            apt-get install -y "python${pyver}-venv" 2>/dev/null || \
            apt-get install -y python3-venv 2>/dev/null || true
            ;;
        fedora|rhel)
            $PKG_MANAGER install -y python3-libs 2>/dev/null || true
            ;;
        arch)
            pacman -Sy --noconfirm python 2>/dev/null || true
            ;;
        suse)
            zypper install -y python3 2>/dev/null || true
            ;;
    esac

    if ! "$PYTHON_BIN" -m venv --help &>/dev/null; then
        log_error "Cannot get venv module working."
        log_error "Try: apt install python3-venv  OR  dnf install python3-libs"
        exit 1
    fi
    log_info "Python venv module installed"
}

# ---------- Verify pip ----------
ensure_pip() {
    if "$PYTHON_BIN" -m pip --version &>/dev/null; then
        log_info "pip available"
        return
    fi

    log_step "pip not found. Installing..."

    case "$DISTRO" in
        debian)
            apt-get install -y python3-pip 2>/dev/null || true
            ;;
        fedora|rhel)
            $PKG_MANAGER install -y python3-pip 2>/dev/null || true
            ;;
        arch)
            pacman -Sy --noconfirm python-pip 2>/dev/null || true
            ;;
        suse)
            zypper install -y python3-pip 2>/dev/null || true
            ;;
    esac

    if "$PYTHON_BIN" -m pip --version &>/dev/null; then
        log_info "pip installed via package manager"
        return
    fi

    log_step "Falling back to get-pip.py..."
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

# ---------- Verify systemd ----------
check_systemd() {
    if ! command -v systemctl &>/dev/null; then
        log_error "systemd is required but not found."
        log_error "SafeSkillAgent requires systemd for service management on Linux."
        exit 1
    fi
    log_info "systemd available"
}

# ---------- Create service user ----------
create_user() {
    if id -u safeskill &>/dev/null; then
        log_info "User 'safeskill' already exists"
        return
    fi

    log_step "Creating safeskill system user..."
    useradd --system --shell /usr/sbin/nologin --home-dir /etc/safeskill \
        --comment "SafeSkillAgent service account" safeskill
    log_info "User 'safeskill' created"
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

    chown -R root:safeskill "$CONFIG_DIR"
    chmod 750 "$CONFIG_DIR"
    find "$CONFIG_DIR" -name "*.yaml" -exec chmod 640 {} \;

    chown -R safeskill:safeskill "$LOG_DIR"
    chmod 700 "$LOG_DIR"

    log_info "Config ready at $CONFIG_DIR"
}

# ---------- systemd ----------
install_systemd() {
    log_step "Installing systemd service..."

    if systemctl is-active --quiet safeskill-agent 2>/dev/null; then
        log_warn "Stopping existing agent..."
        systemctl stop safeskill-agent
    fi

    cp "$SERVICE_SRC" "$SERVICE_DST"
    chmod 644 "$SERVICE_DST"

    systemctl daemon-reload
    systemctl enable safeskill-agent

    log_info "Starting SafeSkillAgent..."
    systemctl start safeskill-agent

    sleep 2
    if systemctl is-active --quiet safeskill-agent; then
        log_info "SafeSkillAgent is running"
    else
        log_warn "Agent may not have started. Check: journalctl -u safeskill-agent -e"
    fi
}

# ---------- logrotate ----------
setup_logrotate() {
    if ! command -v logrotate &>/dev/null; then
        log_step "Installing logrotate..."
        case "$DISTRO" in
            debian)     apt-get install -y logrotate ;;
            fedora|rhel) $PKG_MANAGER install -y logrotate ;;
            arch)       pacman -Sy --noconfirm logrotate ;;
            suse)       zypper install -y logrotate ;;
        esac
    fi

    log_step "Setting up log rotation..."
    cat > /etc/logrotate.d/safeskill << 'LOGROTATE'
/var/log/safeskill/*.jsonl {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0600 safeskill safeskill
    sharedscripts
    postrotate
        systemctl reload safeskill-agent 2>/dev/null || true
    endscript
}
LOGROTATE
    log_info "Log rotation configured"
}

# ---------- Clone source repo for auto-updates ----------
install_git_source() {
    local src_dir="/opt/safeskill/src"

    log_step "Setting up source repo for auto-updates..."

    if ! command -v git &>/dev/null; then
        case "$DISTRO" in
            debian)     apt-get install -y git ;;
            fedora|rhel) $PKG_MANAGER install -y git ;;
            arch)       pacman -Sy --noconfirm git ;;
            suse)       zypper install -y git ;;
        esac
    fi

    if [[ -d "$src_dir/.git" ]]; then
        log_info "Source repo already exists at $src_dir"
        cd "$src_dir" && git pull --quiet 2>/dev/null || true
        return
    fi

    # If we're running from a git repo, clone from its remote
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

    # Fallback: copy the current project
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

    local updater_service="$SCRIPT_DIR/safeskill-updater.service"
    local updater_timer="$SCRIPT_DIR/safeskill-updater.timer"

    if [[ ! -f "$updater_service" ]] || [[ ! -f "$updater_timer" ]]; then
        log_warn "Updater service/timer files not found. Skipping."
        return
    fi

    cp "$updater_service" /etc/systemd/system/safeskill-updater.service
    cp "$updater_timer" /etc/systemd/system/safeskill-updater.timer
    chmod 644 /etc/systemd/system/safeskill-updater.service
    chmod 644 /etc/systemd/system/safeskill-updater.timer

    chmod +x /opt/safeskill/src/setup/update.sh 2>/dev/null || true

    systemctl daemon-reload
    systemctl enable safeskill-updater.timer
    systemctl start safeskill-updater.timer

    log_info "Auto-update timer enabled (checks every 30 min)"
    log_info "Check timer status: systemctl list-timers safeskill-updater.timer"
}

# ---------- OpenClaw integration ----------
integrate_openclaw() {
    local openclaw_dir="${OPENCLAW_HOME:-$HOME/.openclaw}"
    local integration_script="$SCRIPT_DIR/../openclaw-skill/install.sh"

    if [[ ! -f "$integration_script" ]]; then
        log_warn "OpenClaw integration script not found. Skipping."
        return
    fi

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
    echo "   SafeSkillAgent Linux Installer (Full)"
    echo "============================================"
    echo ""
    echo "This installer will set up everything needed"
    echo "on a fresh Linux machine, including:"
    echo "  - System build dependencies (gcc, libffi, openssl)"
    echo "  - Python 3.10+ (via distro package manager)"
    echo "  - pip, venv module"
    echo "  - All Python dependencies (in isolated venv)"
    echo "  - Dedicated 'safeskill' system user"
    echo "  - Hardened systemd service"
    echo "  - Log rotation"
    echo ""
    echo "Supported distros: Debian, Ubuntu, Fedora,"
    echo "  RHEL, CentOS, Rocky, Alma, Arch, openSUSE"
    echo ""

    check_root
    detect_distro
    install_system_packages
    install_python
    ensure_venv_module
    ensure_pip
    check_systemd
    create_user
    install_agent
    setup_config
    install_systemd
    setup_logrotate
    install_git_source
    install_updater_timer
    integrate_openclaw

    echo ""
    echo "============================================"
    log_info "Installation complete!"
    echo "============================================"
    echo ""
    echo "  Distro:  $DISTRO ($PKG_MANAGER)"
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
    echo "Service management:"
    echo "  systemctl status safeskill-agent"
    echo "  systemctl restart safeskill-agent"
    echo "  journalctl -u safeskill-agent -f"
    echo ""
    echo "OpenClaw integration:"
    echo "  Restart OpenClaw to activate: openclaw stop && openclaw start"
    echo ""
}

main "$@"
