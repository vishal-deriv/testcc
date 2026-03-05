#!/usr/bin/env bash
# SafeSkill install-linux.sh — Step 1 of 2 (Linux)
#
# Installs the SafeSkill daemon (venv, binary, config, systemd).
# Run with sudo: sudo bash setup/install-linux.sh
#
# After this, run: bash setup/start-linux.sh  (wires hook into OpenClaw)
#
# What this does:
#   1. Creates Python venv at /opt/safeskill/venv
#   2. Installs safeskill-agent package from project
#   3. Symlinks /usr/local/bin/safeskill-agent
#   4. Creates /etc/safeskill config directory
#   5. Installs systemd service for auto-start on reboot
#   6. Makes audit logs readable by adm group

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run as root: sudo bash $0" >&2
    exit 1
fi

REAL_USER="${SUDO_USER:-${USER:-$(logname 2>/dev/null || echo '')}}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_DIR="/etc/safeskill"
LOG_DIR="/var/log/safeskill"
RUN_DIR="/var/run/safeskill"
VENV_DIR="/opt/safeskill/venv"
BIN_SYMLINK="/usr/local/bin/safeskill-agent"
SERVICE_SRC="$SCRIPT_DIR/safeskill.service"
SERVICE_DST="/etc/systemd/system/safeskill.service"
VENV_SAFESKILL="$VENV_DIR/bin/safeskill"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
step() { echo -e "${CYAN}[>>]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

echo ""
echo "==========================================="
echo "  SafeSkill — Install Daemon (Step 1 of 2)"
echo "  Platform: Linux (systemd)"
echo "==========================================="
echo ""

# ── 0. Check prerequisites ─────────────────────────────────────────────────
step "0. Checking prerequisites..."

if ! command -v python3 &>/dev/null; then
    echo "python3 not found. Installing..." >&2
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq python3 python3-venv python3-pip curl
    elif command -v dnf &>/dev/null; then
        dnf install -y -q python3 python3-pip curl
    elif command -v yum &>/dev/null; then
        yum install -y -q python3 python3-pip curl
    else
        echo "Cannot auto-install python3 — install manually and re-run" >&2
        exit 1
    fi
fi

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [[ "$PY_MAJOR" -lt 3 ]] || [[ "$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 10 ]]; then
    echo "Python 3.10+ required, found $PY_VER" >&2
    exit 1
fi

python3 -c "import venv" 2>/dev/null || {
    echo "python3-venv not found. Installing..." >&2
    if command -v apt-get &>/dev/null; then
        apt-get install -y -qq python3-venv
    fi
}

if ! command -v curl &>/dev/null; then
    echo "curl not found. Installing..." >&2
    if command -v apt-get &>/dev/null; then
        apt-get install -y -qq curl
    elif command -v dnf &>/dev/null; then
        dnf install -y -q curl
    fi
fi

if ! command -v systemctl &>/dev/null; then
    warn "systemd not found — daemon will install but won't auto-start"
fi

ok "Prerequisites OK (Python $PY_VER)"

# ── 1. Create venv and install package ─────────────────────────────────────
step "1. Creating venv and installing SafeSkill..."

mkdir -p /opt/safeskill
if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
    ok "Created $VENV_DIR"
else
    ok "Venv already exists: $VENV_DIR"
fi

"$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel -q
"$VENV_DIR/bin/pip" install -e "$PROJECT_DIR" -q
ok "Package installed"

# ── 2. Symlink binaries ───────────────────────────────────────────────────
step "2. Symlinking daemon and CLI binaries..."
mkdir -p /usr/local/bin
ln -sf "$VENV_DIR/bin/safeskill-agent" "$BIN_SYMLINK"
ln -sf "$VENV_DIR/bin/safeskill" /usr/local/bin/safeskill
ok "Symlinked $BIN_SYMLINK and /usr/local/bin/safeskill"

# ── 3. Config directory ──────────────────────────────────────────────────
step "3. Setting up /etc/safeskill config directory..."
if [[ ! -d "$CONFIG_DIR" ]]; then
    mkdir -p "$CONFIG_DIR/environments"
    ok "Created $CONFIG_DIR"
else
    ok "$CONFIG_DIR already exists"
fi

if [[ -x "$VENV_SAFESKILL" ]]; then
    SAFESKILL_INSTALL_DIR="$PROJECT_DIR" "$VENV_SAFESKILL" init --config-dir "$CONFIG_DIR" 2>/dev/null || true
    ok "Config initialized"
fi

if [[ ! -f "$CONFIG_DIR/base-policy.yaml" ]]; then
    warn "Policy files not installed by 'safeskill init' — copying manually"
    for f in base-policy.yaml runtime-policy.yaml signatures.yaml; do
        [[ -f "$PROJECT_DIR/safeskill/config/$f" ]] && cp "$PROJECT_DIR/safeskill/config/$f" "$CONFIG_DIR/"
    done
    for f in dev.yaml staging.yaml production.yaml; do
        [[ -f "$PROJECT_DIR/safeskill/config/environments/$f" ]] && cp "$PROJECT_DIR/safeskill/config/environments/$f" "$CONFIG_DIR/environments/"
    done
fi

hname=$(hostname 2>/dev/null || uname -n)
ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
agent_yaml="$CONFIG_DIR/agent.yaml"
if [[ ! -f "$agent_yaml" ]]; then
    printf "default_hostname: %s\ndefault_user: %s\ndefault_source_ip: %s\n" \
        "$hname" "$REAL_USER" "$ip" > "$agent_yaml"
fi

if [[ ! -f "$CONFIG_DIR/admin.token" ]]; then
    python3 -c "import secrets; print(secrets.token_urlsafe(32))" > "$CONFIG_DIR/admin.token"
    chmod 600 "$CONFIG_DIR/admin.token"
    ok "Admin token created"
fi

chown -R root:root "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"
chmod 640 "$CONFIG_DIR"/*.yaml 2>/dev/null || true
[[ -f "$CONFIG_DIR/admin.token" ]] && chmod 600 "$CONFIG_DIR/admin.token"
ok "Config directory ready"

# ── 4. Audit log directory ───────────────────────────────────────────────
step "4. Setting up audit log directory..."

LOG_GROUP="adm"
getent group adm &>/dev/null || LOG_GROUP="root"

if [[ -d "$LOG_DIR" ]]; then
    chown -R "root:$LOG_GROUP" "$LOG_DIR"
    chmod 750 "$LOG_DIR"
    find "$LOG_DIR" -name "audit-*.jsonl" -exec chmod 640 {} \; 2>/dev/null || true
    ok "Audit logs readable by $LOG_GROUP group ($LOG_DIR)"
else
    mkdir -p "$LOG_DIR"
    chown "root:$LOG_GROUP" "$LOG_DIR"
    chmod 750 "$LOG_DIR"
    ok "Created $LOG_DIR"
fi

# ── 5. Runtime directory ─────────────────────────────────────────────────
step "5. Setting up runtime directory..."
mkdir -p "$RUN_DIR"
chown root:root "$RUN_DIR"
chmod 755 "$RUN_DIR"
ok "Runtime directory ready ($RUN_DIR)"

# ── 6. systemd service ──────────────────────────────────────────────────
step "6. Installing systemd service..."

if pgrep -f "safeskill-agent start" &>/dev/null; then
    warn "Stopping manually-started daemon..."
    pkill -f "safeskill-agent start" || true
    sleep 1
fi

if [[ -f "$SERVICE_SRC" ]]; then
    cp "$SERVICE_SRC" "$SERVICE_DST"
else
    warn "Service file not found at $SERVICE_SRC — generating inline"
    cat > "$SERVICE_DST" <<'UNIT'
[Unit]
Description=SafeSkill Command Security Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/safeskill-agent start --config-dir /etc/safeskill --log-dir /var/log/safeskill --socket /var/run/safeskill/safeskill.sock
Restart=on-failure
RestartSec=10
Environment=SAFESKILL_TRUST_MODE=normal
Environment=SAFESKILL_ENVIRONMENT=production
WorkingDirectory=/etc/safeskill
StandardOutput=append:/var/log/safeskill/agent-stdout.log
StandardError=append:/var/log/safeskill/agent-stderr.log
LimitNOFILE=1024

RuntimeDirectory=safeskill
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
UNIT
fi

if command -v systemctl &>/dev/null; then
    systemctl daemon-reload
    systemctl enable safeskill.service
    systemctl restart safeskill.service
    sleep 2

    if systemctl is-active --quiet safeskill.service; then
        ok "SafeSkill daemon running (auto-starts on reboot)"
    else
        warn "Daemon may not have started — check: sudo systemctl status safeskill"
        warn "Logs: sudo journalctl -u safeskill -n 20"
    fi
else
    warn "systemd not available — start daemon manually: /usr/local/bin/safeskill-agent start &"
fi

# ── 7. Verify socket ────────────────────────────────────────────────────
step "7. Verifying socket..."
for i in 1 2 3 4 5; do
    if [[ -S /var/run/safeskill/safeskill.sock ]]; then
        ok "Socket ready: /var/run/safeskill/safeskill.sock"
        break
    fi
    sleep 1
done
[[ -S /var/run/safeskill/safeskill.sock ]] || warn "Socket not yet available — daemon may still be starting"

# ── 8. Smoke test ────────────────────────────────────────────────────────
step "8. Running smoke test..."

if [[ -S /var/run/safeskill/safeskill.sock ]]; then
    if /usr/local/bin/safeskill check whoami &>/dev/null; then
        ok "PASS — 'whoami' allowed"
    else
        warn "FAIL — 'whoami' blocked or daemon unreachable"
    fi

    if ! /usr/local/bin/safeskill check 'cat /etc/passwd' &>/dev/null; then
        ok "PASS — 'cat /etc/passwd' blocked"
    else
        warn "FAIL — 'cat /etc/passwd' was NOT blocked"
    fi
else
    warn "Socket not ready — skipping smoke test"
fi

echo ""
echo "==========================================="
ok "Install complete! (Step 1 of 2)"
echo ""
echo "  Config:    $CONFIG_DIR"
echo "  Logs:      $LOG_DIR"
echo "  Socket:    /var/run/safeskill/safeskill.sock"
echo "  Service:   sudo systemctl status safeskill"
echo ""
echo "Next step — wire hook into OpenClaw:"
echo "  bash setup/start-linux.sh"
echo "==========================================="
echo ""
