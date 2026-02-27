#!/usr/bin/env bash
# SafeSkill install.sh — Step 1 of 2
#
# Installs the SafeSkill daemon (venv, binary, config, launchd).
# Run with sudo: sudo bash setup/install.sh
#
# After this, run: bash setup/start.sh  (wires hook into OpenClaw)
#
# What this does:
#   1. Creates Python venv at /opt/safeskill/venv
#   2. Installs safeskill-agent package from project
#   3. Symlinks /usr/local/bin/safeskill-agent
#   4. Creates /etc/safeskill config directory
#   5. Loads LaunchDaemon for auto-start on reboot
#   6. Makes audit logs readable by staff group

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
VENV_DIR="/opt/safeskill/venv"
BIN_SYMLINK="/usr/local/bin/safeskill-agent"
PLIST_DST="/Library/LaunchDaemons/com.safeskill.agent.plist"
PLIST_SRC="$SCRIPT_DIR/com.safeskill.agent.plist"
VENV_SAFESKILL="$VENV_DIR/bin/safeskill"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
step() { echo -e "${CYAN}[>>]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

echo ""
echo "==========================================="
echo "  SafeSkill — Install Daemon (Step 1 of 2)"
echo "==========================================="
echo ""

# ── 1. Create venv and install package ───────────────────────────────────────
step "1. Creating venv and installing SafeSkill..."

if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
    ok "Created $VENV_DIR"
else
    ok "Venv already exists: $VENV_DIR"
fi

"$VENV_DIR/bin/pip" install -e "$PROJECT_DIR" -q
ok "Package installed"

# ── 2. Symlink binary ───────────────────────────────────────────────────────
step "2. Symlinking daemon binary..."
mkdir -p /usr/local/bin
ln -sf "$VENV_DIR/bin/safeskill-agent" "$BIN_SYMLINK"
ok "Symlinked $BIN_SYMLINK"

# ── 3. Config directory ──────────────────────────────────────────────────────
step "3. Setting up /etc/safeskill config directory..."
if [[ ! -d "$CONFIG_DIR" ]]; then
    mkdir -p "$CONFIG_DIR/environments"
    ok "Created $CONFIG_DIR"
else
    ok "$CONFIG_DIR already exists"
fi

if [[ -x "$VENV_SAFESKILL" ]]; then
    "$VENV_SAFESKILL" init --config-dir "$CONFIG_DIR" 2>/dev/null || true
    ok "Config initialized"
fi

hname=$(hostname 2>/dev/null || uname -n)
ip=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "127.0.0.1")
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

chown -R root:wheel "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"
chmod 640 "$CONFIG_DIR"/*.yaml 2>/dev/null || true
[[ -f "$CONFIG_DIR/admin.token" ]] && chmod 600 "$CONFIG_DIR/admin.token"
ok "Config directory ready"

# ── 4. Audit log permissions ──────────────────────────────────────────────────
step "4. Setting up audit log directory..."
if [[ -d "$LOG_DIR" ]]; then
    chown -R root:staff "$LOG_DIR"
    chmod -N "$LOG_DIR" 2>/dev/null || true
    chmod 750 "$LOG_DIR"
    find "$LOG_DIR" -name "audit-*.jsonl" -exec chmod 640 {} \; 2>/dev/null || true
    ok "Audit logs readable by staff group ($LOG_DIR)"
else
    mkdir -p "$LOG_DIR"
    chown root:staff "$LOG_DIR"
    chmod 750 "$LOG_DIR"
    ok "Created $LOG_DIR"
fi

# ── 5. LaunchDaemon ──────────────────────────────────────────────────────────
step "5. Loading LaunchDaemon..."

if pgrep -f "safeskill-agent start" &>/dev/null; then
    warn "Stopping manually-started daemon..."
    pkill -f "safeskill-agent start" || true
    sleep 1
fi

if [[ -f "$PLIST_SRC" ]]; then
    cp "$PLIST_SRC" "$PLIST_DST"
else
    warn "Plist source not found at $PLIST_SRC"
fi
chown root:wheel "$PLIST_DST"
chmod 644 "$PLIST_DST"

if launchctl list 2>/dev/null | grep -q "com.safeskill.agent"; then
    launchctl unload "$PLIST_DST" 2>/dev/null || true
    sleep 1
fi
launchctl load -w "$PLIST_DST"
sleep 2

if launchctl list 2>/dev/null | grep -q "com.safeskill.agent"; then
    ok "SafeSkill daemon running (auto-starts on reboot)"
else
    warn "Daemon may not have started — check: sudo launchctl list | grep safeskill"
fi

# ── 6. Verify socket ────────────────────────────────────────────────────────
step "6. Verifying socket..."
for i in 1 2 3 4 5; do
    if [[ -S /var/run/safeskill/safeskill.sock ]]; then
        ok "Socket ready: /var/run/safeskill/safeskill.sock"
        break
    fi
    sleep 1
done
[[ -S /var/run/safeskill/safeskill.sock ]] || warn "Socket not yet available — daemon may still be starting"

echo ""
echo "==========================================="
ok "Install complete! (Step 1 of 2)"
echo ""
echo "  Config:    $CONFIG_DIR"
echo "  Logs:      $LOG_DIR"
echo "  Socket:    /var/run/safeskill/safeskill.sock"
echo ""
echo "Next step — wire hook into OpenClaw:"
echo "  bash setup/start.sh"
echo "==========================================="
echo ""
