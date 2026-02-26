#!/usr/bin/env bash
# SafeSkill finalize-install.sh
# Run with sudo: sudo bash scripts/finalize-install.sh
#
# Completes the system-level setup that requires root:
#   1. Creates /etc/safeskill/ config directory
#   2. Loads LaunchDaemon for auto-start on reboot
#   3. Makes audit logs readable by the current user
#
# Safe to run on an already-running system — it stops the manually-started
# daemon, then hands control to launchd, which restarts it immediately.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run as root: sudo bash $0" >&2
    exit 1
fi

REAL_USER="${SUDO_USER:-${USER:-$(logname 2>/dev/null || echo '')}}"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_DIR="/etc/safeskill"
LOG_DIR="/var/log/safeskill"
PLIST_DST="/Library/LaunchDaemons/com.safeskill.agent.plist"
PLIST_SRC="$SCRIPT_DIR/setup/com.safeskill.agent.plist"
VENV_SAFESKILL="/opt/safeskill/venv/bin/safeskill"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
step() { echo -e "${CYAN}[>>]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

echo ""
echo "==========================================="
echo "  SafeSkill — Finalize System Installation"
echo "==========================================="
echo ""

# 1. Config directory
step "1. Setting up /etc/safeskill config directory..."
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

# Write agent.yaml with hostname/user info for audit log metadata
hname=$(hostname 2>/dev/null || uname -n)
ip=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "127.0.0.1")
agent_yaml="$CONFIG_DIR/agent.yaml"
if [[ ! -f "$agent_yaml" ]]; then
    printf "default_hostname: %s\ndefault_user: %s\ndefault_source_ip: %s\n" \
        "$hname" "$REAL_USER" "$ip" > "$agent_yaml"
fi

# Admin token for protected endpoints
if [[ ! -f "$CONFIG_DIR/admin.token" ]]; then
    python3 -c "import secrets; print(secrets.token_urlsafe(32))" > "$CONFIG_DIR/admin.token"
    chmod 600 "$CONFIG_DIR/admin.token"
    ok "Admin token created at $CONFIG_DIR/admin.token"
fi

chown -R root:wheel "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"
chmod 640 "$CONFIG_DIR"/*.yaml 2>/dev/null || true
[[ -f "$CONFIG_DIR/admin.token" ]] && chmod 600 "$CONFIG_DIR/admin.token"

ok "Config directory ready"

# 2. Audit log permissions — readable by the user who installed
step "2. Fixing audit log permissions..."
if [[ -d "$LOG_DIR" ]]; then
    # Make log dir readable by staff group (all standard macOS users)
    chown -R root:staff "$LOG_DIR"
    chmod -N "$LOG_DIR" 2>/dev/null || true
    chmod 750 "$LOG_DIR"
    # Make existing audit files group-readable
    find "$LOG_DIR" -name "audit-*.jsonl" -exec chmod 640 {} \; 2>/dev/null || true
    ok "Audit logs readable by staff group ($LOG_DIR)"
else
    mkdir -p "$LOG_DIR"
    chown root:staff "$LOG_DIR"
    chmod 750 "$LOG_DIR"
    ok "Created $LOG_DIR"
fi

# 3. LaunchDaemon — stop manual process, let launchd own it
step "3. Transitioning daemon to launchd control..."

# Kill any manually-started daemon
if pgrep -f "safeskill-agent start" &>/dev/null; then
    warn "Stopping manually-started daemon..."
    pkill -f "safeskill-agent start" || true
    sleep 1
    ok "Manual daemon stopped"
fi

# Install/update plist
if [[ -f "$PLIST_SRC" ]]; then
    cp "$PLIST_SRC" "$PLIST_DST"
else
    warn "Plist source not found at $PLIST_SRC — using existing $PLIST_DST"
fi
chown root:wheel "$PLIST_DST"
chmod 644 "$PLIST_DST"

# Load (or reload) the LaunchDaemon
if launchctl list 2>/dev/null | grep -q "com.safeskill.agent"; then
    launchctl unload "$PLIST_DST" 2>/dev/null || true
    sleep 1
fi
launchctl load -w "$PLIST_DST"
sleep 2

if launchctl list 2>/dev/null | grep -q "com.safeskill.agent"; then
    ok "SafeSkillAgent running under launchd (auto-starts on reboot)"
else
    warn "Daemon may not have started — check: sudo launchctl list | grep safeskill"
    warn "If it failed: sudo launchctl list com.safeskill.agent"
fi

# 4. Verify socket
step "4. Verifying socket..."
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
ok "Finalize complete!"
echo ""
echo "  Config:    $CONFIG_DIR"
echo "  Logs:      $LOG_DIR  (readable by staff group)"
echo "  Socket:    /var/run/safeskill/safeskill.sock"
echo "  LaunchD:   auto-start on reboot enabled"
echo ""
echo "View audit logs:"
echo "  tail -f $LOG_DIR/audit-\$(date +%Y-%m-%d).jsonl"
echo ""
echo "Verify interception:"
echo "  bash openclaw-skill/verify-interception.sh"
echo "==========================================="
echo ""
