#!/usr/bin/env bash
set -euo pipefail

# SafeSkillAgent macOS Uninstaller

PLIST_DST="/Library/LaunchDaemons/com.safeskill.agent.plist"
CONFIG_DIR="/etc/safeskill"
LOG_DIR="/var/log/safeskill"
VENV_DIR="/opt/safeskill/venv"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR]${NC} This uninstaller must be run as root (use sudo)"
        exit 1
    fi
}

main() {
    echo "========================================"
    echo "  SafeSkillAgent macOS Uninstaller"
    echo "========================================"
    echo ""

    check_root

    if launchctl list 2>/dev/null | grep -q "com.safeskill.agent"; then
        log_info "Stopping agent..."
        launchctl unload -w "$PLIST_DST" 2>/dev/null || true
    fi

    if [[ -f "$PLIST_DST" ]]; then
        log_info "Removing LaunchDaemon plist..."
        rm -f "$PLIST_DST"
    fi

    if [[ -L /usr/local/bin/safeskill ]]; then
        log_info "Removing symlinks..."
        rm -f /usr/local/bin/safeskill
        rm -f /usr/local/bin/safeskill-agent
    fi

    if [[ -d "$VENV_DIR" ]]; then
        log_info "Removing virtual environment..."
        rm -rf "$VENV_DIR"
    fi

    rm -f /tmp/safeskill.sock

    echo ""
    read -rp "Remove config ($CONFIG_DIR)? [y/N] " remove_config
    if [[ "$remove_config" =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
        log_info "Config removed"
    else
        log_warn "Config preserved at $CONFIG_DIR"
    fi

    read -rp "Remove logs ($LOG_DIR)? [y/N] " remove_logs
    if [[ "$remove_logs" =~ ^[Yy]$ ]]; then
        rm -rf "$LOG_DIR"
        log_info "Logs removed"
    else
        log_warn "Logs preserved at $LOG_DIR"
    fi

    echo ""
    log_info "SafeSkillAgent has been uninstalled."
}

main "$@"
