#!/usr/bin/env bash
# SafeSkill start.sh
#
# Wires SafeSkill into OpenClaw via NODE_OPTIONS preload hook.
# Run once after installing OpenClaw. Safe to re-run.
#
# What this does:
#   1. Copies safeskill-hook.js to ~/.openclaw/
#   2. Injects NODE_OPTIONS=--require into OpenClaw's launchd plist
#   3. Removes old bash-layer env vars (SHELL, BASH_ENV) from plist
#   4. Restarts OpenClaw gateway so the hook takes effect
#
# Does NOT require sudo.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
HOOK_SRC="$SCRIPT_DIR/openclaw-skill/safeskill-hook.js"
HOOK_DST="$HOME/.openclaw/safeskill-hook.js"
PLIST="$HOME/Library/LaunchAgents/ai.openclaw.gateway.plist"
PB="/usr/libexec/PlistBuddy"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
step() { echo -e "${CYAN}[>>]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()  { echo -e "${RED}[ERR]${NC} $*" >&2; exit 1; }

echo ""
echo "======================================="
echo "  SafeSkill — Wire Hook into OpenClaw"
echo "======================================="
echo ""

# ── 1. Verify prerequisites ──────────────────────────────────────────────────
step "1. Checking prerequisites..."

[[ -f "$HOOK_SRC" ]]  || die "Hook not found at $HOOK_SRC"
[[ -f "$PLIST" ]]     || die "OpenClaw plist not found at $PLIST"
[[ -S "/var/run/safeskill/safeskill.sock" ]] || \
    warn "SafeSkill daemon socket not found — start daemon first: sudo launchctl load -w /Library/LaunchDaemons/com.safeskill.agent.plist"

ok "Prerequisites OK"

# ── 2. Install hook file ─────────────────────────────────────────────────────
step "2. Installing hook file..."
cp "$HOOK_SRC" "$HOOK_DST"
ok "Hook installed: $HOOK_DST"

# ── 3. Inject NODE_OPTIONS into plist ────────────────────────────────────────
step "3. Updating OpenClaw plist..."

NODE_OPT="--require $HOOK_DST"

# Add or update NODE_OPTIONS
if $PB -c "Print :EnvironmentVariables:NODE_OPTIONS" "$PLIST" &>/dev/null; then
    $PB -c "Set :EnvironmentVariables:NODE_OPTIONS '$NODE_OPT'" "$PLIST"
    ok "NODE_OPTIONS updated"
else
    $PB -c "Add :EnvironmentVariables:NODE_OPTIONS string '$NODE_OPT'" "$PLIST"
    ok "NODE_OPTIONS added"
fi

# Remove old bash-layer env vars (no longer needed)
for key in SHELL BASH_ENV SAFESKILL_REAL_SHELL; do
    if $PB -c "Print :EnvironmentVariables:$key" "$PLIST" &>/dev/null; then
        $PB -c "Delete :EnvironmentVariables:$key" "$PLIST"
        ok "Removed old env var: $key"
    fi
done

ok "Plist updated"

# ── 4. Restart OpenClaw gateway ──────────────────────────────────────────────
step "4. Restarting OpenClaw gateway..."

# Use openclaw's own stop command first to avoid port conflict,
# then reload via launchd so NODE_OPTIONS takes effect
openclaw gateway stop 2>/dev/null | grep -v "^$" || true
sleep 2
launchctl bootout "gui/$UID/ai.openclaw.gateway" 2>/dev/null || true
sleep 1
launchctl load -w "$PLIST"
sleep 3

# Verify it came back up
if launchctl list 2>/dev/null | grep -q "ai.openclaw.gateway"; then
    ok "OpenClaw gateway running"
else
    warn "Gateway may still be starting — check: launchctl list | grep openclaw"
fi

# ── 5. Verify hook is active ─────────────────────────────────────────────────
step "5. Verifying hook..."

# Quick smoke test: ask safeskill to check a harmless command
if safeskill check whoami &>/dev/null; then
    ok "SafeSkill daemon responding"
else
    warn "SafeSkill daemon not responding — commands will be blocked until it starts"
fi

echo ""
echo "======================================="
ok "SafeSkill is now wired into OpenClaw!"
echo ""
echo "  Hook:    $HOOK_DST"
echo "  Method:  NODE_OPTIONS preload (child_process interception)"
echo "  Layers:  1 (was 3 — bash wrapper/trap/shim removed)"
echo ""
echo "Monitor audit log (always uses most recent file):"
echo "  sudo tail -f \$(sudo ls -t /var/log/safeskill/audit-*.jsonl | head -1) | python3 -c \\"
echo "  \"import sys,json"
echo "  for l in sys.stdin:"
echo "    try:"
echo "      d=json.loads(l)"
echo "      if d.get('event_action')=='evaluate':"
echo "        print(d['event_timestamp'][:19], f\\\"[{d['event_outcome'].upper():7}]\\\", d.get('system_command',''))"
echo "    except: pass\""
echo ""
echo "Restart daemon if needed:"
echo "  sudo launchctl kickstart -k system/com.safeskill.agent"
echo "======================================="
echo ""
