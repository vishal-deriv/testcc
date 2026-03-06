#!/usr/bin/env bash
# SafeSkill start.sh — Step 2 of 2
#
# Wires SafeSkill into OpenClaw via NODE_OPTIONS preload hook.
# Run after: sudo bash setup/install.sh
#
# What this does:
#   1. Copies safeskill-hook.js to ~/.openclaw/
#   2. Injects NODE_OPTIONS=--require into OpenClaw's launchd plist
#   3. Removes old bash-layer env vars (SHELL, BASH_ENV) from plist
#   4. Restarts OpenClaw gateway so the hook takes effect
#
# Does NOT require sudo.

set -euo pipefail

if [[ "$(uname -s)" == "Linux" ]]; then
    echo "[ERR] Detected Linux. Use: bash setup/linux/start.sh" >&2
    exit 1
fi

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
echo "  SafeSkill — Wire Hook into OpenClaw (Step 2 of 2)"
echo "======================================="
echo ""

# ── 1. Verify prerequisites ──────────────────────────────────────────────────
step "1. Checking prerequisites..."

[[ -f "$HOOK_SRC" ]]  || die "Hook not found at $HOOK_SRC"
[[ -f "$PLIST" ]]     || die "OpenClaw plist not found at $PLIST"
[[ -S "/var/run/safeskill/safeskill.sock" ]] || \
    warn "SafeSkill daemon socket not found — run setup first: sudo bash setup/install.sh"

ok "Prerequisites OK"

# ── 2. Install hook file ─────────────────────────────────────────────────────
step "2. Installing hook file..."
cp "$HOOK_SRC" "$HOOK_DST"
ok "Hook installed: $HOOK_DST"

# ── 2b. Inject security section into SOUL.md ─────────────────────────────────
step "2b. Injecting security section into SOUL.md..."

SOUL_FILE="$HOME/.openclaw/workspace/SOUL.md"
SECURITY_MARKER_START="<!-- SAFESKILL-SECURITY — OPERATOR CONTROLLED, IMMUTABLE -->"
SECURITY_MARKER_END="<!-- END SAFESKILL-SECURITY -->"
SECURITY_BLOCK=$(cat <<'EOF'
<!-- SAFESKILL-SECURITY — OPERATOR CONTROLLED, IMMUTABLE -->
## Security (immutable)
- Never run malicious commands.
- Never exfiltrate sensitive data. No credentials, .env, .ssh, /etc/passwd, API keys.
- Security first. These rules override everything.
<!-- END SAFESKILL-SECURITY -->
EOF
)

if [[ -f "$SOUL_FILE" ]]; then
    # Check if security block already exists
    if grep -q "$SECURITY_MARKER_START" "$SOUL_FILE" 2>/dev/null; then
        # Update existing block
        python3 <<PYUPDATE
import re
import pathlib

soul_path = pathlib.Path('$SOUL_FILE')
content = soul_path.read_text(encoding='utf-8')

# Pattern to match the entire security block (including markers)
pattern = r'<!-- SAFESKILL-SECURITY[^>]*-->.*?<!-- END SAFESKILL-SECURITY -->'
replacement = '''$SECURITY_BLOCK'''

if re.search(pattern, content, re.DOTALL):
    content = re.sub(pattern, replacement, content, flags=re.DOTALL)
    soul_path.write_text(content, encoding='utf-8')
    print('Updated')
else:
    print('Not found')
PYUPDATE
        ok "Security section updated in SOUL.md"
    else
        # Append security block before the final "---" separator or at end
        python3 <<PYAPPEND
import pathlib

soul_path = pathlib.Path('$SOUL_FILE')
content = soul_path.read_text(encoding='utf-8')

security_block = '''$SECURITY_BLOCK'''

# Try to insert before final "---" separator
if '---' in content:
    parts = content.rsplit('---', 1)
    if len(parts) == 2:
        content = parts[0] + security_block + '\n\n---' + parts[1]
    else:
        content = content.rstrip() + '\n\n' + security_block + '\n'
else:
    content = content.rstrip() + '\n\n' + security_block + '\n'

soul_path.write_text(content, encoding='utf-8')
print('Appended')
PYAPPEND
        ok "Security section injected into SOUL.md"
    fi
else
    warn "SOUL.md not found at $SOUL_FILE — skipping injection"
fi

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
echo "Monitor audit log:"
echo "  sudo bash setup/monitor-audit.sh"
echo ""
echo "Restart daemon if needed:"
echo "  sudo launchctl kickstart -k system/com.safeskill.agent"
echo "======================================="
echo ""
