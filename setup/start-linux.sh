#!/usr/bin/env bash
# SafeSkill start-linux.sh — Step 2 of 2 (Linux)
#
# Wires SafeSkill into OpenClaw via NODE_OPTIONS preload hook.
# Run after: sudo bash setup/install-linux.sh
#
# What this does:
#   1. Copies safeskill-hook.js to ~/.openclaw/
#   2. Injects NODE_OPTIONS into OpenClaw's environment
#   3. Restarts OpenClaw gateway so the hook takes effect
#
# Does NOT require sudo.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
HOOK_SRC="$SCRIPT_DIR/openclaw-skill/safeskill-hook.js"
HOOK_DST="$HOME/.openclaw/safeskill-hook.js"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
step() { echo -e "${CYAN}[>>]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()  { echo -e "${RED}[ERR]${NC} $*" >&2; exit 1; }

echo ""
echo "======================================="
echo "  SafeSkill — Wire Hook into OpenClaw (Step 2 of 2)"
echo "  Platform: Linux (systemd)"
echo "======================================="
echo ""

# ── 1. Verify prerequisites ────────────────────────────────────────────────
step "1. Checking prerequisites..."

[[ -f "$HOOK_SRC" ]] || die "Hook not found at $HOOK_SRC"
[[ -S "/var/run/safeskill/safeskill.sock" ]] || \
    warn "SafeSkill daemon socket not found — run setup first: sudo bash setup/install-linux.sh"

if ! command -v openclaw &>/dev/null; then
    warn "'openclaw' command not in PATH — will try to find it"
fi

ok "Prerequisites OK"

# ── 2. Install hook file ───────────────────────────────────────────────────
step "2. Installing hook file..."
mkdir -p "$HOME/.openclaw"
cp "$HOOK_SRC" "$HOOK_DST"
ok "Hook installed: $HOOK_DST"

# ── 3. Inject NODE_OPTIONS into OpenClaw environment ──────────────────────
step "3. Configuring NODE_OPTIONS for OpenClaw..."

NODE_OPT="--require $HOOK_DST"

# Strategy: find where OpenClaw gets its environment and inject NODE_OPTIONS.
# On Linux, OpenClaw can run as:
#   a) systemd user service  (~/.config/systemd/user/openclaw-gateway.service)
#   b) systemd system service (/etc/systemd/system/openclaw*.service)
#   c) Process managed by a shell wrapper or started manually
#
# We try all known methods and at minimum set it in shell profile.

INJECTED=false

# --- Method A: systemd user service ---
USER_SERVICE_DIR="$HOME/.config/systemd/user"
for svc_name in openclaw-gateway openclaw ai.openclaw.gateway; do
    svc_file="$USER_SERVICE_DIR/${svc_name}.service"
    if [[ -f "$svc_file" ]]; then
        step "  Found user service: $svc_file"
        override_dir="$USER_SERVICE_DIR/${svc_name}.service.d"
        mkdir -p "$override_dir"
        cat > "$override_dir/safeskill.conf" <<OVERRIDE
[Service]
Environment=NODE_OPTIONS=$NODE_OPT
Environment=SAFESKILL_SOCKET=/var/run/safeskill/safeskill.sock
OVERRIDE
        systemctl --user daemon-reload 2>/dev/null || true
        ok "NODE_OPTIONS injected via systemd user override ($override_dir/safeskill.conf)"
        INJECTED=true
        break
    fi
done

# --- Method B: systemd system service ---
if ! $INJECTED; then
    for svc_name in openclaw-gateway openclaw ai.openclaw.gateway; do
        svc_file="/etc/systemd/system/${svc_name}.service"
        if [[ -f "$svc_file" ]]; then
            step "  Found system service: $svc_file"
            if [[ "$(id -u)" -eq 0 ]]; then
                override_dir="/etc/systemd/system/${svc_name}.service.d"
                mkdir -p "$override_dir"
                cat > "$override_dir/safeskill.conf" <<OVERRIDE
[Service]
Environment=NODE_OPTIONS=$NODE_OPT
Environment=SAFESKILL_SOCKET=/var/run/safeskill/safeskill.sock
OVERRIDE
                systemctl daemon-reload 2>/dev/null || true
                ok "NODE_OPTIONS injected via systemd system override ($override_dir/safeskill.conf)"
                INJECTED=true
            else
                warn "System service found but need sudo to create override"
                warn "Run: sudo bash $0"
            fi
            break
        fi
    done
fi

# --- Method C: OpenClaw config file (~/.openclaw/openclaw.json) ---
if ! $INJECTED; then
    OC_CONFIG="$HOME/.openclaw/openclaw.json"
    if [[ -f "$OC_CONFIG" ]]; then
        step "  Found OpenClaw config: $OC_CONFIG"
        if command -v python3 &>/dev/null; then
            python3 << PYINJECT
import json, sys, os

config_path = os.path.expanduser('$OC_CONFIG')
with open(config_path, 'r') as f:
    config = json.load(f)

if 'env' not in config:
    config['env'] = {}

config['env']['NODE_OPTIONS'] = '$NODE_OPT'
config['env']['SAFESKILL_SOCKET'] = '/var/run/safeskill/safeskill.sock'

# Remove old bash-layer vars
for key in ['SHELL', 'BASH_ENV', 'SAFESKILL_REAL_SHELL']:
    config['env'].pop(key, None)

with open(config_path, 'w') as f:
    json.dump(config, f, indent=2)
    f.write('\n')

print('OK')
PYINJECT
            ok "NODE_OPTIONS injected into $OC_CONFIG"
            INJECTED=true
        else
            warn "python3 not available — cannot update openclaw.json"
        fi
    fi
fi

# --- Method D: Shell profile fallback ---
# Always write to profile as a safety net — ensures NODE_OPTIONS is set
# if OpenClaw is started from a login shell.
PROFILE_FILE="$HOME/.profile"
[[ -f "$HOME/.bashrc" ]] && PROFILE_FILE="$HOME/.bashrc"
[[ -f "$HOME/.zshrc" ]] && PROFILE_FILE="$HOME/.zshrc"

MARKER="# SafeSkill NODE_OPTIONS hook"
if ! grep -q "$MARKER" "$PROFILE_FILE" 2>/dev/null; then
    cat >> "$PROFILE_FILE" <<PROFILE

$MARKER
export NODE_OPTIONS="$NODE_OPT"
export SAFESKILL_SOCKET="/var/run/safeskill/safeskill.sock"
PROFILE
    ok "NODE_OPTIONS added to $PROFILE_FILE (fallback for manual starts)"
else
    # Update existing entry
    python3 -c "
import re, pathlib
p = pathlib.Path('$PROFILE_FILE')
c = p.read_text()
c = re.sub(r'export NODE_OPTIONS=.*', 'export NODE_OPTIONS=\"$NODE_OPT\"', c)
p.write_text(c)
" 2>/dev/null || true
    ok "NODE_OPTIONS updated in $PROFILE_FILE"
fi

if ! $INJECTED; then
    warn "No systemd service or openclaw.json found for OpenClaw"
    warn "NODE_OPTIONS set in $PROFILE_FILE — will apply when OpenClaw starts from a shell"
    warn "If OpenClaw runs via systemd, create a service override manually:"
    warn "  sudo systemctl edit openclaw-gateway"
    warn "  [Service]"
    warn "  Environment=NODE_OPTIONS=$NODE_OPT"
fi

# ── 4. Restart OpenClaw gateway ───────────────────────────────────────────
step "4. Restarting OpenClaw gateway..."

RESTARTED=false

# Try openclaw CLI
if command -v openclaw &>/dev/null; then
    openclaw gateway stop 2>/dev/null || true
    sleep 2
    openclaw gateway start 2>/dev/null &
    sleep 3
    RESTARTED=true
    ok "Restarted via 'openclaw' CLI"
fi

# Try systemd user service
if ! $RESTARTED; then
    for svc_name in openclaw-gateway openclaw ai.openclaw.gateway; do
        if systemctl --user is-enabled "$svc_name" &>/dev/null; then
            systemctl --user restart "$svc_name"
            sleep 3
            RESTARTED=true
            ok "Restarted via systemctl --user restart $svc_name"
            break
        fi
    done
fi

# Try systemd system service
if ! $RESTARTED && [[ "$(id -u)" -eq 0 ]]; then
    for svc_name in openclaw-gateway openclaw ai.openclaw.gateway; do
        if systemctl is-enabled "$svc_name" &>/dev/null; then
            systemctl restart "$svc_name"
            sleep 3
            RESTARTED=true
            ok "Restarted via systemctl restart $svc_name"
            break
        fi
    done
fi

if ! $RESTARTED; then
    warn "Could not auto-restart OpenClaw gateway"
    warn "Restart it manually so the hook takes effect"
fi

# ── 5. Verify hook is active ─────────────────────────────────────────────
step "5. Verifying hook..."

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
echo ""
echo "Monitor audit log:"
echo "  sudo bash setup/monitor-audit.sh"
echo ""
echo "Restart daemon if needed:"
echo "  sudo systemctl restart safeskill"
echo "======================================="
echo ""
