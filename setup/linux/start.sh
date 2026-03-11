#!/usr/bin/env bash
# SafeSkill start.sh — Step 2 of 2 (Linux)
#
# Wires SafeSkill into OpenClaw via NODE_OPTIONS preload hook.
# Run after: sudo bash setup/linux/install.sh
#
# What this does:
#   1. Copies safeskill-hook.js to ~/.openclaw/
#   2. Injects NODE_OPTIONS into OpenClaw's environment
#   3. Restarts OpenClaw gateway so the hook takes effect
#
# Optional env:
#   OPENCLAW_PROFILE=<profile>   (default: main)
#
# Does NOT require sudo.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
HOOK_SRC="$PROJECT_DIR/openclaw-skill/safeskill-hook.js"
HOOK_DST="$HOME/.openclaw/safeskill-hook.js"
OPENCLAW_PROFILE="${OPENCLAW_PROFILE:-main}"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
step() { echo -e "${CYAN}[>>]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()  { echo -e "${RED}[ERR]${NC} $*" >&2; exit 1; }

wait_user_service_active() {
    local svc="$1"
    local tries="${2:-12}"
    local i
    for ((i=1; i<=tries; i++)); do
        if systemctl --user is-active --quiet "$svc"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

detect_user_gateway_service() {
    local svc_name
    for svc_name in "openclaw-gateway-${OPENCLAW_PROFILE}" openclaw-gateway openclaw ai.openclaw.gateway; do
        if systemctl --user cat "$svc_name" >/dev/null 2>&1 || [[ -f "$HOME/.config/systemd/user/${svc_name}.service" ]]; then
            echo "$svc_name"
            return 0
        fi
    done
    return 1
}

service_env_has_hook() {
    local svc="$1"
    local env_dump
    env_dump="$(systemctl --user show "$svc" --property=Environment --no-pager 2>/dev/null || true)"
    [[ "$env_dump" == *"NODE_OPTIONS=--require $HOOK_DST"* ]] && \
    [[ "$env_dump" == *"SAFESKILL_SOCKET=/var/run/safeskill/safeskill.sock"* ]]
}

read_gateway_port() {
    local cfg="$HOME/.openclaw/openclaw.json"
    if [[ -f "$cfg" ]] && command -v python3 >/dev/null 2>&1; then
        python3 - <<PYPORT 2>/dev/null || echo "18799"
import json
import os
p = os.path.expanduser("$cfg")
with open(p, "r", encoding="utf-8") as f:
    cfg = json.load(f)
port = cfg.get("gateway", {}).get("port", 18799)
print(int(port))
PYPORT
    else
        echo "18799"
    fi
}

is_port_listening_loopback() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -tln 2>/dev/null | grep -qE "127\.0\.0\.1:${port}\b|::1:${port}\b"
        return $?
    fi
    if command -v netstat >/dev/null 2>&1; then
        netstat -tln 2>/dev/null | grep -qE "127\.0\.0\.1\.${port}|127\.0\.0\.1:${port}|::1:${port}"
        return $?
    fi
    return 2
}

echo ""
echo "======================================="
echo "  SafeSkill — Wire Hook into OpenClaw (Step 2 of 2)"
echo "  Platform: Linux (systemd)"
echo "======================================="
echo ""

# -- 1. Verify prerequisites ------------------------------------------------
step "1. Checking prerequisites..."

[[ -f "$HOOK_SRC" ]] || die "Hook not found at $HOOK_SRC"
[[ -S "/var/run/safeskill/safeskill.sock" ]] || \
    warn "SafeSkill daemon socket not found — run setup first: sudo bash setup/linux/install.sh"

if ! command -v openclaw &>/dev/null; then
    warn "'openclaw' command not in PATH — will try to find it"
fi

ok "Prerequisites OK"

# -- 2. Install hook file ---------------------------------------------------
step "2. Installing hook file..."
mkdir -p "$HOME/.openclaw"
cp "$HOOK_SRC" "$HOOK_DST"
ok "Hook installed: $HOOK_DST"

# -- 2b. Inject security section into SOUL.md ------------------------------
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

# -- 3. Inject NODE_OPTIONS into OpenClaw environment -----------------------
step "3. Configuring NODE_OPTIONS for OpenClaw..."

NODE_OPT="--require $HOOK_DST"
SYSTEMD_USER_OK=false
if systemctl --user show-environment >/dev/null 2>&1; then
    SYSTEMD_USER_OK=true
fi

INJECTED=false

# Method A: systemd user service
USER_SERVICE_DIR="$HOME/.config/systemd/user"
if $SYSTEMD_USER_OK; then
    for svc_name in openclaw-gateway openclaw ai.openclaw.gateway "openclaw-gateway-${OPENCLAW_PROFILE}"; do
        svc_file="$USER_SERVICE_DIR/${svc_name}.service"
        if [[ -f "$svc_file" ]]; then
            step "  Found user service: $svc_file"
            override_dir="$USER_SERVICE_DIR/${svc_name}.service.d"
            mkdir -p "$override_dir"
            cat > "$override_dir/safeskill.conf" <<OVERRIDE
[Service]
Environment="NODE_OPTIONS=$NODE_OPT"
Environment=SAFESKILL_SOCKET=/var/run/safeskill/safeskill.sock
OVERRIDE
            systemctl --user daemon-reload 2>/dev/null || true
            ok "NODE_OPTIONS injected via systemd user override ($override_dir/safeskill.conf)"
            INJECTED=true
            break
        fi
    done
else
    warn "systemd --user bus unavailable in this session; skipping user service override"
fi

# Method B: systemd system service
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
Environment="NODE_OPTIONS=$NODE_OPT"
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

# Method C: OpenClaw config file
if ! $INJECTED; then
    OC_CONFIG="$HOME/.openclaw/openclaw.json"
    if [[ -f "$OC_CONFIG" ]]; then
        step "  Found OpenClaw config: $OC_CONFIG"
        if command -v python3 &>/dev/null; then
            python3 << PYINJECT
import json, os

config_path = os.path.expanduser('$OC_CONFIG')
with open(config_path, 'r', encoding='utf-8') as f:
    config = json.load(f)

if 'env' not in config:
    config['env'] = {}

config['env']['NODE_OPTIONS'] = '$NODE_OPT'
config['env']['SAFESKILL_SOCKET'] = '/var/run/safeskill/safeskill.sock'

for key in ['SHELL', 'BASH_ENV', 'SAFESKILL_REAL_SHELL']:
    config['env'].pop(key, None)

with open(config_path, 'w', encoding='utf-8') as f:
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

if ! $INJECTED; then
    # Method D: shell profile fallback (only when all managed injection methods fail)
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
        python3 -c "
import re, pathlib
p = pathlib.Path('$PROFILE_FILE')
c = p.read_text()
c = re.sub(r'export NODE_OPTIONS=.*', 'export NODE_OPTIONS=\"$NODE_OPT\"', c)
p.write_text(c)
" 2>/dev/null || true
        ok "NODE_OPTIONS updated in $PROFILE_FILE"
    fi

    warn "No systemd service or openclaw.json found for OpenClaw"
    warn "NODE_OPTIONS set in $PROFILE_FILE — will apply when OpenClaw starts from a shell"
    warn "If OpenClaw runs via systemd, create a service override manually:"
    warn "  sudo systemctl edit openclaw-gateway"
    warn "  [Service]"
    warn "  Environment=NODE_OPTIONS=$NODE_OPT"
else
    # Clean up stale shell fallback from older installs to avoid blocking `openclaw tui`.
    for profile in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        if [[ -f "$profile" ]] && grep -q "# SafeSkill NODE_OPTIONS hook" "$profile" 2>/dev/null; then
            python3 - "$profile" <<'PYCLEAN' 2>/dev/null || true
import pathlib
import re
import sys

p = pathlib.Path(sys.argv[1])
c = p.read_text(encoding="utf-8")
c = re.sub(
    r"\n?# SafeSkill NODE_OPTIONS hook\nexport NODE_OPTIONS=.*\nexport SAFESKILL_SOCKET=.*\n?",
    "\n",
    c,
    flags=re.MULTILINE,
)
p.write_text(c, encoding="utf-8")
PYCLEAN
            ok "Removed stale shell fallback from $profile"
        fi
    done
fi

# -- 4. Restart OpenClaw gateway --------------------------------------------
step "4. Restarting OpenClaw gateway..."

RESTARTED=false
ACTIVE_USER_SERVICE=""
if SERVICE_CANDIDATE="$(detect_user_gateway_service)"; then
    ACTIVE_USER_SERVICE="$SERVICE_CANDIDATE"
fi

if command -v openclaw &>/dev/null; then
    openclaw --profile "$OPENCLAW_PROFILE" gateway stop 2>/dev/null || true
    sleep 2
    START_OUT="$(openclaw --profile "$OPENCLAW_PROFILE" gateway start 2>&1 || true)"

    # Some environments need gateway install before start.
    if echo "$START_OUT" | grep -q "Gateway service disabled"; then
        warn "Gateway service disabled for profile '$OPENCLAW_PROFILE'; attempting install..."
        openclaw --profile "$OPENCLAW_PROFILE" gateway install >/dev/null 2>&1 || true
        START_OUT="$(openclaw --profile "$OPENCLAW_PROFILE" gateway start 2>&1 || true)"
    fi

    if [[ -n "$ACTIVE_USER_SERVICE" ]] && wait_user_service_active "$ACTIVE_USER_SERVICE" 15; then
        RESTARTED=true
        ok "Restarted via 'openclaw --profile $OPENCLAW_PROFILE' CLI (service: $ACTIVE_USER_SERVICE)"
    else
        warn "CLI start did not confirm active user service yet; trying systemctl fallback"
    fi
fi

if ! $RESTARTED; then
    for svc_name in "openclaw-gateway-${OPENCLAW_PROFILE}" openclaw-gateway openclaw ai.openclaw.gateway; do
        if systemctl --user is-enabled "$svc_name" &>/dev/null; then
            systemctl --user restart "$svc_name"
            if wait_user_service_active "$svc_name" 15; then
                RESTARTED=true
                ACTIVE_USER_SERVICE="$svc_name"
                ok "Restarted via systemctl --user restart $svc_name"
                break
            fi
        fi
    done
fi

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
    die "Could not auto-restart OpenClaw gateway. Restart manually, then re-run this script."
fi

# -- 5. Verify gateway + hook wiring ----------------------------------------
step "5. Verifying gateway + hook wiring..."

if [[ -n "$ACTIVE_USER_SERVICE" ]]; then
    if service_env_has_hook "$ACTIVE_USER_SERVICE"; then
        ok "Gateway service env includes NODE_OPTIONS + SAFESKILL_SOCKET ($ACTIVE_USER_SERVICE)"
    else
        die "Gateway service is running but missing SafeSkill env. Check drop-in and rerun."
    fi
else
    warn "Could not detect user gateway service name; skipping service env verification"
fi

GATEWAY_PORT="$(read_gateway_port)"
if is_port_listening_loopback "$GATEWAY_PORT"; then
    ok "Gateway listener detected on loopback port $GATEWAY_PORT"
else
    warn "Could not confirm listener on loopback port $GATEWAY_PORT"
fi

# -- 6. Verify daemon responsiveness ----------------------------------------
step "6. Verifying SafeSkill daemon..."

if safeskill check whoami &>/dev/null; then
    ok "SafeSkill daemon responding"
else
    die "SafeSkill daemon not responding. Commands may fail-closed until daemon is healthy."
fi

echo ""
echo "======================================="
ok "SafeSkill is now wired into OpenClaw!"
echo ""
echo "  Hook:    $HOOK_DST"
echo "  Profile: $OPENCLAW_PROFILE"
echo "  Method:  NODE_OPTIONS preload (child_process interception)"
echo ""
echo "Monitor audit log:"
echo "  sudo bash setup/linux/monitor-audit.sh"
echo ""
echo "Restart daemon if needed:"
echo "  sudo systemctl restart safeskill"
echo "======================================="
echo ""
