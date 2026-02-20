#!/usr/bin/env bash
set -euo pipefail

# SafeSkill OpenClaw Integration Installer
#
# Deploys all SafeSkill enforcement layers into OpenClaw:
#   Layer 1: exec-approvals.json   -> ~/.openclaw/exec-approvals.json
#   Layer 2: safeskill-exec.sh     -> ~/.openclaw/skills/safeskill/safeskill-exec.sh
#   Layer 3: SKILL.md              -> ~/.openclaw/skills/safeskill/SKILL.md
#   Layer 4: safeskill-hook/       -> ~/.openclaw/hooks/safeskill-hook/
#
# Run AFTER installing the SafeSkillAgent daemon (via install-macos.sh or install-linux.sh)
# Can be run as non-root (installs to user's ~/.openclaw/)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OPENCLAW_DIR="${OPENCLAW_HOME:-$HOME/.openclaw}"
SKILL_DIR="$OPENCLAW_DIR/skills/safeskill"
HOOK_DIR="$OPENCLAW_DIR/hooks/safeskill-hook"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step()  { echo -e "${CYAN}[STEP]${NC} $*"; }

# ---------- Pre-flight checks ----------
check_prerequisites() {
    if [[ ! -d "$OPENCLAW_DIR" ]]; then
        log_warn "OpenClaw directory not found at $OPENCLAW_DIR"
        log_info "Creating $OPENCLAW_DIR..."
        mkdir -p "$OPENCLAW_DIR"
    fi

    if ! command -v safeskill &>/dev/null; then
        log_warn "SafeSkillAgent CLI not found in PATH."
        log_warn "Make sure to install the agent first (setup/install-macos.sh or setup/install-linux.sh)"
    fi

    local socket="${SAFESKILL_SOCKET:-/tmp/safeskill.sock}"
    if [[ -S "$socket" ]]; then
        log_info "SafeSkillAgent daemon is running (socket: $socket)"
    else
        log_warn "SafeSkillAgent daemon is NOT running (socket not found: $socket)"
        log_warn "Start it with: safeskill start"
    fi
}

# ---------- Layer 1: Exec Approvals ----------
install_exec_approvals() {
    log_step "Layer 1: Installing exec-approvals config..."

    local target="$OPENCLAW_DIR/exec-approvals.json"

    if [[ -f "$target" ]]; then
        log_warn "exec-approvals.json already exists at $target"
        echo ""
        echo "  Options:"
        echo "    [m] Merge SafeSkill allowlist into existing config (recommended)"
        echo "    [o] Overwrite with SafeSkill defaults"
        echo "    [s] Skip — keep existing config"
        echo ""
        read -rp "  Choice [m/o/s]: " choice

        case "${choice,,}" in
            m)
                log_info "Merging SafeSkill exec-approvals into existing config..."
                # Backup existing
                cp "$target" "${target}.bak.$(date +%s)"
                # Merge using python: add SafeSkill defaults if not present
                python3 -c "
import json, sys

with open('${target}', 'r') as f:
    existing = json.load(f)

with open('${SCRIPT_DIR}/exec-approvals.json', 'r') as f:
    safeskill = json.load(f)

# Merge defaults — only set if not already configured
for key in ('security', 'ask', 'askFallback'):
    existing.setdefault('defaults', {}).setdefault(key, safeskill['defaults'][key])

# Merge allowlist into main agent
main_agent = existing.setdefault('agents', {}).setdefault('main', {})
main_agent.setdefault('security', 'allowlist')
main_agent.setdefault('ask', 'on-miss')
main_agent.setdefault('askFallback', 'deny')

existing_patterns = set()
for entry in main_agent.get('allowlist', []):
    existing_patterns.add(entry.get('pattern', ''))

merged_list = list(main_agent.get('allowlist', []))
for entry in safeskill['agents']['main']['allowlist']:
    if entry['pattern'] not in existing_patterns:
        merged_list.append(entry)
        existing_patterns.add(entry['pattern'])

main_agent['allowlist'] = merged_list

with open('${target}', 'w') as f:
    json.dump(existing, f, indent=2)

print(f'Merged {len(merged_list)} total allowlist entries')
" 2>/dev/null || {
                    log_error "Merge failed. Restoring backup..."
                    mv "${target}.bak."* "$target" 2>/dev/null || true
                    return
                }
                log_info "Merge complete (backup saved as .bak)"
                ;;
            o)
                cp "$target" "${target}.bak.$(date +%s)"
                cp "$SCRIPT_DIR/exec-approvals.json" "$target"
                log_info "Overwritten (backup saved as .bak)"
                ;;
            *)
                log_info "Skipped exec-approvals"
                return
                ;;
        esac
    else
        cp "$SCRIPT_DIR/exec-approvals.json" "$target"
        log_info "exec-approvals.json installed at $target"
    fi
}

# ---------- Layer 2: Shell replacement (THE REAL ENFORCEMENT) ----------
install_shell_intercept() {
    log_step "Layer 2: Installing SafeSkill shell interceptor..."

    local shell_src="$SCRIPT_DIR/safeskill-shell"
    local shell_dst="/usr/local/bin/safeskill-shell"

    if [[ ! -f "$shell_src" ]]; then
        log_error "safeskill-shell not found at $shell_src"
        return 1
    fi

    # Install to /usr/local/bin (may need sudo - try both)
    if cp "$shell_src" "$shell_dst" 2>/dev/null; then
        chmod +x "$shell_dst"
        log_info "Shell interceptor installed at $shell_dst"
    elif sudo cp "$shell_src" "$shell_dst" 2>/dev/null; then
        sudo chmod +x "$shell_dst"
        log_info "Shell interceptor installed at $shell_dst (via sudo)"
    else
        # Fallback: install in user's local bin
        local user_bin="$HOME/.local/bin"
        mkdir -p "$user_bin"
        cp "$shell_src" "$user_bin/safeskill-shell"
        chmod +x "$user_bin/safeskill-shell"
        shell_dst="$user_bin/safeskill-shell"
        log_warn "Could not install to /usr/local/bin. Installed at $shell_dst"
    fi

    SAFESKILL_SHELL_PATH="$shell_dst"
    log_info "Shell interceptor ready: $SAFESKILL_SHELL_PATH"
}

# ---------- Layer 3: Skill ----------
install_skill() {
    log_step "Layer 3: Installing SafeSkill skill..."

    mkdir -p "$SKILL_DIR"

    cp "$SCRIPT_DIR/SKILL.md" "$SKILL_DIR/SKILL.md"
    log_info "SKILL.md installed at $SKILL_DIR/SKILL.md"

    # Copy wrappers for direct invocation
    for f in safeskill-exec.sh safeskill-wrapper.sh; do
        if [[ -f "$SCRIPT_DIR/$f" ]]; then
            cp "$SCRIPT_DIR/$f" "$SKILL_DIR/$f"
            chmod +x "$SKILL_DIR/$f"
        fi
    done
}

# ---------- Layer 4: Hook ----------
install_hook() {
    log_step "Layer 4: Installing SafeSkill bootstrap hook..."

    mkdir -p "$HOOK_DIR"

    cp "$SCRIPT_DIR/safeskill-hook/HOOK.md" "$HOOK_DIR/HOOK.md"
    cp "$SCRIPT_DIR/safeskill-hook/handler.ts" "$HOOK_DIR/handler.ts"

    log_info "Hook installed at $HOOK_DIR/"
}

# ---------- Configure OpenClaw exec settings ----------
configure_openclaw() {
    log_step "Configuring OpenClaw exec enforcement..."

    local config_file="$OPENCLAW_DIR/config.json"
    local configured=false

    # Method 1: Try openclaw CLI
    if command -v openclaw &>/dev/null; then
        log_info "Configuring via openclaw CLI..."

        openclaw config set tools.exec.host gateway 2>/dev/null && \
            log_info "Set tools.exec.host = gateway" || true
        openclaw config set tools.exec.security allowlist 2>/dev/null && \
            log_info "Set tools.exec.security = allowlist" || true
        openclaw config set tools.exec.ask on-miss 2>/dev/null && \
            log_info "Set tools.exec.ask = on-miss" || true
        openclaw config set tools.exec.askFallback deny 2>/dev/null && \
            log_info "Set tools.exec.askFallback = deny" || true

        configured=true
    fi

    # METHOD 2: Patch OpenClaw's startup wrapper
    # OpenClaw's env config uses "never override" semantics, meaning our
    # SHELL setting gets ignored because the OS already sets SHELL=/bin/bash.
    # The only reliable way is to inject SHELL into the actual launch command.

    local shell_path="${SAFESKILL_SHELL_PATH:-/usr/local/bin/safeskill-shell}"

    log_info "Setting SHELL override for OpenClaw..."

    # Write to .env (OpenClaw loads this but won't override existing SHELL)
    local env_file="$OPENCLAW_DIR/.env"
    local env_lines=()
    if [[ -f "$env_file" ]]; then
        while IFS= read -r line; do
            [[ "$line" == SHELL=* ]] && continue
            [[ "$line" == SAFESKILL_* ]] && continue
            env_lines+=("$line")
        done < "$env_file"
    fi
    env_lines+=("SHELL=$shell_path")
    env_lines+=("SAFESKILL_REAL_SHELL=/bin/bash")
    env_lines+=("SAFESKILL_SOCKET=/tmp/safeskill.sock")
    printf '%s\n' "${env_lines[@]}" > "$env_file"
    log_info "Updated $env_file"

    # Write to config json
    python3 -c "
import json, os

config_path = '${config_file}'
config = {}
if os.path.exists(config_path):
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
    except (json.JSONDecodeError, IOError):
        config = {}

env_block = config.setdefault('env', {})
env_block['SHELL'] = '${shell_path}'
env_block['SAFESKILL_REAL_SHELL'] = '/bin/bash'
env_block['SAFESKILL_SOCKET'] = '/tmp/safeskill.sock'

tools = config.setdefault('tools', {})
exec_cfg = tools.setdefault('exec', {})
exec_cfg['host'] = 'gateway'
exec_cfg['security'] = 'allowlist'
exec_cfg['ask'] = 'on-miss'
exec_cfg['askFallback'] = 'deny'

with open(config_path, 'w') as f:
    json.dump(config, f, indent=2)
print('Config written')
" 2>/dev/null || true

    # METHOD 3: Create a wrapper script that launches OpenClaw with SHELL set
    local wrapper="$OPENCLAW_DIR/start-safe.sh"
    cat > "$wrapper" << WRAPPER
#!/usr/bin/env bash
# Start OpenClaw with SafeSkill enforcement
# This sets SHELL at process level so OpenClaw MUST use safeskill-shell
export SHELL="${shell_path}"
export SAFESKILL_REAL_SHELL="/bin/bash"
export SAFESKILL_SOCKET="/tmp/safeskill.sock"
exec openclaw "\$@"
WRAPPER
    chmod +x "$wrapper"
    log_info "Created $wrapper"

    # METHOD 4: Create shell profile snippet that overrides SHELL for openclaw
    local profile_snippet="$OPENCLAW_DIR/safeskill-env.sh"
    cat > "$profile_snippet" << 'ENVSNIPPET'
# SafeSkill: Override SHELL for OpenClaw
# Source this in your .bashrc/.zshrc, or the OpenClaw systemd unit
export SHELL="SHELL_PATH_PLACEHOLDER"
export SAFESKILL_REAL_SHELL="/bin/bash"
export SAFESKILL_SOCKET="/tmp/safeskill.sock"
ENVSNIPPET
    sed -i "s|SHELL_PATH_PLACEHOLDER|${shell_path}|g" "$profile_snippet" 2>/dev/null || \
        sed "s|SHELL_PATH_PLACEHOLDER|${shell_path}|g" "$profile_snippet" > "${profile_snippet}.tmp" && \
        mv "${profile_snippet}.tmp" "$profile_snippet"
    log_info "Created $profile_snippet"

    # METHOD 5: If OpenClaw has a systemd service, try to add Environment=SHELL
    local oc_service=""
    for svc in /etc/systemd/system/openclaw*.service /lib/systemd/system/openclaw*.service; do
        if [[ -f "$svc" ]]; then
            oc_service="$svc"
            break
        fi
    done

    if [[ -n "$oc_service" ]]; then
        log_info "Found OpenClaw systemd service: $oc_service"
        local override_dir="${oc_service%.service}.service.d"
        sudo mkdir -p "$override_dir" 2>/dev/null || mkdir -p "$override_dir" 2>/dev/null || true
        local override_file="$override_dir/safeskill.conf"
        cat > "$override_file" 2>/dev/null << OVERRIDE || true
[Service]
Environment=SHELL=${shell_path}
Environment=SAFESKILL_REAL_SHELL=/bin/bash
Environment=SAFESKILL_SOCKET=/tmp/safeskill.sock
OVERRIDE
        if [[ -f "$override_file" ]]; then
            sudo systemctl daemon-reload 2>/dev/null || true
            log_info "Systemd override created at $override_file"
        fi
    fi

    configured=true

    echo ""
    log_info "=== SHELL override configured ==="
    echo ""
    echo "  OpenClaw MUST be started with SHELL=$shell_path"
    echo ""
    echo "  Choose ONE of these methods:"
    echo ""
    echo "  A) Use the safe launcher (recommended):"
    echo "       $wrapper"
    echo ""
    echo "  B) Set SHELL inline:"
    echo "       SHELL=$shell_path openclaw start"
    echo ""
    echo "  C) Source the env file first:"
    echo "       source $profile_snippet && openclaw start"
    echo ""
    echo "  D) If OpenClaw runs via systemd, it's already configured."
    echo "       Just restart: sudo systemctl restart openclaw"
    echo ""
}

# ---------- Verify installation ----------
verify() {
    log_step "Verifying installation..."

    local ok=true

    if [[ -f "$OPENCLAW_DIR/exec-approvals.json" ]]; then
        log_info "Layer 1 (exec-approvals): OK"
    else
        log_warn "Layer 1 (exec-approvals): MISSING (secondary defense)"
        # Not fatal — shell intercept is the primary
    fi

    local shell_path="${SAFESKILL_SHELL_PATH:-/usr/local/bin/safeskill-shell}"
    if [[ -x "$shell_path" ]]; then
        log_info "Layer 2 (SHELL interceptor): OK — $shell_path"

        # Check if OpenClaw config has SHELL set
        if [[ -f "$OPENCLAW_DIR/openclaw.json" ]]; then
            if python3 -c "
import json
with open('${OPENCLAW_DIR}/openclaw.json') as f:
    c = json.load(f)
shell = c.get('env',{}).get('SHELL','')
exit(0 if 'safeskill' in shell else 1)
" 2>/dev/null; then
                log_info "Layer 2 (SHELL in config): OK — OpenClaw will use safeskill-shell"
            else
                log_error "Layer 2 (SHELL in config): NOT SET — OpenClaw will bypass SafeSkill!"
                ok=false
            fi
        elif [[ -f "$OPENCLAW_DIR/.env" ]] && grep -q "SHELL=.*safeskill" "$OPENCLAW_DIR/.env" 2>/dev/null; then
            log_info "Layer 2 (SHELL in .env): OK"
        else
            log_error "Layer 2 (SHELL config): NOT SET — run configure_openclaw"
            ok=false
        fi
    else
        log_error "Layer 2 (SHELL interceptor): NOT INSTALLED at $shell_path"
        ok=false
    fi

    if [[ -f "$SKILL_DIR/SKILL.md" ]]; then
        log_info "Layer 3 (skill prompt): OK"
    else
        log_warn "Layer 3 (skill prompt): MISSING (soft defense)"
    fi

    if [[ -f "$HOOK_DIR/handler.ts" ]] && [[ -f "$HOOK_DIR/HOOK.md" ]]; then
        log_info "Layer 4 (bootstrap hook): OK"
    else
        log_warn "Layer 4 (bootstrap hook): MISSING (secondary defense)"
    fi

    if [[ "$ok" == true ]]; then
        echo ""
        log_info "All layers installed successfully."
    else
        echo ""
        log_error "Some layers failed to install. Check errors above."
        return 1
    fi
}

# ---------- Main ----------
main() {
    echo ""
    echo "============================================"
    echo "  SafeSkill OpenClaw Integration Installer"
    echo "============================================"
    echo ""
    echo "  Deploying 4 defense layers:"
    echo "    Layer 1: Exec approvals (OS-level gate)"
    echo "    Layer 2: Shell wrapper (exec interception)"
    echo "    Layer 3: Skill prompt (LLM instructions)"
    echo "    Layer 4: Bootstrap hook (startup verification)"
    echo ""
    echo "  Target: $OPENCLAW_DIR"
    echo ""

    check_prerequisites
    echo ""
    install_shell_intercept
    echo ""
    install_exec_approvals
    echo ""
    install_skill
    echo ""
    install_hook
    echo ""
    configure_openclaw
    echo ""
    verify

    local shell_path="${SAFESKILL_SHELL_PATH:-/usr/local/bin/safeskill-shell}"

    echo ""
    echo "============================================"
    echo ""
    echo "  NEXT STEPS:"
    echo ""
    echo "  1. Make sure SafeSkillAgent daemon is running:"
    echo "       safeskill start"
    echo ""
    echo "  2. STOP OpenClaw and restart with SafeSkill:"
    echo "       openclaw stop"
    echo "       SHELL=$shell_path openclaw start"
    echo ""
    echo "     OR use the launcher we created:"
    echo "       openclaw stop"
    echo "       ~/.openclaw/start-safe.sh start"
    echo ""
    echo "  3. Test: tell OpenClaw \"run rm -rf /tmp/test\""
    echo "     It MUST show [SafeSkill] BLOCKED"
    echo ""
    echo "  4. Verify OpenClaw is using the right shell:"
    echo "     Tell OpenClaw: \"run echo \$SHELL\""
    echo "     Must show: $shell_path"
    echo ""
    echo "============================================"
    echo ""
}

main "$@"
