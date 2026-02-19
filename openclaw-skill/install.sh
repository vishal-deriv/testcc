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

# ---------- Layer 2 + 3: Skill ----------
install_skill() {
    log_step "Layer 2+3: Installing SafeSkill skill..."

    mkdir -p "$SKILL_DIR"

    # Copy SKILL.md (Layer 3: LLM prompt instructions)
    cp "$SCRIPT_DIR/SKILL.md" "$SKILL_DIR/SKILL.md"
    log_info "SKILL.md installed at $SKILL_DIR/SKILL.md"

    # Copy exec wrapper (Layer 2: shell interception)
    cp "$SCRIPT_DIR/safeskill-exec.sh" "$SKILL_DIR/safeskill-exec.sh"
    chmod +x "$SKILL_DIR/safeskill-exec.sh"
    log_info "safeskill-exec.sh installed at $SKILL_DIR/safeskill-exec.sh"

    # Copy the original wrapper too for direct invocation
    if [[ -f "$SCRIPT_DIR/safeskill-wrapper.sh" ]]; then
        cp "$SCRIPT_DIR/safeskill-wrapper.sh" "$SKILL_DIR/safeskill-wrapper.sh"
        chmod +x "$SKILL_DIR/safeskill-wrapper.sh"
    fi
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
    log_step "Configuring OpenClaw exec settings..."

    if ! command -v openclaw &>/dev/null; then
        log_warn "'openclaw' CLI not found. Skipping auto-configuration."
        log_warn "Manually add to your OpenClaw config:"
        echo ""
        echo '  {'
        echo '    "tools": {'
        echo '      "exec": {'
        echo '        "security": "allowlist",'
        echo '        "ask": "on-miss",'
        echo '        "askFallback": "deny"'
        echo '      }'
        echo '    }'
        echo '  }'
        echo ""
        return
    fi

    # Try to set exec defaults via openclaw CLI
    openclaw config set tools.exec.security allowlist 2>/dev/null && \
        log_info "Set tools.exec.security = allowlist" || \
        log_warn "Could not set tools.exec.security (set manually)"

    openclaw config set tools.exec.ask on-miss 2>/dev/null && \
        log_info "Set tools.exec.ask = on-miss" || \
        log_warn "Could not set tools.exec.ask (set manually)"

    openclaw config set tools.exec.askFallback deny 2>/dev/null && \
        log_info "Set tools.exec.askFallback = deny" || \
        log_warn "Could not set tools.exec.askFallback (set manually)"
}

# ---------- Verify installation ----------
verify() {
    log_step "Verifying installation..."

    local ok=true

    if [[ -f "$OPENCLAW_DIR/exec-approvals.json" ]]; then
        log_info "Layer 1 (exec-approvals): OK"
    else
        log_error "Layer 1 (exec-approvals): MISSING"
        ok=false
    fi

    if [[ -f "$SKILL_DIR/safeskill-exec.sh" ]] && [[ -x "$SKILL_DIR/safeskill-exec.sh" ]]; then
        log_info "Layer 2 (exec wrapper): OK"
    else
        log_error "Layer 2 (exec wrapper): MISSING"
        ok=false
    fi

    if [[ -f "$SKILL_DIR/SKILL.md" ]]; then
        log_info "Layer 3 (skill prompt): OK"
    else
        log_error "Layer 3 (skill prompt): MISSING"
        ok=false
    fi

    if [[ -f "$HOOK_DIR/handler.ts" ]] && [[ -f "$HOOK_DIR/HOOK.md" ]]; then
        log_info "Layer 4 (bootstrap hook): OK"
    else
        log_error "Layer 4 (bootstrap hook): MISSING"
        ok=false
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
    install_exec_approvals
    echo ""
    install_skill
    echo ""
    install_hook
    echo ""
    configure_openclaw
    echo ""
    verify

    echo ""
    echo "============================================"
    echo ""
    echo "  Next steps:"
    echo ""
    echo "  1. Make sure SafeSkillAgent daemon is running:"
    echo "       safeskill start"
    echo ""
    echo "  2. Restart OpenClaw to pick up the new skill + hook:"
    echo "       openclaw stop && openclaw start"
    echo ""
    echo "  3. Test it — tell OpenClaw:"
    echo "       \"run rm -rf /tmp/test\""
    echo "     It should be BLOCKED at multiple layers."
    echo ""
    echo "============================================"
    echo ""
}

main "$@"
