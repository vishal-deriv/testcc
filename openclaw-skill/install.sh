#!/usr/bin/env bash
set -euo pipefail

# SafeSkill OpenClaw Integration Installer — Production
#
# Two enforcement layers:
#   Layer 1 (Hard):  BASH_ENV trap — intercepts at bash level, LLM cannot bypass
#   Layer 2 (Soft):  AGENTS.md injection — LLM always reads this, told to use safeskill
#
# Run as the same user that runs OpenClaw (NOT root).

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
WORKSPACE="${OPENCLAW_WORKSPACE:-$OPENCLAW_HOME/workspace}"
TRAP_INSTALL_PATH="/opt/safeskill/safeskill-trap.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!!]${NC} $*"; }
log_error() { echo -e "${RED}[FAIL]${NC} $*"; }
log_step()  { echo -e "${CYAN}[>>]${NC} ${BOLD}$*${NC}"; }

# ================================================================
# LAYER 1: BASH_ENV TRAP (hard enforcement)
# ================================================================
install_trap() {
    log_step "Layer 1: Installing BASH_ENV trap..."

    local src="$SCRIPT_DIR/safeskill-trap.sh"
    if [[ ! -f "$src" ]]; then
        log_error "safeskill-trap.sh not found"
        return 1
    fi

    # Try /opt/safeskill first (requires sudo), fallback to home
    if sudo cp "$src" "$TRAP_INSTALL_PATH" 2>/dev/null; then
        sudo chmod 644 "$TRAP_INSTALL_PATH"
    elif [[ -w "$(dirname "$TRAP_INSTALL_PATH")" ]]; then
        cp "$src" "$TRAP_INSTALL_PATH"
        chmod 644 "$TRAP_INSTALL_PATH"
    else
        TRAP_INSTALL_PATH="$HOME/.safeskill-trap.sh"
        cp "$src" "$TRAP_INSTALL_PATH"
        chmod 644 "$TRAP_INSTALL_PATH"
        log_warn "Installed trap at $TRAP_INSTALL_PATH (no sudo access)"
    fi

    log_info "Trap script: $TRAP_INSTALL_PATH"

    # Quick test: does the trap work?
    local test_out
    test_out=$(BASH_ENV="$TRAP_INSTALL_PATH" SAFESKILL_SOCKET=/tmp/safeskill.sock \
        bash -c 'echo "trap-test-ok"' 2>/dev/null) || true

    if [[ "$test_out" == *"trap-test-ok"* ]]; then
        log_info "Trap test passed (safe commands pass through)"
    else
        log_warn "Trap test inconclusive — may still work with daemon running"
    fi
}

# ================================================================
# LAYER 2: AGENTS.MD INJECTION (LLM enforcement)
# ================================================================
inject_agents_md() {
    log_step "Layer 2: Injecting into AGENTS.md..."

    local agents_file="$WORKSPACE/AGENTS.md"
    local inject_src="$SCRIPT_DIR/safeskill-inject.md"

    if [[ ! -f "$inject_src" ]]; then
        log_error "safeskill-inject.md not found"
        return 1
    fi

    mkdir -p "$WORKSPACE"

    # Check if already injected
    if [[ -f "$agents_file" ]] && grep -q "SAFESKILL SECURITY ENFORCEMENT" "$agents_file" 2>/dev/null; then
        # Update existing injection
        local tmp="${agents_file}.tmp.$$"
        awk '/<!-- SAFESKILL SECURITY ENFORCEMENT/{skip=1} /<!-- END SAFESKILL -->/{skip=0;next} !skip' "$agents_file" > "$tmp"
        cat "$inject_src" >> "$tmp"
        mv "$tmp" "$agents_file"
        log_info "AGENTS.md updated (replaced existing SafeSkill block)"
    elif [[ -f "$agents_file" ]]; then
        # Append to existing
        echo "" >> "$agents_file"
        cat "$inject_src" >> "$agents_file"
        log_info "AGENTS.md injected (appended to existing)"
    else
        # Create new
        cat "$inject_src" > "$agents_file"
        log_info "AGENTS.md created with SafeSkill enforcement"
    fi
}

# ================================================================
# INSTALL SKILL (so it shows up in skill list too)
# ================================================================
install_skill() {
    log_step "Installing SafeSkill skill..."

    local skill_dir="$OPENCLAW_HOME/skills/safeskill"
    mkdir -p "$skill_dir"

    if [[ -f "$SCRIPT_DIR/SKILL.md" ]]; then
        cp "$SCRIPT_DIR/SKILL.md" "$skill_dir/SKILL.md"
        log_info "SKILL.md installed"
    fi

    # Copy wrapper scripts
    for f in safeskill-exec.sh safeskill-wrapper.sh safeskill-shell; do
        if [[ -f "$SCRIPT_DIR/$f" ]]; then
            cp "$SCRIPT_DIR/$f" "$skill_dir/$f"
            chmod +x "$skill_dir/$f"
        fi
    done
}

# ================================================================
# CONFIGURE GATEWAY ENVIRONMENT
# ================================================================
configure_gateway_env() {
    log_step "Configuring gateway environment..."

    # Method A: .env file
    local env_file="$OPENCLAW_HOME/.env"
    local env_lines=()
    if [[ -f "$env_file" ]]; then
        while IFS= read -r line; do
            [[ "$line" == BASH_ENV=* ]] && continue
            [[ "$line" == SAFESKILL_SOCKET=* ]] && continue
            [[ "$line" == _SAFESKILL_ACTIVE=* ]] && continue
            env_lines+=("$line")
        done < "$env_file"
    fi
    env_lines+=("BASH_ENV=$TRAP_INSTALL_PATH")
    env_lines+=("SAFESKILL_SOCKET=/tmp/safeskill.sock")
    printf '%s\n' "${env_lines[@]}" > "$env_file"
    log_info ".env updated: BASH_ENV=$TRAP_INSTALL_PATH"

    # Method B: openclaw.json env block
    local config_file="$OPENCLAW_HOME/openclaw.json"
    python3 -c "
import json, os
p = '${config_file}'
c = {}
if os.path.exists(p):
    try:
        with open(p) as f: c = json.load(f)
    except: pass
e = c.setdefault('env', {})
e['BASH_ENV'] = '${TRAP_INSTALL_PATH}'
e['SAFESKILL_SOCKET'] = '/tmp/safeskill.sock'
with open(p, 'w') as f: json.dump(c, f, indent=2)
print('openclaw.json updated')
" 2>/dev/null && log_info "openclaw.json env block updated" || log_warn "Could not update openclaw.json"

    # Method C: Create gateway launcher
    local launcher="$OPENCLAW_HOME/start-safeskill-gateway.sh"
    cat > "$launcher" << LAUNCHER
#!/usr/bin/env bash
# Start OpenClaw gateway with SafeSkill enforcement
export BASH_ENV="$TRAP_INSTALL_PATH"
export SAFESKILL_SOCKET="/tmp/safeskill.sock"
exec openclaw gateway "\$@"
LAUNCHER
    chmod +x "$launcher"
    log_info "Gateway launcher: $launcher"

    # Method D: systemd user service override (if gateway runs as service)
    local uid
    uid=$(id -u 2>/dev/null) || true
    local xdg="/run/user/$uid"
    if [[ -d "$xdg" ]] && command -v systemctl &>/dev/null; then
        (
            export XDG_RUNTIME_DIR="$xdg"
            systemctl --user set-environment BASH_ENV="$TRAP_INSTALL_PATH" 2>/dev/null && \
                log_info "systemd user env: BASH_ENV set" || true
            systemctl --user set-environment SAFESKILL_SOCKET="/tmp/safeskill.sock" 2>/dev/null || true
        )
    fi
}

# ================================================================
# VERIFY
# ================================================================
verify() {
    log_step "Verifying installation..."

    local ok=true

    # Check daemon
    if [[ -S "/tmp/safeskill.sock" ]]; then
        local health
        health=$(curl -sf --max-time 2 --unix-socket /tmp/safeskill.sock http://localhost/health 2>/dev/null) || true
        if echo "$health" | grep -q "healthy" 2>/dev/null; then
            log_info "SafeSkillAgent daemon: RUNNING"
        else
            log_warn "SafeSkillAgent daemon: socket exists but not healthy"
        fi
    else
        log_error "SafeSkillAgent daemon: NOT RUNNING"
        echo "       Start it:  safeskill start --config-dir /etc/safeskill --log-dir /var/log/safeskill"
        ok=false
    fi

    # Check trap
    if [[ -f "$TRAP_INSTALL_PATH" ]]; then
        log_info "Layer 1 (BASH_ENV trap): $TRAP_INSTALL_PATH"
    else
        log_error "Layer 1 (BASH_ENV trap): MISSING"
        ok=false
    fi

    # Check AGENTS.md
    if [[ -f "$WORKSPACE/AGENTS.md" ]] && grep -q "SAFESKILL" "$WORKSPACE/AGENTS.md" 2>/dev/null; then
        log_info "Layer 2 (AGENTS.md): injected"
    else
        log_error "Layer 2 (AGENTS.md): NOT injected"
        ok=false
    fi

    # Check socket permissions
    if [[ -S "/tmp/safeskill.sock" ]]; then
        local perms
        perms=$(stat -c "%a" /tmp/safeskill.sock 2>/dev/null || stat -f "%Lp" /tmp/safeskill.sock 2>/dev/null || echo "?")
        if [[ "$perms" == "666" ]]; then
            log_info "Socket permissions: 666 (non-root can connect)"
        else
            log_warn "Socket permissions: $perms (may need: sudo chmod 666 /tmp/safeskill.sock)"
        fi
    fi

    echo ""
    if [[ "$ok" == true ]]; then
        log_info "All checks passed"
    else
        log_error "Some checks failed — see above"
    fi
}

# ================================================================
# MAIN
# ================================================================
main() {
    echo ""
    echo "============================================"
    echo "  SafeSkill OpenClaw Integration"
    echo "============================================"
    echo ""
    echo "  Layer 1: BASH_ENV trap (hard enforcement)"
    echo "  Layer 2: AGENTS.md injection (LLM instruction)"
    echo ""
    echo "  OpenClaw home: $OPENCLAW_HOME"
    echo "  Workspace:     $WORKSPACE"
    echo ""

    install_trap
    echo ""
    inject_agents_md
    echo ""
    install_skill
    echo ""
    configure_gateway_env
    echo ""
    verify

    echo ""
    echo "============================================"
    echo ""
    echo "  ${BOLD}TO ACTIVATE:${NC}"
    echo ""
    echo "  Option A (recommended — guaranteed to work):"
    echo "    openclaw gateway stop"
    echo "    BASH_ENV=$TRAP_INSTALL_PATH openclaw gateway start"
    echo ""
    echo "  Option B (use the launcher):"
    echo "    openclaw gateway stop"
    echo "    $OPENCLAW_HOME/start-safeskill-gateway.sh start"
    echo ""
    echo "  Option C (if gateway runs via systemd --user):"
    echo "    systemctl --user restart openclaw-gateway"
    echo ""
    echo "  Then start TUI:  openclaw tui"
    echo ""
    echo "  ${BOLD}TEST:${NC}"
    echo "    Tell OpenClaw: \"run rm -rf ~/tmp\""
    echo "    Layer 1 blocks it at bash level → [SafeSkill] BLOCKED"
    echo "    Layer 2 tells LLM to check first → safeskill check"
    echo ""
    echo "============================================"
    echo ""
}

main "$@"
