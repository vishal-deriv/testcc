#!/usr/bin/env bash
set -euo pipefail

# SafeSkillAgent Update Script
#
# Pulls latest code from git, rebuilds the venv, restarts the service.
# Designed to be run by a systemd timer (Linux) or launchd (macOS) periodically.
#
# Usage:
#   ./setup/update.sh                    # Auto-detect OS, use defaults
#   ./setup/update.sh --branch main      # Pull from specific branch
#   ./setup/update.sh --tag latest       # Pull latest git tag only
#   ./setup/update.sh --check-only       # Check for updates without applying
#   ./setup/update.sh --force            # Force rebuild even if no changes
#
# Exit codes:
#   0 - Updated successfully (or no update needed)
#   1 - Update failed
#   2 - No updates available (with --check-only)

INSTALL_DIR="${SAFESKILL_INSTALL_DIR:-/opt/safeskill/src}"
VENV_DIR="${SAFESKILL_VENV_DIR:-/opt/safeskill/venv}"
CONFIG_DIR="${SAFESKILL_CONFIG_DIR:-/etc/safeskill}"
LOG_DIR="${SAFESKILL_LOG_DIR:-/var/log/safeskill}"
GIT_REMOTE="${SAFESKILL_GIT_REMOTE:-origin}"
GIT_BRANCH="${SAFESKILL_GIT_BRANCH:-main}"
USE_TAGS=false
CHECK_ONLY=false
FORCE=false
LOCK_FILE="/tmp/safeskill-update.lock"
UPDATE_LOG="$LOG_DIR/update.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$UPDATE_LOG" 2>/dev/null || echo "[INFO] $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$UPDATE_LOG" 2>/dev/null || echo "[WARN] $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$UPDATE_LOG" 2>/dev/null || echo "[ERROR] $*"; }
log_step()  { echo -e "${CYAN}[STEP]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$UPDATE_LOG" 2>/dev/null || echo "[STEP] $*"; }

# ---------- Parse arguments ----------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --branch)   GIT_BRANCH="$2"; shift 2 ;;
            --tag)      USE_TAGS=true; shift ;;
            --check-only) CHECK_ONLY=true; shift ;;
            --force)    FORCE=true; shift ;;
            --install-dir) INSTALL_DIR="$2"; shift 2 ;;
            --remote)   GIT_REMOTE="$2"; shift 2 ;;
            *) log_error "Unknown option: $1"; exit 1 ;;
        esac
    done
}

# ---------- Locking ----------
acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local lock_pid
        lock_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
            log_warn "Another update is already running (PID $lock_pid). Exiting."
            exit 0
        fi
        rm -f "$LOCK_FILE"
    fi
    echo $$ > "$LOCK_FILE"
}

release_lock() {
    rm -f "$LOCK_FILE"
}
trap release_lock EXIT

# ---------- Detect OS ----------
detect_os() {
    if [[ "$(uname)" == "Darwin" ]]; then
        OS="macos"
        SERVICE_CMD="launchctl"
    else
        OS="linux"
        SERVICE_CMD="systemctl"
    fi
}

# ---------- Check for updates ----------
check_for_updates() {
    if [[ ! -d "$INSTALL_DIR/.git" ]]; then
        log_error "Not a git repo: $INSTALL_DIR"
        log_error "Run the installer first, or set SAFESKILL_INSTALL_DIR"
        return 1
    fi

    cd "$INSTALL_DIR"

    log_step "Fetching from $GIT_REMOTE..."
    git fetch "$GIT_REMOTE" --tags --quiet 2>/dev/null || {
        log_error "git fetch failed. Check network and git remote."
        return 1
    }

    local local_ref remote_ref

    if [[ "$USE_TAGS" == true ]]; then
        local_ref=$(git describe --tags --abbrev=0 2>/dev/null || echo "none")
        remote_ref=$(git tag --sort=-v:refname | head -1 2>/dev/null || echo "none")

        if [[ "$local_ref" == "$remote_ref" ]] && [[ "$FORCE" != true ]]; then
            log_info "Already on latest tag: $local_ref"
            return 2
        fi
        log_info "Update available: $local_ref -> $remote_ref"
    else
        local_ref=$(git rev-parse HEAD)
        remote_ref=$(git rev-parse "$GIT_REMOTE/$GIT_BRANCH" 2>/dev/null || echo "")

        if [[ -z "$remote_ref" ]]; then
            log_error "Could not resolve $GIT_REMOTE/$GIT_BRANCH"
            return 1
        fi

        if [[ "$local_ref" == "$remote_ref" ]] && [[ "$FORCE" != true ]]; then
            log_info "Already up to date ($(echo "$local_ref" | cut -c1-8))"
            return 2
        fi
        log_info "Update available: $(echo "$local_ref" | cut -c1-8) -> $(echo "$remote_ref" | cut -c1-8)"
    fi

    return 0
}

# ---------- Apply update ----------
apply_update() {
    cd "$INSTALL_DIR"

    # Record current version for rollback
    local prev_commit
    prev_commit=$(git rev-parse HEAD)
    echo "$prev_commit" > "$INSTALL_DIR/.safeskill-prev-version"

    log_step "Pulling latest code..."
    if [[ "$USE_TAGS" == true ]]; then
        local latest_tag
        latest_tag=$(git tag --sort=-v:refname | head -1)
        git checkout "$latest_tag" --quiet
        log_info "Checked out tag: $latest_tag"
    else
        git pull "$GIT_REMOTE" "$GIT_BRANCH" --quiet
        log_info "Pulled branch: $GIT_BRANCH"
    fi

    local new_commit
    new_commit=$(git rev-parse HEAD)
    log_info "Now at: $(echo "$new_commit" | cut -c1-8)"

    # Check if Python deps changed
    local deps_changed=false
    if git diff "$prev_commit" "$new_commit" -- requirements.txt pyproject.toml 2>/dev/null | grep -q '^[+-]'; then
        deps_changed=true
        log_info "Dependencies changed — will rebuild venv"
    fi

    # Rebuild venv if needed or forced
    if [[ "$deps_changed" == true ]] || [[ "$FORCE" == true ]]; then
        rebuild_venv
    else
        log_step "Reinstalling package (deps unchanged)..."
        "$VENV_DIR/bin/pip" install "$INSTALL_DIR" --quiet 2>/dev/null || {
            log_warn "Quick install failed, doing full rebuild..."
            rebuild_venv
        }
    fi

    # Update config files (only add new ones, never overwrite existing)
    update_configs

    # Update OpenClaw integration if present
    update_openclaw

    log_info "Code updated successfully"
}

# ---------- Rebuild venv ----------
rebuild_venv() {
    log_step "Rebuilding virtual environment..."

    local python_bin=""
    for candidate in python3.14 python3.13 python3.12 python3.11 python3.10 python3; do
        if command -v "$candidate" &>/dev/null; then
            local ver
            ver=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null) || continue
            local minor
            minor=$(echo "$ver" | cut -d. -f2)
            if [[ "$minor" -ge 10 ]]; then
                python_bin="$candidate"
                break
            fi
        fi
    done

    if [[ -z "$python_bin" ]]; then
        log_error "Python 3.10+ not found"
        return 1
    fi

    rm -rf "$VENV_DIR"
    "$python_bin" -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --upgrade pip --quiet
    "$VENV_DIR/bin/pip" install "$INSTALL_DIR" --quiet

    log_info "Venv rebuilt with $python_bin"
}

# ---------- Update configs (non-destructive) ----------
update_configs() {
    log_step "Checking for new config files..."

    local src_config="$INSTALL_DIR/config"

    # Only copy files that don't already exist
    for f in base-policy.yaml signatures.yaml runtime-policy.yaml; do
        if [[ -f "$src_config/$f" ]] && [[ ! -f "$CONFIG_DIR/$f" ]]; then
            cp "$src_config/$f" "$CONFIG_DIR/$f"
            log_info "Added new config: $f"
        fi
    done

    for f in dev.yaml staging.yaml production.yaml; do
        if [[ -f "$src_config/environments/$f" ]] && [[ ! -f "$CONFIG_DIR/environments/$f" ]]; then
            mkdir -p "$CONFIG_DIR/environments"
            cp "$src_config/environments/$f" "$CONFIG_DIR/environments/$f"
            log_info "Added new environment config: $f"
        fi
    done

    # Always update signatures (these are additive security updates)
    if [[ -f "$src_config/signatures.yaml" ]]; then
        cp "$src_config/signatures.yaml" "$CONFIG_DIR/signatures.yaml"
        log_info "Signatures updated"
    fi
}

# ---------- Update OpenClaw skill ----------
update_openclaw() {
    local real_home="$HOME"
    if [[ -n "${SUDO_USER:-}" ]]; then
        real_home=$(eval echo "~$SUDO_USER")
    fi

    local openclaw_skill_dir="$real_home/.openclaw/skills/safeskill"
    local openclaw_hook_dir="$real_home/.openclaw/hooks/safeskill-hook"

    if [[ -d "$openclaw_skill_dir" ]]; then
        log_step "Updating OpenClaw skill..."
        cp "$INSTALL_DIR/openclaw-skill/SKILL.md" "$openclaw_skill_dir/SKILL.md"
        cp "$INSTALL_DIR/openclaw-skill/safeskill-exec.sh" "$openclaw_skill_dir/safeskill-exec.sh"
        chmod +x "$openclaw_skill_dir/safeskill-exec.sh"
        log_info "OpenClaw skill updated"
    fi

    if [[ -d "$openclaw_hook_dir" ]]; then
        cp "$INSTALL_DIR/openclaw-skill/safeskill-hook/HOOK.md" "$openclaw_hook_dir/HOOK.md"
        cp "$INSTALL_DIR/openclaw-skill/safeskill-hook/handler.ts" "$openclaw_hook_dir/handler.ts"
        log_info "OpenClaw hook updated"
    fi
}

# ---------- Restart service ----------
restart_service() {
    log_step "Restarting SafeSkillAgent service..."

    if [[ "$OS" == "macos" ]]; then
        launchctl unload /Library/LaunchDaemons/com.safeskill.agent.plist 2>/dev/null || true
        sleep 1
        launchctl load -w /Library/LaunchDaemons/com.safeskill.agent.plist
    else
        systemctl restart safeskill-agent
    fi

    sleep 2

    # Verify the service is running
    local socket="${SAFESKILL_SOCKET:-/tmp/safeskill.sock}"
    if [[ -S "$socket" ]]; then
        local health
        health=$(curl -sf --max-time 3 --unix-socket "$socket" http://localhost/health 2>/dev/null || echo "")
        if echo "$health" | grep -q '"healthy"'; then
            log_info "Service restarted and healthy"
            return 0
        fi
    fi

    log_warn "Service may not have started correctly. Check logs."
    return 0
}

# ---------- Rollback ----------
rollback() {
    log_error "Update failed. Rolling back..."

    cd "$INSTALL_DIR"
    local prev_version_file="$INSTALL_DIR/.safeskill-prev-version"

    if [[ -f "$prev_version_file" ]]; then
        local prev
        prev=$(cat "$prev_version_file")
        git checkout "$prev" --quiet 2>/dev/null || {
            log_error "Rollback failed. Manual intervention needed."
            return 1
        }
        rebuild_venv || true
        restart_service || true
        log_warn "Rolled back to $(echo "$prev" | cut -c1-8)"
    else
        log_error "No previous version recorded. Cannot rollback."
    fi
}

# ---------- Main ----------
main() {
    parse_args "$@"
    detect_os
    acquire_lock

    mkdir -p "$LOG_DIR" 2>/dev/null || true

    log_info "=== SafeSkillAgent Update Check ==="
    log_info "Install dir: $INSTALL_DIR"
    log_info "Branch: $GIT_BRANCH | Tags mode: $USE_TAGS"

    check_for_updates
    local check_result=$?

    if [[ $check_result -eq 2 ]]; then
        # No updates
        [[ "$CHECK_ONLY" == true ]] && exit 2
        exit 0
    elif [[ $check_result -ne 0 ]]; then
        exit 1
    fi

    if [[ "$CHECK_ONLY" == true ]]; then
        log_info "Update available. Run without --check-only to apply."
        exit 0
    fi

    # Apply the update with rollback on failure
    if apply_update; then
        restart_service
        log_info "=== Update Complete ==="
    else
        rollback
        exit 1
    fi
}

main "$@"
