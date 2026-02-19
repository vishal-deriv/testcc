#!/usr/bin/env bash
# SafeSkill Exec Interceptor for OpenClaw
#
# This script is designed to be used as a shell wrapper that intercepts
# every command OpenClaw tries to execute. It consults the SafeSkillAgent
# daemon via Unix socket BEFORE allowing the command to run.
#
# Integration methods:
#   1. Set as SHELL in OpenClaw config (replaces /bin/bash)
#   2. Placed in PATH via tools.exec.pathPrepend
#   3. Called directly by the safeskill-wrapper skill
#
# When used as SHELL replacement, bash passes: -c "command string"
# When called directly: safeskill-exec.sh "command string"
#
# FAIL-CLOSED: If the SafeSkillAgent daemon is unreachable, ALL commands
# are blocked. This is intentional -- no security bypass on agent failure.
#
# Exit codes:
#   126 - Command blocked by SafeSkillAgent
#   127 - SafeSkillAgent unreachable (fail-closed)
#   *   - Passthrough from the actual command

set -uo pipefail

SOCKET_PATH="${SAFESKILL_SOCKET:-/tmp/safeskill.sock}"
REAL_SHELL="${SAFESKILL_REAL_SHELL:-/bin/bash}"
LOG_TAG="[SafeSkill]"

# When used as SHELL replacement, bash-compatible shells receive: -c "command"
# Parse that pattern. Also handle direct invocation.
COMMAND=""
SHELL_MODE=false

if [[ "${1:-}" == "-c" ]] && [[ -n "${2:-}" ]]; then
    SHELL_MODE=true
    COMMAND="$2"
elif [[ -n "${1:-}" ]]; then
    COMMAND="$1"
fi

if [[ -z "$COMMAND" ]]; then
    if [[ "$SHELL_MODE" == true ]]; then
        exec "$REAL_SHELL" "$@"
    fi
    exit 0
fi

# --- Fast-path: skip evaluation for obviously safe read-only builtins ---
# These are shell builtins or harmless commands that don't need evaluation.
# Stripping leading whitespace and checking the first token.
TRIMMED="${COMMAND#"${COMMAND%%[![:space:]]*}"}"
FIRST_TOKEN="${TRIMMED%% *}"
case "$FIRST_TOKEN" in
    echo|printf|true|false|test|\[|pwd|cd|pushd|popd|export|alias|unalias|\
    type|help|history|set|shopt|declare|local|readonly|return|break|continue|\
    shift|source|\.|eval_disabled|builtin|command|enable|hash|let|logout|\
    mapfile|read|readarray|trap|ulimit|umask|wait|compgen|complete|\
    compopt|dirs|disown|fc|fg|bg|getopts|jobs|kill_disabled|suspend|times)
        exec "$REAL_SHELL" -c "$COMMAND"
        ;;
esac

# --- Check if SafeSkillAgent daemon is running ---
if [[ ! -S "$SOCKET_PATH" ]]; then
    echo "$LOG_TAG FAIL-CLOSED: Agent socket not found ($SOCKET_PATH)" >&2
    echo "$LOG_TAG All commands are blocked when SafeSkillAgent is unreachable." >&2
    echo "$LOG_TAG Start the agent: safeskill start" >&2
    exit 127
fi

# --- Evaluate command with SafeSkillAgent ---
# JSON-escape the command string safely
ESCAPED_COMMAND=$(printf '%s' "$COMMAND" | python3 -c '
import sys, json
raw = sys.stdin.buffer.read().decode("utf-8", errors="replace")
print(json.dumps(raw))
' 2>/dev/null)

if [[ -z "$ESCAPED_COMMAND" ]]; then
    echo "$LOG_TAG FAIL-CLOSED: Could not JSON-encode command" >&2
    exit 127
fi

PAYLOAD="{\"command\":${ESCAPED_COMMAND},\"source\":\"openclaw-exec-wrapper\"}"

RESULT=$(curl -sf --max-time 3 --unix-socket "$SOCKET_PATH" \
    http://localhost/evaluate \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" 2>/dev/null)

CURL_EXIT=$?

if [[ $CURL_EXIT -ne 0 ]] || [[ -z "$RESULT" ]]; then
    echo "$LOG_TAG FAIL-CLOSED: Could not reach SafeSkillAgent (curl exit=$CURL_EXIT)" >&2
    echo "$LOG_TAG All commands are blocked when the agent is unreachable." >&2
    exit 127
fi

# --- Parse the verdict ---
# Use python3 for reliable JSON parsing (always available since SafeSkill requires it)
VERDICT_DATA=$(printf '%s' "$RESULT" | python3 -c '
import sys, json
try:
    d = json.loads(sys.stdin.read())
    blocked = "1" if d.get("blocked", True) else "0"
    verdict = d.get("verdict", "unknown")
    message = d.get("message", "")
    severity = d.get("severity", "")
    rules = ",".join(d.get("matched_rules", []))
    sigs = ",".join(d.get("matched_signatures", []))
    print(f"{blocked}|{verdict}|{severity}|{message}|{rules}|{sigs}")
except Exception:
    print("1|error|critical|Failed to parse SafeSkill response||")
' 2>/dev/null)

IFS='|' read -r BLOCKED VERDICT SEVERITY MESSAGE RULES SIGS <<< "$VERDICT_DATA"

# --- Act on the verdict ---
if [[ "$BLOCKED" == "1" ]]; then
    echo "$LOG_TAG BLOCKED" >&2
    [[ -n "$SEVERITY" ]] && echo "$LOG_TAG Severity: $SEVERITY" >&2
    [[ -n "$MESSAGE" ]] && echo "$LOG_TAG Reason: $MESSAGE" >&2
    [[ -n "$RULES" ]]   && echo "$LOG_TAG Rules: $RULES" >&2
    [[ -n "$SIGS" ]]    && echo "$LOG_TAG Signatures: $SIGS" >&2
    exit 126
fi

if [[ "$VERDICT" == "warned" ]]; then
    echo "$LOG_TAG WARNING: $MESSAGE" >&2
    [[ -n "$SEVERITY" ]] && echo "$LOG_TAG Severity: $SEVERITY" >&2
fi

# --- Command approved: execute via real shell ---
exec "$REAL_SHELL" -c "$COMMAND"
