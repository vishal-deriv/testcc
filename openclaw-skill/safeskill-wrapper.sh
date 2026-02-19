#!/usr/bin/env bash
# SafeSkill Direct Command Wrapper
#
# Evaluate a command with SafeSkillAgent, then execute it only if approved.
# Use this for manual/script invocation (not as a SHELL replacement).
# For SHELL replacement, use safeskill-exec.sh instead.
#
# Usage: safeskill-wrapper.sh "command to check and execute"
#
# Exit codes:
#   0   - Command executed successfully
#   126 - Command was blocked by SafeSkill
#   127 - SafeSkill agent is not running (fail-closed)
#   *   - Command's own exit code

set -uo pipefail

SOCKET_PATH="${SAFESKILL_SOCKET:-/tmp/safeskill.sock}"
COMMAND="${1:-}"

if [[ -z "$COMMAND" ]]; then
    echo "Usage: safeskill-wrapper.sh \"command\"" >&2
    exit 127
fi

if [[ ! -S "$SOCKET_PATH" ]]; then
    echo "[SafeSkill] FAIL-CLOSED: Agent not running (socket: $SOCKET_PATH)" >&2
    echo "[SafeSkill] Refusing to execute without security evaluation." >&2
    echo "[SafeSkill] Start agent: safeskill start" >&2
    exit 127
fi

ESCAPED_COMMAND=$(printf '%s' "$COMMAND" | python3 -c '
import sys, json
raw = sys.stdin.buffer.read().decode("utf-8", errors="replace")
print(json.dumps(raw))
' 2>/dev/null)

if [[ -z "$ESCAPED_COMMAND" ]]; then
    echo "[SafeSkill] FAIL-CLOSED: Could not encode command" >&2
    exit 127
fi

PAYLOAD="{\"command\":${ESCAPED_COMMAND},\"source\":\"openclaw-wrapper\"}"

RESULT=$(curl -sf --max-time 3 --unix-socket "$SOCKET_PATH" \
    http://localhost/evaluate \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" 2>/dev/null)

if [[ $? -ne 0 ]] || [[ -z "$RESULT" ]]; then
    echo "[SafeSkill] FAIL-CLOSED: Could not reach agent" >&2
    exit 127
fi

VERDICT_DATA=$(printf '%s' "$RESULT" | python3 -c '
import sys, json
try:
    d = json.loads(sys.stdin.read())
    blocked = "1" if d.get("blocked", True) else "0"
    verdict = d.get("verdict", "unknown")
    message = d.get("message", "")
    severity = d.get("severity", "")
    print(f"{blocked}|{verdict}|{severity}|{message}")
except Exception:
    print("1|error|critical|Failed to parse response")
' 2>/dev/null)

IFS='|' read -r BLOCKED VERDICT SEVERITY MESSAGE <<< "$VERDICT_DATA"

if [[ "$BLOCKED" == "1" ]]; then
    echo "[SafeSkill] BLOCKED" >&2
    [[ -n "$SEVERITY" ]] && echo "[SafeSkill] Severity: $SEVERITY" >&2
    [[ -n "$MESSAGE" ]] && echo "[SafeSkill] Reason: $MESSAGE" >&2
    exit 126
fi

if [[ "$VERDICT" == "warned" ]]; then
    echo "[SafeSkill] WARNING: $MESSAGE" >&2
fi

exec bash -c "$COMMAND"
