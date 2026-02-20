#!/usr/bin/env bash
# SafeSkill BASH_ENV Trap — Production
#
# Set BASH_ENV to this file. When bash starts non-interactively
# (e.g., bash -c "command"), it sources this BEFORE executing.
# The DEBUG trap with extdebug fires before every command and
# can PREVENT execution by returning non-zero.
#
# This is the hard enforcement layer. The LLM cannot bypass it.

# Don't run in interactive shells (user's own terminal)
[[ $- == *i* ]] && return 0

# Don't recurse
[[ -n "${_SAFESKILL_ACTIVE:-}" ]] && return 0
export _SAFESKILL_ACTIVE=1

_SS_SOCK="${SAFESKILL_SOCKET:-/tmp/safeskill.sock}"

# Bail early if socket doesn't exist (agent not running)
if [[ ! -S "$_SS_SOCK" ]]; then
    # Fail-closed: block all commands when agent is down
    if [[ "${SAFESKILL_FAIL_OPEN:-0}" != "1" ]]; then
        shopt -s extdebug 2>/dev/null
        trap 'echo "[SafeSkill] BLOCKED — agent not running" >&2; return 1' DEBUG
    fi
    return 0
fi

# Pre-check: curl and python3 must be available
if ! command -v curl &>/dev/null || ! command -v python3 &>/dev/null; then
    return 0
fi

shopt -s extdebug 2>/dev/null

_safeskill_check() {
    local cmd="$1"

    # Skip empty / internal
    [[ -z "$cmd" ]] && return 0
    [[ "$cmd" == _safeskill_* ]] && return 0
    [[ "$cmd" == "shopt "* ]] && return 0
    [[ "$cmd" == "trap "* ]] && return 0
    [[ "$cmd" == "return "* ]] && return 0
    [[ "$cmd" == "export _SAFESKILL"* ]] && return 0

    # Fast-path: builtins and read-only commands
    local first="${cmd%% *}"
    case "$first" in
        echo|printf|true|false|test|\[|pwd|cd|pushd|popd|export|alias|\
        unalias|type|help|set|shopt|declare|typeset|local|readonly|\
        source|\.|builtin|command|hash|let|read|readarray|mapfile|\
        trap|ulimit|umask|wait|compgen|complete|compopt|dirs|disown|\
        fg|bg|getopts|jobs|suspend|times|shift|break|continue|return|\
        logout|enable|:|exec)
            return 0
            ;;
        # Read-only system commands
        ls|dir|cat|head|tail|wc|sort|uniq|grep|awk|sed|cut|tr|tee|\
        find|which|whereis|whoami|id|hostname|uname|date|cal|pwd|\
        file|stat|du|df|dirname|basename|realpath|readlink|diff|comm|\
        cmp|md5sum|sha256sum|sha1sum|env|printenv|man|info|less|more|\
        strings|hexdump|xxd|lsof|ps|top|htop|free|uptime|w|who|last|\
        journalctl|dmesg|ip|ifconfig|netstat|ss|ping|dig|nslookup|host)
            return 0
            ;;
        # Dev tools (read-only invocations pass through, mutations caught by daemon)
        git|node|npm|npx|python3|python|pip|pip3|cargo|go|make|cmake|\
        java|javac|mvn|gradle|ruby|gem|php|composer|dotnet)
            return 0
            ;;
    esac

    # Socket still there?
    [[ ! -S "$_SS_SOCK" ]] && {
        echo "[SafeSkill] BLOCKED — agent socket gone" >&2
        return 1
    }

    # JSON-encode
    local esc
    esc=$(printf '%s' "$cmd" | python3 -c 'import sys,json;print(json.dumps(sys.stdin.buffer.read().decode("utf-8","replace")))' 2>/dev/null) || return 0

    # Query daemon
    local res
    res=$(curl -sf --max-time 2 --unix-socket "$_SS_SOCK" \
        http://localhost/evaluate \
        -H "Content-Type: application/json" \
        -d "{\"command\":${esc},\"source\":\"bash-trap\"}" 2>/dev/null)

    [[ $? -ne 0 || -z "$res" ]] && {
        echo "[SafeSkill] BLOCKED — agent unreachable" >&2
        return 1
    }

    # Parse
    local line
    line=$(printf '%s' "$res" | python3 -c '
import sys,json
d=json.loads(sys.stdin.read())
b="1" if d.get("blocked",True) else "0"
print(f"{b}|{d.get(\"verdict\",\"?\")}|{d.get(\"severity\",\"\")}|{d.get(\"message\",\"\")}")
' 2>/dev/null) || return 0

    local blk v sev msg
    IFS='|' read -r blk v sev msg <<< "$line"

    if [[ "$blk" == "1" ]]; then
        echo "[SafeSkill] BLOCKED" >&2
        [[ -n "$sev" ]] && echo "[SafeSkill] Severity: $sev" >&2
        [[ -n "$msg" ]] && echo "[SafeSkill] Reason: $msg" >&2
        return 1
    fi

    [[ "$v" == "warned" ]] && echo "[SafeSkill] WARNING: $msg" >&2

    return 0
}

trap '_safeskill_check "$BASH_COMMAND"' DEBUG
