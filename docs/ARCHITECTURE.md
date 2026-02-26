# SafeSkill + OpenClaw: Deep Architecture & Execution Model

**A full-stack technical explanation of how SafeSkill intercepts and evaluates shell commands in the OpenClaw AI agent stack.**

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [OpenClaw Overview](#2-openclaw-overview)
3. [OpenClaw Shell Execution Flow](#3-openclaw-shell-execution-flow)
4. [SafeSkill Architecture](#4-safeskill-architecture)
5. [OS-Level Interception: BASH_ENV & DEBUG Trap](#5-os-level-interception-bash_env--debug-trap)
6. [The SafeSkill Daemon](#6-the-safeskill-daemon)
7. [End-to-End Data Flow](#7-end-to-end-data-flow)
8. [Process Model & Deployment](#8-process-model--deployment)
9. [Security Model & Threat Coverage](#9-security-model--threat-coverage)
10. [Verification & Troubleshooting](#10-verification--troubleshooting)

---

## 1. Executive Summary

**SafeSkill** is a command-security daemon that sits between an AI agent and the shell. It **never executes commands**—it only evaluates them and returns allow/block verdicts. **OpenClaw** is an AI assistant platform that gives an LLM tools (e.g., run shell commands, send messages). SafeSkill integrates by intercepting the shell at the OS level (via bash's `BASH_ENV` and `DEBUG` trap) so that **every** command the agent tries to run is checked before it executes.

**Key invariants:**
- The LLM cannot bypass SafeSkill; interception happens in the shell, not in the application layer.
- SafeSkill is fail-closed: if the daemon is unreachable, all non-fast-path commands are blocked.
- Logging is SIEM-ready: every evaluate request produces an audit record with hostname, user, command, verdict.

---

## 2. OpenClaw Overview

**OpenClaw** is an AI assistant platform (TUI, Web UI, messaging integrations). It provides:

- **Gateway**: WebSocket server that coordinates agents, tools, and channels.
- **Agent**: LLM-backed assistant with tools (e.g., `exec`, `web_search`, `send_message`).
- **Tools**: The `exec` tool runs shell commands on behalf of the agent.
- **Workspace**: Files like `SOUL.md`, `BOOTSTRAP.md` define the agent's identity and constraints.

### High-Level OpenClaw Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  User / Client                                                               │
│  (TUI, Web UI, Telegram, Slack, etc.)                                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  OpenClaw Gateway (Node.js)                                                  │
│  - WebSocket server (default port 18789)                                     │
│  - Routes tool calls from agents                                             │
│  - Manages sessions, approvals, channel routing                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
            ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
            │  exec tool   │ │ other tools  │ │  node host   │
            │  (shell)     │ │ (web_search,  │ │  (macOS app, │
            │              │ │  message...)  │ │  headless)   │
            └──────────────┘ └──────────────┘ └──────────────┘
```

### Where Commands Run

The `exec` tool can run commands in different **hosts**:

| Host | Description | Shell Invocation |
|------|-------------|------------------|
| **gateway** | Same machine as the gateway process | `$SHELL -c "command"` (or equivalent) |
| **sandbox** | Isolated container | `sh -lc "command"` inside container |
| **node** | Paired device (macOS app, headless node) | Forwarded over IPC; node runs locally |

For the typical desktop setup with SafeSkill, commands run on **host=gateway** on the user's Mac. The gateway (Node.js) spawns a child process to execute the command.

---

## 3. OpenClaw Shell Execution Flow

### 3.1 How the Exec Tool Works

When the agent wants to run a command (e.g., `ls -la` or `python3 script.py`), it invokes the `exec` tool. The gateway receives this and:

1. **Resolves host**: gateway, sandbox, or node.
2. **Checks exec approvals**: `~/.openclaw/exec-approvals.json` (allowlist / ask-on-miss).
3. **Spawns the command**: On non-Windows, uses `$SHELL -c "command"` (or falls back to `/bin/bash` or similar).
4. **Streams output** back to the agent.

OpenClaw's source is external (npm package). From integration docs and behavior:

- **Gateway-host exec**: `child_process.spawn` or equivalent with `$SHELL -c "command"`.
- **Shell**: Inherits from the gateway process environment. If `SHELL` is unset, a default (e.g. `/bin/bash`) is used.

### 3.2 Environment Inheritance

The gateway runs as a process (LaunchAgent, systemd, or foreground). Its **environment variables** are passed to child processes. So:

- If the gateway has `BASH_ENV=/opt/safeskill/safeskill-trap.sh` and `SAFESKILL_SOCKET=/tmp/safeskill.sock` in its env,
- And it spawns `bash -c "command"` (or `$SHELL -c "command"` with `SHELL=/bin/bash`),
- Then the child bash process **inherits** `BASH_ENV` and will source that file before running the command.

This is the critical hook for SafeSkill interception.

---

## 4. SafeSkill Architecture

SafeSkill has two main components:

1. **Daemon** (Python): Long-running process that evaluates commands and writes audit logs.
2. **Trap** (Bash script): Runs inside the shell **before** each command; asks the daemon and can block execution.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Agent says: "run cat /etc/passwd"                                           │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Gateway: spawns bash -c "cat /etc/passwd"                                   │
│  (inherits BASH_ENV from gateway env)                                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Bash starts → sources BASH_ENV (safeskill-trap.sh) → DEBUG trap installed   │
│  → trap runs BEFORE "cat /etc/passwd"                                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Trap: curl --unix-socket /var/run/safeskill/safeskill.sock POST /evaluate    │
│  Body: {"command":"cat /etc/passwd","source":"bash-trap","user":"test3"}      │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  SafeSkill Daemon                                                            │
│  - Receives request on Unix socket                                          │
│  - Evaluator: policies + signatures + trust mode                             │
│  - Returns: {"blocked":true,"verdict":"blocked","message":"..."}              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Trap: if blocked → return 1 (DEBUG trap) → bash aborts command              │
│        if allowed → return 0 → bash proceeds to run "cat /etc/passwd"        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. OS-Level Interception: BASH_ENV & DEBUG Trap

### 5.1 BASH_ENV (Bash Built-in Behavior)

From the Bash manual:

> If this parameter is set when Bash is started in non-interactive mode, its value is expanded and used as the name of a file to read and execute before the shell runs.

**Non-interactive** means:
- `bash -c "command"`
- `bash script.sh`
- Not: `bash` (interactive login), or `bash -i`

So when the gateway runs `bash -c "ls -la"`:
1. Bash starts in non-interactive mode.
2. If `BASH_ENV` is set (e.g. `/opt/safeskill/safeskill-trap.sh`), bash **sources** that file.
3. The trap script runs, sets up the DEBUG trap, then exits (or stays in context).
4. Bash then runs the actual command—but **before** that, the DEBUG trap fires.

### 5.2 DEBUG Trap + extdebug

The DEBUG trap runs **before every simple command** (and in certain other contexts). With `shopt -s extdebug`:

- The trap runs before the command is executed.
- If the trap handler returns non-zero, the command is **aborted**.

```bash
trap '_safeskill_check "$BASH_COMMAND"' DEBUG
```

- `$BASH_COMMAND`: The command line about to be executed.
- `_safeskill_check`: Calls SafeSkill daemon; returns 0 (allow) or 1 (block).

This is the enforcement point: the shell **never runs** the command if the trap returns 1.

### 5.3 Why BASH_ENV and Not SHELL Replacement?

Two integration options:

| Method | How | Pros | Cons |
|--------|-----|------|------|
| **BASH_ENV** | Set `BASH_ENV=/path/to/trap.sh` in gateway env. Bash sources it before each `bash -c "cmd"`. | No change to `SHELL`; works when gateway uses `bash -c`. | Only works if **bash** is the shell. `sh -c` or zsh won't use BASH_ENV. |
| **SHELL replacement** | Set `SHELL=/path/to/safeskill-shell`. Gateway spawns `safeskill-shell -c "cmd"`; wrapper checks daemon, then `exec /bin/bash -c "cmd"`. | Works regardless of default shell. | Gateway must respect `SHELL` and spawn `$SHELL -c`. |

SafeSkill uses **BASH_ENV** because:
- OpenClaw's gateway typically spawns `$SHELL -c` or `bash -c`.
- On macOS, `/bin/sh` is often bash-compatible.
- Minimal config: set two env vars in the gateway plist.

### 5.4 What Gets Intercepted

**Intercepted:**
- Commands run by the OpenClaw agent via the gateway.
- Any `bash -c "command"` spawned by a process that has `BASH_ENV` set.

**Not intercepted:**
- Commands you type in your own terminal (no `BASH_ENV` there).
- Commands run by cron, launchd, or other services (they don't inherit the gateway env).
- Commands run by `sh -c` when `sh` is not bash (e.g. dash).

---

## 6. The SafeSkill Daemon

### 6.1 Process Model

- **Binary**: `/usr/local/bin/safeskill-agent` → symlink to `/opt/safeskill/venv/bin/safeskill`
- **Service**: launchd (macOS) or systemd (Linux)
- **Plist**: `com.safeskill.agent` in `/Library/LaunchDaemons/`
- **Runs as**: root (to read /etc/safeskill, write /var/log/safeskill)

### 6.2 IPC: Unix Domain Socket

The daemon listens on a **Unix domain socket** (not TCP):

- **Path**: `/var/run/safeskill/safeskill.sock` (default) — root-owned directory prevents symlink/replacement attacks
- **Directory**: `/var/run/safeskill/` created at install, mode 0755 root:wheel; only daemon can create socket
- **Permissions**: Socket 0666 so non-root OpenClaw can connect
- **Protocol**: HTTP-like over the socket (aiohttp `UnixSite`)

**Authentication:**
- **Client token**: Daemon generates at startup, writes to `/var/run/safeskill/client.token` (0644). Trap reads and sends `X-SafeSkill-Token` header. Required for `/evaluate`.
- **Admin token**: Stored in `/etc/safeskill/admin.token` (0600 root). Required for `/trust-mode`, `/policy/reload`, `/policy/inject`, `/environment`. Use `sudo safeskill set-trust` etc.

The trap connects with:
```bash
TOKEN=$(cat /var/run/safeskill/client.token)
curl --unix-socket /var/run/safeskill/safeskill.sock http://localhost/evaluate \
  -H "X-SafeSkill-Token: $TOKEN" -d '{"command":"..."}'
```

### 6.3 Request/Response

**Request** (`POST /evaluate`):
```json
{
  "command": "cat /etc/passwd",
  "source": "bash-trap",
  "user": "test3"
}
```

**Response** (blocked):
```json
{
  "blocked": true,
  "verdict": "blocked",
  "severity": "critical",
  "message": "Data exfiltration pattern matched",
  "matched_rules": ["data-exfil-passwd"],
  "matched_signatures": ["DATA_EXFIL"]
}
```

**Response** (allowed):
```json
{
  "blocked": false,
  "verdict": "allowed"
}
```

### 6.4 Evaluation Pipeline

```
EvaluationRequest
       │
       ▼
┌──────────────────┐
│ TrustEnforcer    │  zero-trust allowlist, strict blocklist
└──────────────────┘
       │
       ▼
┌──────────────────┐
│ PolicyManager    │  base-policy.yaml, runtime-policy.yaml, env overrides
│ (regex rules)    │
└──────────────────┘
       │
       ▼
┌──────────────────┐
│ SignatureManager │  signatures.yaml (categories: reverse-shell, data-exfil, etc.)
└──────────────────┘
       │
       ▼
┌──────────────────┐
│ CommandEvaluator │  hardcoded patterns + policy + signatures
│                  │  → Verdict (allowed | blocked | warned)
└──────────────────┘
       │
       ▼
EvaluationResult → AuditLogger.log_evaluation() → JSONL file
```

### 6.5 Evaluator Logic (Simplified)

1. **Metacharacter guard**: Commands containing `;`, `&`, `|`, `` ` ``, or `$(` never use fast-path — they always go to the daemon. Prevents `echo x; rm -rf /` bypass.
2. **Fast-path**: Only truly passive builtins (e.g. `echo`, `pwd`, `cd`) skip daemon. Execution-capable commands (`exec`, `find`, `awk`, `sed`, `git`, `make`, etc.) always go to the daemon.
2. **Trust mode**: normal | strict | zero-trust. Affects severity→verdict mapping.
3. **Pattern matching**: Regex against the command string for:
   - Reverse shells, pipe-to-shell
   - Data exfiltration (`cat /etc/passwd`, etc.)
   - Privilege escalation
   - Disk wipe, fork bomb
   - Skill/daemon tampering
4. **Policy rules**: YAML-defined patterns with severity and action.
5. **Signature rules**: Category-based patterns from signatures.yaml.

### 6.6 Audit Logging

- **Path**: `/var/log/safeskill/audit-YYYY-MM-DD.jsonl`
- **Format**: One JSON object per line (JSONL)
- **Fields**: insert_timestamp, event_timestamp, hostname, event_action, event_outcome, blocked, system_command, user_name, source_ip, source, severity, matched_rules, matched_signatures, message

Example (allowed):
```json
{"insert_timestamp":"2026-02-22T12:00:00.000000Z","event_action":"evaluate","event_outcome":"allowed","blocked":false,"system_command":"echo hello","user_name":"test3","source":"bash-trap"}
```

Example (blocked):
```json
{"insert_timestamp":"2026-02-22T12:00:01.000000Z","event_action":"evaluate","event_outcome":"blocked","blocked":true,"system_command":"cat /etc/passwd","matched_rules":["data-exfil-passwd"]}
```

---

## 7. End-to-End Data Flow

```
User in TUI: "run cat /etc/passwd"
        │
        ▼
OpenClaw TUI → WebSocket → Gateway (Node)
        │
        ▼
Gateway: exec tool invoked, host=gateway
        │
        ▼
Gateway: child_process.spawn($SHELL, ["-c", "cat /etc/passwd"])
        │  Env: BASH_ENV=/opt/safeskill/safeskill-trap.sh, SAFESKILL_SOCKET=/var/run/safeskill/safeskill.sock
        ▼
/bin/bash -c "cat /etc/passwd"
        │
        ├─ 1. Non-interactive: bash sources BASH_ENV → safeskill-trap.sh
        ├─ 2. Trap sets: trap '_safeskill_check "$BASH_COMMAND"' DEBUG
        ├─ 3. Bash is about to run "cat /etc/passwd"
        ├─ 4. DEBUG trap fires → _safeskill_check "cat /etc/passwd"
        │
        ▼
_safeskill_check:
  - "cat" not in fast-path (cat is excluded for daemon to check paths)
  - curl --unix-socket /var/run/safeskill/safeskill.sock POST /evaluate (with X-SafeSkill-Token)
  - Body: {"command":"cat /etc/passwd","source":"bash-trap","user":"test3"}
        │
        ▼
SafeSkill Daemon (aiohttp):
  - Parses request
  - CommandEvaluator.evaluate()
  - DATA_EXFIL_PATTERNS match "cat /etc/passwd"
  - Returns verdict: blocked
  - AuditLogger: writes JSONL line
        │
        ▼
Trap receives: {"blocked":true,"verdict":"blocked",...}
  - return 1 (DEBUG trap)
        │
        ▼
Bash: trap returned 1 → command aborted
  - Prints "[SafeSkill] BLOCKED" to stderr
  - Exit code non-zero
        │
        ▼
Gateway: child process failed → returns error to agent
Agent: "Command was blocked by SafeSkill."
```

---

## 8. Process Model & Deployment

### 8.1 Process Tree (Typical macOS)

```
launchd (system)
  └── com.safeskill.agent (root)
        └── Python safeskill-agent start
              └── aiohttp server (listening on /var/run/safeskill/safeskill.sock)

launchd (gui/501)
  └── ai.openclaw.gateway (test3)
        └── node openclaw gateway --port 18789
              └── (when exec runs) bash -c "command"
                    └── (trap sources BASH_ENV, DEBUG trap runs)
                    └── curl → /var/run/safeskill/safeskill.sock
                    └── (if allowed) cat /etc/passwd  [blocked in this case]
```

### 8.2 Key Files

| Purpose | Path |
|---------|------|
| SafeSkill daemon plist | `/Library/LaunchDaemons/com.safeskill.agent.plist` |
| OpenClaw gateway plist | `~/Library/LaunchAgents/ai.openclaw.gateway.plist` |
| Trap script | `/opt/safeskill/safeskill-trap.sh` |
| Daemon config | `/etc/safeskill/agent.yaml` |
| Policies | `/etc/safeskill/base-policy.yaml`, `runtime-policy.yaml`, `signatures.yaml` |
| Audit logs | `/var/log/safeskill/audit-YYYY-MM-DD.jsonl` |
| Socket | `/var/run/safeskill/safeskill.sock` |
| OpenClaw config | `~/.openclaw/openclaw.json` |
| SOUL.md (agent identity) | `~/.openclaw/workspace/SOUL.md` |

### 8.3 Environment Variables (Gateway Must Have)

For interception to work, the **gateway** process must have:

- `BASH_ENV=/opt/safeskill/safeskill-trap.sh` (or `~/.safeskill-trap.sh`)
- `SAFESKILL_SOCKET=/var/run/safeskill/safeskill.sock`

These are typically set in:
- The LaunchAgent plist `EnvironmentVariables` (if OpenClaw install writes them from config)
- Or by starting the gateway as: `BASH_ENV=... SAFESKILL_SOCKET=/var/run/safeskill/safeskill.sock openclaw gateway start`

---

## 9. Security Model & Threat Coverage

### 9.1 Defense in Depth

| Layer | Mechanism | Bypassable by Agent? |
|-------|------------|----------------------|
| SOUL.md | Immutable Security block in agent identity; LLM refuses harmful requests | Yes (LLM can be prompted to ignore) |
| SafeSkill trap | OS-level; runs before command in bash | No (enforced by shell) |
| Exec approvals | OpenClaw allowlist/ask-on-miss | No (enforced by gateway) |

### 9.2 Threat Categories (Evaluator)

- **Data exfiltration**: `cat /etc/passwd`, `cat /etc/shadow`, curl with sensitive paths
- **Reverse shells**: bash -i /dev/tcp, nc -e, ncat -e
- **Privilege escalation**: chmod +s, sudoers modification
- **Destructive**: rm -rf /, mkfs, dd to disk, shred
- **Obfuscation**: base64 decode, hex escape sequences
- **Self-tampering**: Stopping/unloading SafeSkill, killing daemon

### 9.3 Fail-Closed

If the daemon is down or unreachable:
- Trap gets curl error or empty response
- Trap treats as blocked, returns 1
- Command never runs

---

## 10. Interception Scope & Limits

### 10.1 What SafeSkill Intercepts

| Intercepted | How |
|-------------|-----|
| **Shell commands** | Every `bash -c "command"` run on the **host** (gateway) goes through the trap. The trap sends the full command string to the daemon before execution. |
| **Policy evaluation** | Daemon checks against `base-policy.yaml`, `signatures.yaml`, trust mode, and hardcoded patterns. |
| **Allow/block** | Verdict returned before the command runs. Blocked commands never execute. |

### 10.2 What SafeSkill Does NOT Intercept

| Not intercepted | Why |
|-----------------|-----|
| **Commands in the sandbox** | When OpenClaw uses `host=sandbox`, exec runs inside a Docker container with `sh -lc "command"`. That process is **not** on the host. No BASH_ENV, no trap, no daemon. |
| **Python `import os`** | That's Python code, not a shell command. SafeSkill only sees shell invocations like `python3 -c "..."` or `python3 script.py`. |
| **File reads via `open()`** | Python/Node file I/O is not a shell command. SafeSkill never sees it. |
| **Direct syscalls** | Any syscall (read, write, execve) that doesn't go through the shell is invisible to SafeSkill. |

### 10.3 Sandbox vs Host

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  host=gateway (on your Mac)                                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  bash -c "command"  →  BASH_ENV trap  →  SafeSkill daemon  →  allow  │   │
│  │  Commands run on host. SafeSkill intercepts ALL of them.            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  host=sandbox (Docker container)                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  sh -lc "command"  →  runs inside container                         │   │
│  │  No BASH_ENV. No trap. No SafeSkill. Commands never touch the host.  │   │
│  │  Container is isolated; typically only workspace is mounted.         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Sandbox isolation:** The sandbox is a container. It does NOT have arbitrary host access. It typically mounts only the workspace directory. So even without SafeSkill, the sandbox cannot read `/etc/passwd` or wipe the host—it's isolated. SafeSkill adds host-level enforcement when exec runs **on the host**.

### 10.4 Required Config for Full Interception

To intercept **every** command the agent runs, exec must run on the host:

| Setting | Purpose |
|---------|---------|
| `tools.exec.host: "gateway"` | Run exec on the host instead of sandbox |
| `agents.defaults.sandbox.mode: "off"` | Disable sandbox so sessions can use host exec |
| `SHELL: "/bin/bash"` (in gateway plist) | Force bash so BASH_ENV trap works (zsh ignores it) |
| `BASH_ENV`, `SAFESKILL_SOCKET` | Already set by SafeSkill install |

Without these, OpenClaw defaults to `host=sandbox`, and SafeSkill never sees the commands.

### 10.5 Intercepting `import os`, File Reads, etc.

SafeSkill evaluates **shell command strings**. It cannot intercept:

- Python `import os` or `open("/etc/passwd")`
- Node.js `fs.readFileSync()`
- Any syscall or library call

To enforce policy on those would require:

- **Runtime instrumentation** (e.g. a Python sandbox that intercepts syscalls)
- **eBPF/syscall tracing** at the kernel level
- **Container isolation** with strict mounts (sandbox already does this)

That is a different architecture. SafeSkill focuses on **shell command interception**—the primary vector for agent-triggered system changes.

---

## 11. Verification & Troubleshooting

### 11.1 Checklist

| Check | Command |
|-------|---------|
| Daemon running | `ps aux \| grep safeskill` |
| Socket exists | `ls -la /var/run/safeskill/safeskill.sock` |
| Gateway has BASH_ENV | Inspect plist: `cat ~/Library/LaunchAgents/ai.openclaw.gateway.plist` |
| Trap exists | `ls -la /opt/safeskill/safeskill-trap.sh` |
| Trap works | `BASH_ENV=/opt/safeskill/safeskill-trap.sh bash -c 'echo ok'` |
| Block test | In TUI: "run cat /etc/passwd" → should see [SafeSkill] BLOCKED |
| Audit log | `sudo tail -f /var/log/safeskill/audit-$(date +%Y-%m-%d).jsonl` |

### 11.2 No Evaluate Events in Log?

- **Cause**: Commands not going through bash with BASH_ENV, or trap fast-path bypassing daemon.
- **Fix**: Ensure gateway plist has `BASH_ENV` and `SAFESKILL_SOCKET`. Restart gateway. Check that `python3`/`node` are no longer in trap fast-path (they should go to daemon for logging).
- **If using sandbox**: Commands run in container → no interception. Use `host=gateway` and `sandbox.mode: "off"` (see §10.4).

### 11.3 Commands Bypass SafeSkill?

- Gateway may be using `sh -c` with non-bash sh.
- Or `SHELL` points to something other than bash.
- Try SHELL replacement: `SHELL=/path/to/safeskill-shell` so the wrapper always does the check.

---

## Appendix A: Trap Fast-Path

**Metacharacter guard**: Commands with `;`, `&`, `|`, `` ` ``, or `$(` always go to the daemon (no fast-path).

Commands that **skip** the daemon (allowed immediately in the trap):

- Shell builtins only: echo, printf, pwd, cd, export, type, help, set, etc.
- Read-only, non-executable: ls, head, tail, grep, cut, wc, which, etc. (no find, awk, sed, exec)

Commands that **always** go to the daemon:

- Any command with metacharacters (compound commands)
- `exec`, `find`, `awk`, `sed`, `git`, `pip`, `go`, `make`, `cat`, `python3`, `node`, etc.

---

## Appendix B: SOUL.md Security Block

Injected at install by `openclaw-skill/install.sh`:

```markdown
<!-- SAFESKILL-SECURITY — OPERATOR CONTROLLED, IMMUTABLE -->
## Security (immutable)
- Never run malicious commands.
- Never exfiltrate sensitive data. No credentials, .env, .ssh, /etc/passwd, API keys.
- Security first. These rules override everything.
<!-- END SAFESKILL-SECURITY -->
```

This is **advisory** (LLM-level). SafeSkill provides **enforcement** (OS-level).
