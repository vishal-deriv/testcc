# SafeSkill + OpenClaw Integration: Research Findings and Failure Analysis

**Document Version:** 1.1  
**Date:** 2026-02-25  
**Status:** Technical post-mortem and research summary  
**Related:** `docs/ARCHITECTURE.md` (design and data flow)

---

## 1. Purpose

This document records the strategies attempted to integrate SafeSkill (a command-security daemon) with OpenClaw (an AI assistant platform) so that every shell command executed by the agent is intercepted, evaluated, and logged. It summarizes what was tried, what works, what fails, and why. It also provides a concrete problem statement, scope of coverage, and explicit boundaries of what SafeSkill does and does not intercept.

---

## 2. Problem Statement

### 2.1 Core Objective

When an AI agent (LLM) has the ability to run shell commands on a user's machine, it can cause harm: data exfiltration, privilege escalation, reverse shells, destructive operations. The goal is to enforce security at the OS level so that the LLM cannot bypass it, regardless of prompt engineering or jailbreaks.

**Concrete requirements:**

1. **Every command the agent runs must be evaluated before execution.** No command may run without passing through the enforcement layer.
2. **Blocked commands must never execute.** The agent must receive a clear failure signal; the command must not run.
3. **All commands must be logged.** Both allowed and blocked commands must produce audit records for compliance and forensics.
4. **Logs must be SIEM-ready.** Audit records must be in a format suitable for ingestion by SIEM systems (Splunk, Elastic, Datadog, etc.) and optionally forwarded in real time.
5. **Installation must be simple.** The user runs one or two install scripts; no manual LLM prompting, no skill checks, no MD files to maintain. The trap is the gate.

### 2.2 Daemon: Easy to Install

The SafeSkill daemon is designed for one-command installation:

- **Primary installer:** `setup/install-macos.sh` (run as root via `sudo`)
- **Steps:** Installs Xcode CLI tools if needed, Homebrew if needed, Python 3.10+, creates venv at `/opt/safeskill/venv`, installs SafeSkill package, creates config at `/etc/safeskill`, sets up launchd daemon at `/Library/LaunchDaemons/com.safeskill.agent.plist`
- **Result:** Daemon runs as root, listens on Unix socket `/var/run/safeskill/safeskill.sock`, evaluates commands, writes audit logs to `/var/log/safeskill/audit-YYYY-MM-DD.jsonl`
- **SIEM metadata:** At install, the script captures `hostname`, `user`, `source_ip` and writes them to `/etc/safeskill/agent.yaml`. If `.env` contains `SIEM_ENDPOINT_URL` or `API_GATEWAY_BASE_URL`, and optionally `NGSOC_API_KEY` or `SIEM_AUTH_HEADER`, these are written to agent.yaml for real-time forwarding

The daemon itself installs cleanly and works. The failure is not in the daemon; it is in ensuring that every OpenClaw exec invocation reaches the daemon.

### 2.3 SIEM Forwarding

- **Local audit:** Every evaluation is written to JSONL files. Format: `event_timestamp`, `hostname`, `event_action`, `event_outcome`, `blocked`, `risk_score`, `system_command`, `user_name`, `source_ip`, `source`, `severity`, `matched_rules`, `matched_signatures`, `message`
- **Real-time forwarding:** If `siem_endpoint_url` is set in agent.yaml, each audit entry is POSTed to that URL (fire-and-forget, non-blocking). `siem_auth_header` (e.g. Bearer token) is sent if configured
- **Configuration:** Via `.env` at install: `SIEM_ENDPOINT_URL`, `SIEM_AUTH_HEADER`, or `NGSOC_API_KEY` (auto-wrapped as Bearer). OpenClaw skill install calls `update_siem_metadata()` which reads `.env` and patches agent.yaml

SIEM forwarding works for every evaluation that reaches the daemon. The gap: evaluations that never reach the daemon are never logged or forwarded.

**SIEM audit entry schema (JSONL):**

| Field | Type | Description |
|-------|------|-------------|
| `event_timestamp` | ISO8601 | When the evaluation occurred |
| `hostname` | string | Machine hostname (from install) |
| `event_action` | string | Always `"evaluate"` for command evaluations |
| `event_outcome` | string | `"allowed"`, `"blocked"`, or `"warned"` |
| `blocked` | boolean | True if command was blocked |
| `risk_score` | number | 0-100 derived from severity |
| `system_command` | string | The full command string |
| `user_name` | string | User who triggered the command |
| `source_ip` | string | IP (from install) |
| `source` | string | `"bash-trap"`, `"openclaw"`, etc. |
| `severity` | string | `"low"`, `"medium"`, `"high"`, `"critical"` |
| `matched_rules` | array | Policy rule IDs that matched |
| `matched_signatures` | array | Signature IDs that matched |
| `message` | string | Human-readable verdict message |

### 2.4 Command Interception: The Critical Path

Interception must occur at the shell level. The LLM cannot be trusted to self-enforce; it can be prompted to ignore rules. Therefore:

- **Mechanism:** When the gateway spawns a shell to run a command, the shell must run a trap (or wrapper) before executing the command. The trap sends the command string to the daemon; if the daemon returns "blocked," the trap aborts the command.
- **BASH_ENV:** Bash, when started non-interactively (`bash -c "command"`), sources the file named in `BASH_ENV` before running. We install a script that sets a DEBUG trap; the trap runs before every simple command.
- **SHELL replacement:** We set `SHELL` to a wrapper (`safeskill-shell`) so the gateway spawns our wrapper. The wrapper evaluates with the daemon, then execs `bash -c "command"`. Bash then sources BASH_ENV (trap) before running. Dual layer.

**Dependency:** Interception works only if the gateway actually invokes a shell. If the gateway spawns the binary directly (e.g. `execve("/usr/bin/whoami", ["whoami"], env)`), there is no shell, no BASH_ENV, no trap, no wrapper. The command runs without ever touching SafeSkill.

### 2.5 What SafeSkill Does NOT Intercept

SafeSkill evaluates **shell command strings**. It does not intercept:

| Not Intercepted | Explanation |
|-----------------|-------------|
| **Python `import os`** | That is Python code, not a shell command. SafeSkill sees `python3 script.py` or `python3 -c "..."` but not the Python statements inside. |
| **Python `open("/etc/passwd")`** | File I/O inside a Python process. No shell invocation. |
| **Python subprocess / process spawning** | These spawn shell commands. If the Python process was started via `python3 script.py` and that invocation was intercepted, child commands would go through the same shell (if it is a subshell) or a new shell. Behavior depends on how the parent Python was invoked. |
| **Node.js `fs.readFileSync()`** | File I/O. No shell. |
| **Node.js spawning a shell** | When Node spawns a child shell, the child would need BASH_ENV from its parent. If the parent is the gateway's child, it may inherit. If the parent is something else, it may not. |
| **Direct syscalls** | `read()`, `write()`, `execve()` at the kernel level. SafeSkill has no visibility. |
| **eBPF / ptrace** | Kernel or process tracing. Different architecture. |
| **Container isolation** | When OpenClaw uses `host=sandbox`, exec runs inside a container. No BASH_ENV, no trap. Commands never reach the host daemon. |

**Implication:** An agent that runs `python3 -c "print(open('/etc/passwd').read())"` is intercepted once (the `python3 -c "..."` invocation). The daemon evaluates that string. If the policy blocks Python one-liners that read sensitive paths, it can block. But if the agent runs `python3 script.py` and `script.py` contains `open("/etc/passwd").read()`, SafeSkill only sees `python3 script.py`. The evaluator can block based on the script path or allow it; it cannot see or block the `open()` call inside the script.

**Scope boundary:** SafeSkill is intentionally scoped to shell command interception. Python-to-syscall interception (e.g. sandboxing the Python interpreter, intercepting `open()` or process-spawning APIs) would require a different design: a Python sandbox, eBPF, or a modified interpreter. That is out of scope for this integration.

### 2.6 Evaluator Threat Coverage (When Commands Reach the Daemon)

When a command string reaches the daemon, the evaluator checks it against:

| Category | Examples |
|----------|----------|
| **Data exfiltration** | `cat /etc/passwd`, `cat /etc/shadow`, `curl -d @/etc/passwd`, `tar ... \| nc` |
| **Reverse shells** | `bash -i >/dev/tcp/...`, `nc -e bash`, `ncat -e`, `mkfifo ... nc`, Python/Perl/Ruby socket connect |
| **Privilege escalation** | `chmod +s`, `chmod 777`, `echo ... >> /etc/sudoers`, `visudo`, `NOPASSWD` |
| **Destructive** | `rm -rf /`, `mkfs`, `dd of=/dev/sd...`, `shred`, `wipefs` |
| **Obfuscation** | `base64 -d`, hex escapes, `eval` with user input |
| **Self-tampering** | `safeskill disable`, `launchctl unload safeskill`, `kill safeskill`, `rm ... safeskill` |
| **Crypto miners** | `xmrig`, `stratum+tcp://`, `--donate-level` |
| **Metacharacter guard** | Commands with `;`, `&`, `|`, backticks, `$()` always go to daemon (no fast-path) |

Fast-path (allowed in trap without daemon call): only truly passive builtins (`echo`, `pwd`, `cd`, `export`, `type`, `hash`). Commands like `ls`, `whoami`, `ifconfig`, `curl`, `python3`, `node` always go to the daemon. The evaluator never executes commands; it only returns allow/block verdicts.

---

## 3. Reference Architecture

The intended design is documented in `docs/ARCHITECTURE.md`. Key points:

- **SafeSkill daemon**: Evaluates commands via Unix socket; returns allow/block verdicts; writes audit logs.
- **Interception**: Must occur at the shell level so the LLM cannot bypass it.
- **BASH_ENV + DEBUG trap**: When bash starts non-interactively (`bash -c "command"`), it sources `BASH_ENV` before running. A DEBUG trap can run before each command and block execution by returning non-zero.
- **Requirement**: Commands must run on `host=gateway` (not sandbox) and use a shell that honors `BASH_ENV` (bash, not zsh).

---

## 4. Strategies Attempted (Chronological)

### 4.1 Initial Integration (commit a34771f)

- Set `host=gateway` in OpenClaw config to enforce exec-approvals.
- Deployed exec-approvals allowlist.
- Relied on BASH_ENV trap for interception.

**Result:** Exec approvals worked; trap interception depended on gateway using bash and inheriting BASH_ENV.

### 4.2 SHELL Replacement (commits 925abe6, cd4c31e)

- Set `SHELL` to a custom wrapper (`safeskill-shell`) so OpenClaw spawns `$SHELL -c "command"`.
- Wrapper evaluates with daemon, then `exec /bin/bash -c "command"`.
- Rationale: OpenClaw may use `sh` or `zsh`; BASH_ENV is bash-only. Replacing SHELL guarantees our wrapper runs first.

**Result:** Wrapper added; still required gateway to pass SHELL to child processes. OpenClaw docs state: "On non-Windows hosts, exec uses SHELL when set; if SHELL is fish, it prefers bash."

### 4.3 BASH_ENV Trap Injection (commit b2d8611)

- Reverted to BASH_ENV as primary mechanism.
- Patched gateway LaunchAgent plist with `BASH_ENV`, `SAFESKILL_SOCKET`, and `SHELL=/bin/bash`.
- Ensured trap script at `/opt/safeskill/safeskill-trap.sh` (or `~/.safeskill-trap.sh`).

**Result:** Trap works when bash is used. Verified via `verify-interception.sh` (python3 -c "print(...)" appears in audit log).

### 4.4 Production Integration (commit 3f69a1e)

- Combined SHELL wrapper and BASH_ENV.
- Set `SHELL` to `safeskill-shell` so every exec goes through wrapper.
- Wrapper evaluates, then execs `bash -c "command"`; bash sources BASH_ENV (trap) before running the command.
- Config: `tools.exec.host: "gateway"`, `agents.defaults.sandbox.mode: "off"`, `tools.exec.security: "full"`, `tools.exec.ask: "off"`.

**Result:** Dual-layer (wrapper + trap). Commands that reach the shell path are intercepted.

### 4.5 Binary Shim Layer (recent, reverted)

- Added `tools.exec.pathPrepend` with a directory of symlinks to a shim script.
- Shim evaluated each invoked binary (e.g. `whoami`, `ifconfig`) with the daemon before exec'ing the real binary.
- Rationale: OpenClaw might spawn binaries directly (not via `$SHELL -c`), bypassing both wrapper and trap.

**Result:** Shim caused infinite recursion. The shim invokes `python3` and `curl`; with pathPrepend, those resolved to the shim dir, so the shim called itself. Attempted fix: use `PATH=/usr/bin:/bin:...` for helper invocations. Shim still hung in testing. Layer removed.

---

## 5. OpenClaw Configuration (Effective)

The following settings are applied by `openclaw-skill/install.sh`:

| Key | Value | Purpose |
|-----|-------|---------|
| `tools.exec.host` | `"gateway"` | Run exec on host, not sandbox |
| `tools.exec.security` | `"full"` | No allowlist gate; SafeSkill is the enforcement layer |
| `tools.exec.ask` | `"off"` | No interactive approval prompts |
| `agents.defaults.sandbox.mode` | `"off"` | Disable sandbox so host exec is allowed |
| `commands.native` | `"auto"` | Chat slash commands (not exec behavior) |
| `commands.nativeSkills` | `"auto"` | Same |
| `env.BASH_ENV` | `/opt/safeskill/safeskill-trap.sh` or `~/.safeskill-trap.sh` | Trap script for bash |
| `env.SAFESKILL_SOCKET` | `/var/run/safeskill/safeskill.sock` | Daemon socket |
| `env.SHELL` | `~/.openclaw/skills/safeskill/safeskill-shell` | Wrapper shell |
| `env.SAFESKILL_REAL_SHELL` | `/bin/bash` | Real shell used by wrapper |

Gateway LaunchAgent plist (`~/Library/LaunchAgents/ai.openclaw.gateway.plist`) is patched with the same env vars so the gateway process and its children inherit them.

**OpenClaw skill install flow (`openclaw-skill/install.sh`):**

1. **Prerequisite:** SafeSkill daemon must be installed first (`setup/install-macos.sh`)
2. **Layer 1 - Trap:** Copies `safeskill-trap.sh` to `/opt/safeskill/safeskill-trap.sh` (or `~/.safeskill-trap.sh` if no sudo)
3. **SOUL.md:** Injects immutable Security block into `~/.openclaw/workspace/SOUL.md` (advisory; LLM-level)
4. **Skill dir:** Creates `~/.openclaw/skills/safeskill/`, installs `safeskill-shell` wrapper
5. **OpenClaw config:** Merges into `~/.openclaw/openclaw.json` the keys above (host, security, ask, sandbox, env)
6. **Exec approvals:** Deploys `exec-approvals.json` with allowlist and non-interactive policy
7. **Gateway plist:** Patches `~/Library/LaunchAgents/ai.openclaw.gateway.plist` with BASH_ENV, SAFESKILL_SOCKET, SHELL, SAFESKILL_REAL_SHELL
8. **SIEM metadata:** Calls `update_siem_metadata()` to patch `/etc/safeskill/agent.yaml` from `.env`
9. **Restart:** Restarts the OpenClaw gateway so it picks up the new plist env vars

The user runs this script as their normal user (not root). It assumes OpenClaw is already installed.

---

## 6. What Works

1. **Daemon**: Evaluates commands, returns verdicts, writes audit logs. Verified via `safeskill check "command"` and direct socket calls.

2. **Trap (standalone)**: When `BASH_ENV` is set and `bash -c "command"` is run, the trap fires. Verified:
   ```bash
   BASH_ENV=/opt/safeskill/safeskill-trap.sh SAFESKILL_SOCKET=/var/run/safeskill/safeskill.sock bash -c 'python3 -c "print(\"safeskill-verify-XXX\")"'
   ```
   The audit log shows `event_action: "evaluate"`, `source: "bash-trap"`.

3. **Blocking**: `cat /etc/passwd` is correctly blocked when it reaches the daemon. Verdict and audit log reflect the block.

4. **Exec approvals**: With `host=gateway` and `security: full`, OpenClaw does not gate on allowlist; SafeSkill is the enforcement layer.

---

## 7. What Fails

### 7.1 TUI Commands Not Logged

**Symptom:** User asks the agent to run `whoami` or `ifconfig` in the TUI. The agent returns output (e.g. username, interface list), but no corresponding `event_action: "evaluate"` line appears in the SafeSkill audit log. In some runs, error output showed `zsh:1: command not found`, indicating zsh was used instead of bash; zsh does not honor BASH_ENV.

**Possible causes:**
- Commands never reach the shell path. OpenClaw may spawn the binary directly (e.g. `execve("/usr/bin/whoami", ...)`) instead of `$SHELL -c "whoami"`. In that case, BASH_ENV and the SHELL wrapper are never used.
- Shell mismatch: Observed `zsh:1: command not found` in agent output. If the gateway uses zsh for some invocations, BASH_ENV is ignored (it is bash-specific). Our SHELL and BASH_ENV configuration only affects bash.
- LLM fabrication: The model may produce plausible output without invoking the exec tool.
- Different execution host: If the session uses sandbox or node, commands run elsewhere and do not hit the gateway's environment.

### 7.2 Process Terminated Before Output

**Symptom:** When pathPrepend (binary shim) was enabled, `whoami` caused "the process was terminated before producing any output."

**Cause:** The shim script invoked `python3` and `curl`. With pathPrepend, those resolved to the shim directory (symlinks to the same shim). The shim recursively invoked itself, leading to hang or immediate failure.

### 7.3 Intermittent or Missing Interception

**Symptom:** Some commands are logged (e.g. verify script), others are not (e.g. TUI whoami/ifconfig).

**Cause:** Execution path differs. The verify script explicitly runs `bash -c "..."` with BASH_ENV. The TUI exec path may use a different spawn mechanism that bypasses the shell.

---

## 8. Root Cause Analysis

### 8.1 Execution Path Uncertainty

OpenClaw's exec implementation is external (npm package). Documentation states:
- "On non-Windows hosts, exec uses SHELL when set."
- "host=gateway: merges your login-shell PATH into the exec environment."

It does not guarantee that every command is run as `$SHELL -c "command"`. For simple commands like `whoami`, the implementation may:
- Spawn the binary directly via `execve` or `child_process.spawn` with the command as argv.
- Use a shell only for compound commands (pipes, redirects, etc.).

If that is the case, BASH_ENV and SHELL replacement do not apply. There is no shell to source the trap or run the wrapper.

### 8.2 Binary Shim Limitation

The binary shim (pathPrepend with symlinks) would intercept direct spawns. It failed because:
- The shim must invoke helper binaries (`python3`, `curl`) to evaluate and communicate with the daemon.
- With pathPrepend, those helpers resolved to the shim.
- Using a sanitized PATH (`/usr/bin:/bin:...`) for helpers should avoid recursion, but the shim still hung in testing. The cause was not fully isolated; the layer was removed to restore basic functionality.

### 8.3 Scope of Interception

Per ARCHITECTURE.md, SafeSkill intercepts only shell commands. It does not intercept:
- Python `import os` or `open()`.
- Node.js `fs.readFileSync()`.
- Direct syscalls.

The design is intentionally scoped to shell invocations. The gap is that we cannot guarantee all OpenClaw exec invocations go through a shell.

### 8.4 Concrete Failure Summary

| Component | Status | Notes |
|-----------|--------|-------|
| Daemon installation | Working | One-command install, launchd, socket, config |
| Daemon evaluation | Working | Policy, signatures, verdicts, audit log |
| SIEM forwarding | Working | For evaluations that reach the daemon |
| BASH_ENV trap | Working | When bash is invoked with BASH_ENV set |
| SHELL wrapper | Working | When gateway spawns `$SHELL -c "command"` |
| Gateway env injection | Working | Plist patched with BASH_ENV, SHELL, SAFESKILL_SOCKET |
| OpenClaw config | Working | host=gateway, sandbox=off, security=full |
| **TUI command interception** | **Failing** | `whoami`, `ifconfig` often not in audit log |
| **Binary shim** | **Reverted** | pathPrepend caused recursion; shim hung |
| **Execution path guarantee** | **Uncertain** | Cannot confirm all execs use `$SHELL -c` |

**Root cause in one sentence:** We cannot guarantee that OpenClaw's exec tool invokes a shell for every command; if it spawns binaries directly for simple commands, SafeSkill never sees them.

---

## 9. Recommendations

1. **Confirm OpenClaw exec behavior**: Inspect OpenClaw source or add logging to determine exactly how the exec tool spawns commands. If it uses `$SHELL -c` for all commands, the current setup should work; if it spawns binaries directly for simple commands, a working binary shim or upstream change is required.

2. **Binary shim (if needed)**: If direct spawn is confirmed, fix the shim by using absolute paths for helpers (e.g. `/usr/bin/python3`, `/usr/bin/curl`) instead of PATH lookup. Avoid pathPrepend for the shim's own helper invocations.

3. **Fallback: exec wrapper at OpenClaw layer**: If OpenClaw supports a custom exec wrapper or hook, use that to force all commands through a single script that calls SafeSkill before delegating to the real shell. This would not depend on BASH_ENV or PATH.

4. **Verification protocol**: Use a unique, non-guessable command (e.g. `python3 -c "print('safeskill-verify-'$(date +%s))"`) to confirm the execution path. If it appears in the audit log, the path is correct; if not, the command did not reach the daemon.

---

## 10. Appendix: File Locations

| Component | Path |
|-----------|------|
| Daemon plist | `/Library/LaunchDaemons/com.safeskill.agent.plist` |
| Daemon config | `/etc/safeskill/agent.yaml` |
| Trap script | `/opt/safeskill/safeskill-trap.sh` or `~/.safeskill-trap.sh` |
| Shell wrapper | `~/.openclaw/skills/safeskill/safeskill-shell` |
| Daemon socket | `/var/run/safeskill/safeskill.sock` |
| Client token | `/var/run/safeskill/client.token` |
| Audit log | `/var/log/safeskill/audit-YYYY-MM-DD.jsonl` |
| OpenClaw config | `~/.openclaw/openclaw.json` |
| Gateway plist | `~/Library/LaunchAgents/ai.openclaw.gateway.plist` |
| Exec approvals | `~/.openclaw/exec-approvals.json` |
| Policies | `/etc/safeskill/base-policy.yaml`, `runtime-policy.yaml`, `signatures.yaml` |

---

## 11. Appendix: Verification Commands

| Check | Command |
|-------|---------|
| Daemon running | `ps aux \| grep safeskill` |
| Socket exists | `ls -la /var/run/safeskill/safeskill.sock` |
| Gateway has BASH_ENV | `plutil -p ~/Library/LaunchAgents/ai.openclaw.gateway.plist` |
| Trap works (standalone) | `BASH_ENV=/opt/safeskill/safeskill-trap.sh SAFESKILL_SOCKET=/var/run/safeskill/safeskill.sock bash -c 'echo ok'` |
| Block test | In TUI: "run cat /etc/passwd" — should see [SafeSkill] BLOCKED |
| Audit log tail | `sudo tail -f /var/log/safeskill/audit-$(date +%Y-%m-%d).jsonl` |
| Interception verify | Run `BASH_ENV=/opt/safeskill/safeskill-trap.sh SAFESKILL_SOCKET=/var/run/safeskill/safeskill.sock bash -c 'python3 -c "print(\"safeskill-verify-XXX\")"'` then grep the audit log for `safeskill-verify-XXX` |

---

## 12. Appendix: Commit History (Relevant)

```
c070ed7 openclaw-skill: safeskill integration updates
3f69a1e Production-ready SafeSkill OpenClaw integration
b2d8611 fix: use BASH_ENV trap injection instead of SHELL replacement
cd4c31e fix: SHELL env has 'never override' semantics — must be set at process level
925abe6 fix: SHELL replacement — real enforcement that LLM cannot bypass
19e81c4 fix: set host=gateway in OpenClaw config to enforce exec-approvals
a34771f SafeSkillAgent v1.0.0 — runtime command security enforcement for OpenClaw
```
