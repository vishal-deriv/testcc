# SafeSkill + OpenClaw Integration — Learnings & Debug Log

**Date:** 2026-02-25
**Issue:** Commands executed by the OpenClaw AI agent were NOT being intercepted or logged by SafeSkill. Simple commands like `whoami` and `ifconfig` were running without audit entries.

---

## 1. What the System Does

SafeSkill is a **command security daemon** (Python/aiohttp) that:
- Listens on a Unix socket `/var/run/safeskill/safeskill.sock`
- Evaluates every shell command against 24 rules + 18 signatures
- Blocks dangerous commands (reverse shells, data exfil, crypto miners, privilege escalation)
- Writes tamper-evident JSONL audit logs at `/var/log/safeskill/`
- Is fail-closed: if unreachable, ALL commands are blocked

OpenClaw is an AI agent platform that executes shell commands via its gateway process. The integration hooks SafeSkill into every command OpenClaw tries to run.

**Three interception layers (defense in depth):**

| Layer | Mechanism | How it works |
|---|---|---|
| 1 — Shell wrapper | `safeskill-shell` set as `$SHELL` | OpenClaw runs `$SHELL -c "cmd"` → our wrapper evaluates first |
| 2 — BASH_ENV trap | `safeskill-trap.sh` set in `$BASH_ENV` | bash sources this before every non-interactive script → DEBUG trap |
| 3 — Binary shim | `~/.openclaw/safeskill-shims/bin/` in PATH | Symlinks to shim script intercept direct binary spawns |

---

## 2. Bugs Found and Fixed

### Bug #1 — Binary shim `python3 -` pipe + heredoc conflict (ROOT CAUSE of shim failure)

**File:** `openclaw-skill/safeskill-bin-shim.sh`

**What happened:** The shim used this pattern to parse the JSON response from the daemon:
```bash
blocked="$(
  printf '%s' "$res" | python3 - <<'PY'
import json,sys
d=json.load(sys.stdin)
print("1" if d.get("blocked", True) else "0")
PY
)"
```

In bash/zsh, when you pipe (`|`) to a command AND provide a heredoc (`<<'PY'`), **the pipe wins** — the heredoc loses. Python3 received the JSON response string as the **script to execute** (not as data to read from stdin). This caused `SyntaxError` → `JSONDecodeError` → `_fail_closed()` → every command blocked with exit 126.

**Fix:** Change `python3 -` to `python3 -c '...'`:
```bash
blocked="$(
  printf '%s' "$res" | python3 -c '
import json,sys
d=json.load(sys.stdin)
print("1" if d.get("blocked", True) else "0")
')"
```
With `-c`, the code is the argument and stdin is pure data from the pipe. This is correct.

**Lesson:** Never use `cmd | python3 - <<'HEREDOC'...HEREDOC` together. The pipe and heredoc both try to own stdin; the pipe wins in most shells, discarding the heredoc code entirely.

---

### Bug #2 — BASH_ENV trap intercepting `safeskill-shell`'s own internals (ROOT CAUSE of shell wrapper failure)

**File:** `openclaw-skill/safeskill-shell` (and `safeskill-exec.sh`)

**What happened:** When `BASH_ENV` is set in the gateway's environment, bash sources the trap file **before executing ANY script** — including `safeskill-shell` itself (which is a bash script via `#!/usr/bin/env bash` shebang). This installed the DEBUG trap inside `safeskill-shell`'s own process.

The DEBUG trap then fired for `safeskill-shell`'s first line:
```bash
SOCKET_PATH="${SAFESKILL_SOCKET:-/var/run/safeskill/safeskill.sock}"
```

The daemon's **self-protection rule** matched this variable assignment because it contains the string `/var/run/safeskill/safeskill.sock` — the SafeSkill socket path. Result: the daemon blocked `safeskill-shell`'s own initialization. Every command then saw `[SafeSkill] BLOCKED — Self-protection: Attempt to tamper with SafeSkillAgent detected`.

**Error output:**
```
[SafeSkill] BLOCKED
[SafeSkill] Self-protection: Attempt to tamper with SafeSkillAgent detected
[SafeSkill] BLOCKED — Security agent not running (socket: )
```

**Attempted fix that didn't work:** Adding `case "${0##*/}" in safeskill-shell) return 0 ;; esac` to the BASH_ENV trap file. This fails because in BASH_ENV context `$0` is `/bin/bash` (the shell binary), NOT the script name. The script name is not available in the BASH_ENV environment.

**What DOES work:** Add `trap - DEBUG 2>/dev/null || true` as the **absolute first executable line** in `safeskill-shell`, before any variable assignments. The trap handler whitelists the `trap` command itself, so `trap - DEBUG` is allowed to run, clearing the DEBUG trap from `safeskill-shell`'s own process. `BASH_ENV` stays in the environment, so the child bash process (exec'd at the end of safeskill-shell) still gets the trap.

```bash
#!/usr/bin/env bash
# SafeSkill Shell — Drop-in bash replacement for OpenClaw
...

# THIS MUST BE FIRST — before any variable assignments
trap - DEBUG 2>/dev/null || true   # ← remove any DEBUG trap sourced from BASH_ENV

SOCKET_PATH="${SAFESKILL_SOCKET:-/var/run/safeskill/safeskill.sock}"
REAL_SHELL="${SAFESKILL_REAL_SHELL:-/bin/bash}"
...
```

**Why it must be first:** The BASH_ENV trap fires for the VERY FIRST command in the script. Any variable assignment containing the SafeSkill socket path triggers self-protection before `trap - DEBUG` can run.

**Lesson:** `BASH_ENV` is sourced for ALL non-interactive bash processes, including your own enforcement scripts. Every bash script that the gateway might spawn with BASH_ENV set needs `trap - DEBUG` as its very first command.

---

### Bug #3 — Binary shim not in PATH

**What happened:** The shim directory `~/.openclaw/safeskill-shims/bin/` existed and contained 1993 binary symlinks, but `tools.exec.pathPrepend` in `openclaw.json` was `[]` (empty array). The shim was never in PATH.

**Fix:** Added to `~/.openclaw/openclaw.json`:
```json
"tools": {
  "exec": {
    "pathPrepend": ["/Users/test3/.openclaw/safeskill-shims/bin"]
  }
}
```
OpenClaw detected this change and applied it dynamically (no gateway restart needed).

---

### Bug #4 — Audit logs unreadable (permissions)

**What happened:** `/var/log/safeskill/` was created by the daemon (running as root) with mode `drwx------` (700, root:staff). The current user couldn't list or read the directory. This made verification difficult.

**Fix:** Run `sudo chmod 750 /var/log/safeskill` and `sudo chmod 640 /var/log/safeskill/audit-*.jsonl`.

**Why finalize-install.sh had the same bug:** On macOS, `chmod 750` after `chown root:staff` sometimes doesn't stick if there are extended attributes (the `@` flag in `ls -la`). Added `chmod -N` before `chmod 750` to strip ACLs first.

---

### Non-Bug Discovery #1 — OpenClaw DOES use `$SHELL -c "command"`

The INTEGRATION-RESEARCH.md expressed concern that "OpenClaw might spawn binaries directly, bypassing the shell." By reading OpenClaw's source at `~/.nvm/versions/node/v24.13.0/lib/node_modules/openclaw/dist/subagent-registry-DN6TUJw4.js`:

```javascript
function getShellConfig() {
  const envShell = process.env.SHELL?.trim();
  return { shell: envShell ?? "sh", args: ["-c"] };
}
const childArgv = [shell, ...shellArgs, execCommand];
// i.e. ["/path/to/safeskill-shell", "-c", "whoami"]
```

OpenClaw **always** uses `$SHELL -c "command"` for gateway exec calls. The concern in the research doc was unfounded for the current version. The binary shim is defense-in-depth for future versions.

---

### Non-Bug Discovery #2 — Gateway self-restart vs launchd restart

When `openclaw.json` is modified, the gateway detects the change and performs a "full process restart" via SIGUSR1 — spawning a new child process that inherits the parent's environment. This is different from launchd stopping and restarting the process. The self-restart correctly propagates env changes from `openclaw.json`, but does NOT re-read the LaunchAgent plist. So env changes must go into BOTH `openclaw.json` (for runtime) AND the plist (for fresh restarts).

---

### Non-Bug Discovery #3 — Daemon was running manually, not via launchd

The LaunchDaemon plist existed at `/Library/LaunchDaemons/com.safeskill.agent.plist` but was never loaded with `launchctl`. The daemon was running as PID 99065, started manually via `safeskill-agent start`. It would NOT survive a system reboot.

**Fix:** `finalize-install.sh` kills the manual process and loads it via `launchctl load -w`.

---

## 3. System State After All Fixes

```
Daemon:    PID 7060  (launchd-managed, auto-starts on reboot)
Socket:    /var/run/safeskill/safeskill.sock
Config:    /etc/safeskill/  (6 policy files installed)
Logs:      /var/log/safeskill/audit-YYYY-MM-DD.jsonl  (staff group readable)
Rules:     24 active rules
Sigs:      18 signatures
Chain:     116+ audit entries, cryptographic chain valid
```

**OpenClaw gateway config (`~/.openclaw/openclaw.json`):**
```json
"env": {
  "SHELL":              "~/.openclaw/skills/safeskill/safeskill-shell",
  "BASH_ENV":           "~/.safeskill-trap.sh",
  "SAFESKILL_SOCKET":   "/var/run/safeskill/safeskill.sock",
  "SAFESKILL_REAL_SHELL": "/bin/bash"
},
"tools": {
  "exec": {
    "pathPrepend": ["~/.openclaw/safeskill-shims/bin"]
  }
}
```

**Test results:**
```
whoami                    → allowed  (exit 0) ✅
ifconfig lo0              → allowed  (exit 0) ✅
cat /etc/passwd           → BLOCKED  (exit 126, data never read) ✅
bash -c 'cat /etc/passwd' → BLOCKED  (trap fires in child bash) ✅
binary shim whoami        → allowed  (exit 0) ✅
audit chain               → valid=True, 116+ entries ✅
```

---

## 4. Folder Structure (Minimal)

```
testcc/
├── safeskill/                  # Python daemon source
│   ├── config/                 # Bundled default policies + signatures
│   └── *.py                    # agent, cli, evaluator, logger, models, policy,
│                               #   server, setup, signatures, trust, updater, watcher
├── openclaw-skill/             # OpenClaw integration layer
│   ├── install.sh              # Wire up SHELL, BASH_ENV, shims, gateway env
│   ├── verify-interception.sh  # Post-install smoke test
│   ├── safeskill-shell         # Layer 1: $SHELL replacement
│   ├── safeskill-trap.sh       # Layer 2: BASH_ENV DEBUG trap
│   ├── safeskill-bin-shim.sh   # Layer 3: binary shim
│   ├── exec-approvals.json     # OpenClaw exec security config
│   ├── SKILL.md                # OpenClaw skill descriptor
│   ├── safeskill-inject.md     # LLM context injection (soul security)
│   └── safeskill-soul-security.md
├── setup/                      # System-level installation
│   ├── install-macos.sh        # Full install from scratch (needs sudo)
│   ├── finalize-install.sh     # Finish system setup on already-running system
│   ├── uninstall-macos.sh
│   ├── com.safeskill.agent.plist
│   ├── com.safeskill.updater.plist
│   └── update.sh
├── tests/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── INTEGRATION-RESEARCH.md
│   └── LEARNINGS.md            ← this file
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## 5. Quick Reference — Daily Commands

```bash
# Check daemon status
safeskill status

# Watch audit log live
tail -f /var/log/safeskill/audit-$(date +%Y-%m-%d).jsonl

# Test a command manually
safeskill check 'rm -rf /'

# Re-run verification
bash openclaw-skill/verify-interception.sh

# Daemon logs (stdout)
tail -f /var/log/safeskill/agent-stdout.log

# Reload policies after editing /etc/safeskill/
admin_token=$(sudo cat /etc/safeskill/admin.token)
safeskill reload --token "$admin_token"
```

---

## 6. Key Files and Their Roles

| Path | Role |
|---|---|
| `/var/run/safeskill/safeskill.sock` | Unix socket the daemon listens on |
| `/var/run/safeskill/client.token` | Token scripts use to authenticate with daemon |
| `/etc/safeskill/admin.token` | Admin token for policy reload / trust-mode changes |
| `/etc/safeskill/base-policy.yaml` | Core blocking rules (24 rules) |
| `/etc/safeskill/signatures.yaml` | Signature-based detection (18 sigs) |
| `/var/log/safeskill/audit-YYYY-MM-DD.jsonl` | Tamper-evident audit log |
| `~/.openclaw/openclaw.json` | OpenClaw config (SHELL, BASH_ENV, pathPrepend) |
| `~/.openclaw/skills/safeskill/safeskill-shell` | Deployed shell wrapper |
| `~/.safeskill-trap.sh` | Deployed BASH_ENV trap |
| `~/.openclaw/safeskill-shims/bin/` | Deployed binary shim dir (1993 binaries) |
| `/Library/LaunchDaemons/com.safeskill.agent.plist` | Daemon auto-start config |

---

## 7. The Second Chapter — Why the Bash Approach Failed and What Replaced It

*(Appended 2026-02-26 — these are the events that happened after the initial fixes above)*

### The Illusion of Working

After fixing bugs #1–#4, the system appeared complete on paper. Three interception layers, all bugs patched, audit chain valid, test entries in the log. But when we opened the OpenClaw TUI and tried actual commands — `uname -a`, `whoami`, `ls /tmp`, `file /bin/bash` — every single one came back with `SIGTERM` before producing any output. The audit log showed nothing for these commands.

The initial diagnosis was wrong. We assumed the SIGTERM was coming from OpenClaw's sandbox. We checked `openclaw.json` and saw `"sandbox": {"mode": "off"}`. The sandbox was disabled. Something else was killing the commands.

### The Real Culprit: Config Directory Gone

Investigation revealed the first part of the problem: `/etc/safeskill/` had been silently deleted at some point during earlier cleanup. The daemon was running (PID still alive, socket still present) but had **no config directory** — no rules, no policy files, no nothing. Every command evaluation was failing internally, and the fail-closed logic was sending SIGTERM.

Running `finalize-install.sh` again restored `/etc/safeskill/`, reloaded the daemon, and `whoami` appeared in the audit log. But the SIGTERM was still happening for many commands in the TUI.

### The Timing Problem — 600ms Is Too Slow

Even with the config fixed, the three bash layers added compounding overhead per command:

- **Layer 1** (safeskill-shell): 2× python3 startups + 1× curl = ~150ms
- **Layer 2** (BASH_ENV trap): 3× python3 startups + 1× curl = ~200ms
- **Layer 3** (binary shim): 3× python3 startups + 1× curl = ~200ms
- **Total: ~550–700ms before the actual command even starts**

OpenClaw's gateway exec runtime has its own internal timeout. Commands that took >500ms to start were being SIGTERM'd by the gateway before producing output. The audit log showed the evaluation completing — the command was `ALLOWED` — but the process was killed before `exec` could hand control to the real binary.

This was the fundamental flaw: the bash layers evaluated the command **after** Node.js had already spawned a shell process, and the total chain was too slow.

### The Architecture Insight

The bash layers were intercepting at the wrong level. The flow was:

```
OpenClaw Node.js
  → child_process.spawn('/safeskill-shell', ['-c', 'whoami'])   ← process spawned here
    → safeskill-shell starts (~150ms evaluation)
      → /bin/bash -c 'whoami' starts
        → BASH_ENV trap fires (~200ms evaluation)
          → binary shim intercepts whoami (~200ms evaluation)
            → /usr/bin/whoami actually runs  ← too late, gateway already gave up
```

The right answer, which any enterprise security tool (Datadog, New Relic, Snyk) uses for Node.js applications, is to intercept **before** Node.js calls the OS at all — inside the runtime itself.

### NODE_OPTIONS: The Correct Solution

Node.js has a built-in mechanism: `NODE_OPTIONS=--require /path/to/hook.js`. When set in the process environment before the Node.js process starts, it loads the specified file **before any application code runs**. The hook can then patch `require('child_process')` — the module every Node.js process uses to spawn external commands — in memory.

This changes the flow entirely:

```
OpenClaw Node.js (starts with NODE_OPTIONS=--require safeskill-hook.js)
  → safeskill-hook.js patches child_process.spawn (and all 6 variants)
  → OpenClaw code runs normally
  → OpenClaw calls child_process.spawn('whoami')
    → Our patched spawn intercepts (~25ms curl to daemon)
    → ALLOWED → original spawn called → whoami runs instantly
    → BLOCKED → throw EPERM → OpenClaw sees error, no exec at all
```

No shell scripts. No bash traps. No 1993 binary symlinks. One 138-line JavaScript file.

### What Was Built

**`openclaw-skill/safeskill-hook.js`** — patches all 7 `child_process` methods (`spawn`, `spawnSync`, `exec`, `execSync`, `execFile`, `execFileSync`, `fork`). Uses `curl` directly against the daemon socket for evaluation (~25ms, vs ~475ms for the Python CLI). Recursion-guarded with a boolean flag so internal curl calls are not re-intercepted.

**`setup/start.sh`** — drops the hook into `~/.openclaw/`, injects `NODE_OPTIONS=--require` into the OpenClaw launchd plist via `PlistBuddy`, removes the old SHELL/BASH_ENV/SAFESKILL_REAL_SHELL env vars, and restarts the gateway via `openclaw gateway stop` + `launchctl load`.

**All bash-layer files deleted:**
- `~/.openclaw/skills/safeskill/` (safeskill-shell, safeskill-wrapper, safeskill-exec)
- `~/.safeskill-trap.sh` (BASH_ENV trap)
- `~/.openclaw/safeskill-shims/bin/` (1990 binary symlinks)
- Project source: `openclaw-skill/safeskill-shell`, `safeskill-trap.sh`, `safeskill-bin-shim.sh`

**`~/.openclaw/openclaw.json` simplified:**
```json
"env": {
  "SAFESKILL_SOCKET": "/var/run/safeskill/safeskill.sock"
},
"tools": {
  "exec": { "host": "gateway", "security": "full", "ask": "off" }
}
```

### Before vs After

| Metric | Bash layers | NODE_OPTIONS hook |
|---|---|---|
| Interception point | After Node spawns shell | Before Node calls OS |
| Overhead per command | ~600ms | **~25ms** |
| SIGTERM from gateway | Constant | **Gone** |
| Total files | ~2000 (1990 shims + scripts) | **1 file** |
| Source: in audit log | `bash-trap`, `openclaw-bin-shim` | **`openclaw-hook`** |
| OpenClaw commands caught | Only shell-spawned | **All child_process calls** |

### Lesson

The bash approach was intercepting in the wrong runtime. OpenClaw is a Node.js application. Its security boundary is `child_process`. Hooking at the shell layer is fragile, slow, and incomplete — it only catches commands that go through `$SHELL -c`, missing direct `execFile` calls, piped commands, and anything OpenClaw's internal systems run outside the exec tool. The `NODE_OPTIONS` hook catches all of it, at the source.

**Do not reach for bash wrappers when the target application is a managed runtime.** Hook the runtime directly.

---

## 8. SIEM Forwarding

The daemon has built-in SIEM forwarding in `safeskill/logger.py`. Every audit entry is POSTed to an HTTP endpoint in a fire-and-forget background thread. No blocking, no impact on evaluation latency.

**Configuration** — add to `/etc/safeskill/agent.yaml`:
```yaml
siem_endpoint_url: https://your-siem-endpoint/ingestor/openclaw?key=YOUR_API_KEY
```

The daemon picks this up on startup. Requires a full restart (not hot-reload) since it is read at logger initialization time.

**Auth note:** The header name is configurable. Set `siem_auth_header_name` in `agent.yaml` to whatever the endpoint expects (`x-api-key`, `Authorization`, etc.). The value is set via `siem_auth_header`. This was a bug fix — the daemon previously hardcoded `Authorization` regardless of endpoint type, causing persistent 401s against the NGSOC gateway until the installed daemon package was updated.

**SIEM payload format** (every evaluation):
```json
{
  "event_timestamp": "2026-02-26T01:57:00.222956Z",
  "hostname": "test3s-MacBook-Pro.local",
  "event_action": "evaluate",
  "event_outcome": "blocked",
  "blocked": true,
  "risk_score": 100,
  "system_command": "cat /etc/passwd",
  "user_name": "test3",
  "source_ip": "10.17.0.120",
  "source": "openclaw-hook",
  "severity": "critical",
  "matched_rules": ["HEUR-DATAEXFIL"],
  "matched_signatures": [],
  "message": "Data exfiltration pattern detected"
}
```

---

## 9. Updated Quick Reference

```bash
# Wire SafeSkill into OpenClaw (run once after install)
bash setup/start.sh

# Watch live audit log (always uses most recent file)
sudo tail -f $(sudo ls -t /var/log/safeskill/audit-*.jsonl | head -1) | python3 -c "
import sys,json
for l in sys.stdin:
    try:
        d=json.loads(l)
        if d.get('event_action')=='evaluate':
            print(d['event_timestamp'][:19], f\"[{d['event_outcome'].upper():7}]\", d.get('system_command',''))
    except: pass
"

# Test a command manually (exits 0=allowed, 1=blocked)
safeskill check 'cat /etc/passwd'

# Daemon status
safeskill status

# Verify hook is active in OpenClaw plist
/usr/libexec/PlistBuddy -c "Print :EnvironmentVariables:NODE_OPTIONS" \
  ~/Library/LaunchAgents/ai.openclaw.gateway.plist
```
