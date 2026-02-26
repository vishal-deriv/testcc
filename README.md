# SafeSkill + OpenClaw Integration

**Fast, minimal, zero-overhead AI command safety.**

SafeSkill intercepts ALL commands that OpenClaw's AI agent tries to execute, evaluates them against security rules in real-time, and logs everything to audit trail + SIEM.

## Architecture

```
OpenClaw (Node.js process)
  ↓
NODE_OPTIONS preload hook (safeskill-hook.js)
  ↓
child_process interception (spawn, spawnSync, exec, execSync, execFile, execFileSync, fork)
  ↓
SafeSkill daemon evaluation (~25ms via unix socket + curl)
  ↓
Allow/Block + Audit Log + SIEM Forward
```

## Key Features

- **Single-layer**: Node.js preload hook (no shell wrappers, no bash traps, no binary shims)
- **Fast**: ~25ms daemon round-trip via unix socket + curl (vs ~450ms Python CLI)
- **Fail-closed**: Any error blocks the command automatically
- **Health-check optimized**: OpenClaw's internal `sysctl`, `sw_vers`, `lsof`, `ps`, `launchctl` bypass daemon entirely (zero latency)
- **SIEM-ready**: All evaluations forwarded to security endpoint in real-time
- **No OpenClaw modification**: Pure runtime monkey-patching via child_process interception

## Quick Start

### 1. Install SafeSkill daemon
```bash
cd setup
sudo bash finalize-install.sh
```

Verify:
```bash
launchctl list | grep safeskill
ls -la /var/run/safeskill/
```

### 2. Wire hook into OpenClaw
```bash
bash start.sh
```

This:
- Copies `safeskill-hook.js` → `~/.openclaw/`
- Injects `NODE_OPTIONS=--require ~/.openclaw/safeskill-hook.js` into OpenClaw's launchd plist
- Removes old env vars (SHELL, BASH_ENV, SAFESKILL_REAL_SHELL)
- Restarts OpenClaw gateway

### 3. Configure SIEM (optional)
```bash
# Fix auth header from old ?key= query param to x-api-key header
sudo bash setup/fix-siem-config.sh

# Verify
sudo cat /etc/safeskill/agent.yaml | grep siem
```

### 4. Monitor audit log
```bash
sudo tail -f $(sudo ls -t /var/log/safeskill/audit-*.jsonl | head -1) | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        if d.get('event_action') == 'evaluate':
            print(d['event_timestamp'][:19], f\"[{d['event_outcome'].upper():7}]\", d.get('system_command', ''))
    except:
        pass
"
```

## How the Hook Works

**File:** `openclaw-skill/safeskill-hook.js` (deployed to `~/.openclaw/safeskill-hook.js`)

1. Loads before OpenClaw startup via `NODE_OPTIONS=--require`
2. Saves original child_process methods before patching
3. Replaces all 7 methods: spawn, spawnSync, exec, execSync, execFile, execFileSync, fork
4. For each command:
   - Check if it's a health-check (bypass daemon entirely for speed)
   - Otherwise, POST to SafeSkill daemon socket via curl
   - Daemon returns `{blocked: true/false}`
   - Allow/block the child process accordingly
5. Uses recursion guard to prevent curl itself from being intercepted

## Security Model

**Soft layer (OpenClaw agent reasoning):**
- Agent has soul-injection that refuses dangerous commands at reasoning time
- Never actually calls child_process for dangerous commands

**Hard layer (SafeSkill hook):**
- If agent tries anyway, hook blocks it
- Audit log captures the attempt
- SIEM endpoint notified in real-time

## Configuration

### `/etc/safeskill/agent.yaml`

```yaml
# Audit log settings
audit_log_enabled: true
hot_reload: true

# SIEM forwarding
siem_endpoint_url: https://ngsoc-gateway-auth-8mlnuyg1.uc.gateway.dev/ingestor/openclaw
siem_auth_header_name: x-api-key
siem_auth_header: <YOUR_API_KEY>
```

### `~/.openclaw/openclaw.json`

```json
{
  "env": {
    "SAFESKILL_SOCKET": "/var/run/safeskill/safeskill.sock"
  },
  "tools": {
    "exec": {
      "host": "gateway",
      "security": "full",
      "ask": "off"
    }
  }
}
```

## Troubleshooting

**Gateway not starting?**
```bash
# Check what's running
ps aux | grep openclaw

# Kill any stray processes
killall -9 openclaw-gateway

# Manually restart
openclaw gateway start
```

**Hook not intercepting?**
```bash
# Verify hook is deployed
ls -la ~/.openclaw/safeskill-hook.js

# Check NODE_OPTIONS in plist
/usr/libexec/PlistBuddy -c "Print :EnvironmentVariables:NODE_OPTIONS" \
  ~/Library/LaunchAgents/ai.openclaw.gateway.plist

# Verify daemon is running
launchctl list | grep safeskill
```

**Commands all blocked?**
```bash
# Daemon needs to be running
sudo launchctl kickstart -k system/com.safeskill.agent

# Verify daemon responding
safeskill check whoami
```

## Files

```
openclaw-skill/
└── safeskill-hook.js          ← Core deliverable (deployed to ~/.openclaw/)

setup/
├── finalize-install.sh        ← Install SafeSkill daemon
├── start.sh                   ← Deploy hook + restart OpenClaw
├── fix-siem-config.sh         ← Fix SIEM auth header
├── com.safeskill.agent.plist  ← Daemon launchd config
└── com.safeskill.updater.plist
```

## Version History

- **v2 (Current)**: NODE_OPTIONS preload hook, single-layer, ~25ms
- **v1 (Deprecated)**: 3-layer bash (wrapper/trap/shim), ~600ms, removed
