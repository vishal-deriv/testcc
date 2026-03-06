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
- **Cross-platform**: macOS (launchd) and Linux (systemd)
- **Health-check optimized**: OpenClaw's internal monitoring commands bypass daemon entirely (zero latency)
- **SIEM-ready**: All evaluations forwarded to security endpoint in real-time
- **No OpenClaw modification**: Pure runtime monkey-patching via child_process interception

## End-to-End Setup

### Prerequisites
- Node.js 22+
- Python 3.10+
- macOS (launchd) or Linux (systemd)

### 1. Install OpenClaw
```bash
npm install -g openclaw@latest
openclaw onboard --install-daemon
```

### 2. Install SafeSkill

#### macOS
```bash
sudo bash setup/install.sh
bash setup/start.sh
```

- **install.sh**: Creates venv, installs daemon, config, launchd. Requires sudo.
- **start.sh**: Copies hook to `~/.openclaw/`, injects NODE_OPTIONS into the gateway plist, restarts OpenClaw.

#### Linux
```bash
sudo bash setup/linux/install.sh
bash setup/linux/start.sh
```

- **setup/linux/install.sh**: Creates venv, installs daemon, config, systemd service. Auto-installs python3/curl if missing (apt/dnf/yum). Requires sudo.
- **setup/linux/start.sh**: Copies hook to `~/.openclaw/`, injects NODE_OPTIONS via systemd override or openclaw.json, restarts OpenClaw. Set `OPENCLAW_PROFILE=<name>` when not using `main`.

#### Jamf MDM (fleet deployment)

Upload `setup/jamf-install.sh` to Jamf Pro as a script. It handles everything in one pass — installs Xcode CLT, Python, daemon, config, hook, and smoke tests. See [Jamf MDM Deployment](#jamf-mdm-deployment) below.

### 3. Run OpenClaw TUI
```bash
openclaw tui
```

### 4. Monitor audit log (optional)
```bash
sudo bash setup/monitor-audit.sh
```

### 5. Configure SIEM (optional)
```bash
# Fix auth header from old ?key= query param to x-api-key header
sudo bash setup/linux/fix-siem-config.sh

# Verify
sudo cat /etc/safeskill/agent.yaml | grep siem
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

### macOS

**Gateway not starting?**
```bash
ps aux | grep openclaw
killall -9 openclaw-gateway
openclaw gateway start
```

**Hook not intercepting?**
```bash
ls -la ~/.openclaw/safeskill-hook.js

/usr/libexec/PlistBuddy -c "Print :EnvironmentVariables:NODE_OPTIONS" \
  ~/Library/LaunchAgents/ai.openclaw.gateway.plist

launchctl list | grep safeskill
```

**Commands all blocked?**
```bash
sudo launchctl kickstart -k system/com.safeskill.agent
safeskill check whoami
```

### Linux

**Daemon not running?**
```bash
sudo systemctl status safeskill
sudo journalctl -u safeskill -n 30
sudo systemctl restart safeskill
```

**Socket not available?**
```bash
ls -la /var/run/safeskill/safeskill.sock
# If missing, restart daemon:
sudo systemctl restart safeskill
```

**Hook not intercepting?**
```bash
ls -la ~/.openclaw/safeskill-hook.js

# Check service/drop-in or gateway launch command includes NODE_OPTIONS:
systemctl --user cat openclaw-gateway 2>/dev/null || true
systemctl --user cat openclaw-gateway-main 2>/dev/null || true

safeskill check whoami
```

**Commands all blocked?**
```bash
# Daemon needs to be running
sudo systemctl restart safeskill

# Verify daemon responding
safeskill check whoami
```

## Jamf MDM Deployment

For fleet deployment via Jamf Pro, use `setup/jamf-install.sh`. It's a single self-contained script that:

1. Installs Xcode Command Line Tools (silent, no GUI)
2. Installs Python 3.12 from python.org (if system Python < 3.10)
3. Clones repo, creates venv, installs package
4. Sets up config, policies, signatures, admin token
5. Installs and starts LaunchDaemon
6. Deploys hook into OpenClaw
7. Runs 8 smoke tests
8. Writes receipt for Jamf Extension Attributes

**Jamf script parameters:**

| Parameter | Label | Default |
|-----------|-------|---------|
| `$4` | SIEM Endpoint URL | *(blank — skip)* |
| `$5` | SIEM API Key | *(blank — skip)* |
| `$6` | Trust Mode | `normal` |
| `$7` | Environment | `production` |
| `$8` | Git Branch/Tag | `main` |

**Extension Attribute** (to verify deployment across fleet):
```bash
#!/bin/bash
if [[ -f /opt/safeskill/.installed ]]; then
    status=$(grep '^status=' /opt/safeskill/.installed | cut -d= -f2)
    version=$(grep '^version=' /opt/safeskill/.installed | cut -d= -f2)
    echo "<result>${status} (v${version})</result>"
else
    echo "<result>not installed</result>"
fi
```

## Uninstall

**Remove SafeSkill only:**
```bash
sudo bash setup/uninstall-safeskill.sh
```

**Remove OpenClaw only:**
```bash
bash setup/uninstall-openclaw.sh
```

**Remove both:**
```bash
bash setup/uninstall-all.sh
```

| Script | What it removes |
|--------|-----------------|
| `uninstall-safeskill.sh` | Daemon, plists/service, binaries, /opt/safeskill, /etc/safeskill, /var/log/safeskill, /var/run/safeskill |
| `uninstall-openclaw.sh` | Gateway process, ~/.openclaw, LaunchAgent plist, `npm uninstall -g openclaw`, shell completions |
| `uninstall-all.sh` | Runs both scripts |

## Files

```
openclaw-skill/
└── safeskill-hook.js              ← Core deliverable (deployed to ~/.openclaw/)

setup/
├── install.sh                     ← macOS: Step 1 — Install daemon (launchd)
├── start.sh                       ← macOS: Step 2 — Wire hook into OpenClaw
├── linux/
│   ├── install.sh                 ← Linux: Step 1 — Install daemon (systemd)
│   ├── start.sh                   ← Linux: Step 2 — Wire hook into OpenClaw
│   ├── safeskill.service          ← Linux: systemd unit file
│   ├── fix-siem-config.sh         ← Linux: SIEM auth/endpoint fixer
│   └── monitor-audit.sh           ← Linux: monitor audit log
├── jamf-install.sh                ← Jamf MDM: All-in-one fleet deployment
├── com.safeskill.agent.plist      ← macOS: launchd daemon config
├── com.safeskill.updater.plist    ← macOS: launchd updater config
├── monitor-audit.sh               ← Monitor audit log (both platforms)
├── uninstall-safeskill.sh         ← Remove SafeSkill (sudo)
├── uninstall-openclaw.sh          ← Remove OpenClaw
└── uninstall-all.sh               ← Remove both
```

## Version History

- **v2 (Current)**: NODE_OPTIONS preload hook, single-layer, ~25ms
- **v1 (Deprecated)**: 3-layer bash (wrapper/trap/shim), ~600ms, removed
