# SafeSkillAgent

**Runtime-configurable command security enforcement agent for macOS and Linux.**

SafeSkillAgent evaluates shell commands **before execution** and blocks malicious, destructive, or policy-violating commands. Designed to integrate with [OpenClaw](https://openclaw.ai/) as a security skill, it acts as a CrowdStrike-style endpoint agent that can be updated at any time without restarts.

## Architecture

```
┌─────────────┐     ┌──────────────────────────────────────┐
│   OpenClaw   │────▶│          SafeSkillAgent               │
│  (or CLI)    │◀────│                                       │
└─────────────┘     │  ┌─────────┐  ┌───────────┐          │
   JSON over        │  │ Policy  │  │ Signature │          │
   Unix Socket      │  │ Engine  │  │  Matcher  │          │
                    │  └────┬────┘  └─────┬─────┘          │
                    │       │             │                 │
                    │  ┌────▼─────────────▼────┐           │
                    │  │   Command Evaluator    │           │
                    │  │  (Heuristics + Rules)  │           │
                    │  └────────────┬───────────┘           │
                    │              │                        │
                    │  ┌───────────▼──────────┐            │
                    │  │   Trust Enforcer      │            │
                    │  │ (normal/strict/zero)  │            │
                    │  └───────────┬──────────┘            │
                    │              │                        │
                    │  ┌───────────▼──────────┐            │
                    │  │   Audit Logger        │            │
                    │  │ (hash-chained JSONL)  │            │
                    │  └──────────────────────┘            │
                    └──────────────────────────────────────┘
```

## Features

- **Pre-execution evaluation** -- Commands are checked BEFORE execution; nothing runs without a verdict
- **Three trust modes** -- `normal`, `strict`, `zero-trust` with increasing security levels
- **Three environments** -- `dev`, `staging`, `production` with per-environment policy overrides
- **Hot-reload** -- Edit YAML policy files on disk and changes take effect immediately
- **Runtime API** -- Change trust mode, environment, or inject rules via Unix socket API
- **Signature database** -- MITRE ATT&CK-aligned threat signatures (reverse shells, miners, exfil, etc.)
- **Hardcoded heuristics** -- Fork bombs, reverse shells, crypto miners, and curl-pipe-shell patterns are **always blocked** regardless of policy
- **Self-protection** -- Blocks attempts to kill, remove, or tamper with the agent
- **Tamper-evident audit** -- SHA-256 hash-chained append-only audit logs
- **Auto-update** -- Pull signed signature/policy updates from a remote server (CrowdStrike-style)
- **Separate OS setups** -- macOS (launchd) and Linux (systemd with full hardening)

## Quick Start

### Install (macOS)

```bash
sudo ./setup/install-macos.sh
```

### Install (Linux)

```bash
sudo ./setup/install-linux.sh
```

### Manual / Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Initialize config
safeskill init --config-dir ./config

# Start the agent
safeskill start --config-dir ./config --log-dir ./logs --socket /tmp/safeskill.sock
```

## Usage

### Check a command

```bash
safeskill check "rm -rf /"
# [BLOCKED] rm -rf /
#   Severity: critical
#   Message: BLOCKED: Recursive delete of root filesystem

safeskill check "ls -la /tmp"
# [ALLOWED] ls -la /tmp
#   No threats detected
```

### Agent status

```bash
safeskill status
```

### Change trust mode at runtime

```bash
safeskill set-trust strict
safeskill set-trust zero-trust
safeskill set-trust normal
```

### Change environment at runtime

```bash
safeskill set-env production
safeskill set-env staging
safeskill set-env dev
```

### Reload policies from disk

```bash
safeskill reload
```

### Verify audit chain integrity

```bash
safeskill verify-audit
```

## Trust Modes

| Mode | Behavior |
|------|----------|
| `normal` | Blocks critical/high severity, warns on medium, allows low |
| `strict` | Blocks critical/high/medium, warns on low. Blocklist of dangerous commands (rm, chmod, kill, etc.) |
| `zero-trust` | Blocks everything not explicitly allowlisted (only basic read-only commands allowed) |

## Environments

| Environment | Behavior |
|-------------|----------|
| `dev` | Most permissive -- disables some rules, downgrades severities |
| `staging` | Balanced -- all rules active, standard severities |
| `production` | Maximum security -- upgrades severities, blocks what other envs only warn about |

## Configuration

All configuration is in `/etc/safeskill/` (or your custom config dir):

```
/etc/safeskill/
├── base-policy.yaml        # Core security rules
├── runtime-policy.yaml     # Dynamic rules (editable at runtime)
├── signatures.yaml         # Threat signature database
├── agent.yaml              # Agent configuration (optional)
└── environments/
    ├── dev.yaml            # Dev overrides
    ├── staging.yaml        # Staging overrides
    └── production.yaml     # Production overrides
```

### Policy Rule Format

```yaml
rules:
  - id: "CUSTOM-001"
    name: "Block suspicious IP"
    description: "Block connections to known bad IP"
    severity: high          # low, medium, high, critical
    pattern: "10\\.0\\.0\\.99"
    pattern_type: regex     # regex (default), exact, contains, startswith
    action: block           # block, warn, allow, audit
    message: "Connection to suspicious IP blocked"
    environments:           # Optional: limit to specific environments
      - production
      - staging
    trust_modes:            # Optional: limit to specific trust modes
      - normal
      - strict
    tags:
      - network
      - custom
```

## API Reference

The agent listens on a Unix domain socket (default: `/tmp/safeskill.sock`).

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/evaluate` | POST | Evaluate a command `{"command": "...", "source": "openclaw"}` |
| `/health` | GET | Health check |
| `/status` | GET | Agent status and configuration |
| `/policy/reload` | POST | Reload all policies from disk |
| `/policy/inject` | POST | Inject runtime rules `{"rules": [...]}` |
| `/trust-mode` | POST | Change trust mode `{"trust_mode": "strict"}` |
| `/environment` | POST | Change environment `{"environment": "production"}` |
| `/audit/verify` | GET | Verify audit log chain integrity |

### Evaluate a command via curl

```bash
curl -s --unix-socket /tmp/safeskill.sock \
  http://localhost/evaluate \
  -H "Content-Type: application/json" \
  -d '{"command": "rm -rf /", "source": "openclaw"}'
```

Response:
```json
{
  "verdict": "blocked",
  "blocked": true,
  "severity": "critical",
  "message": "BLOCKED: Recursive delete of root filesystem",
  "matched_rules": ["FS-001"],
  "matched_signatures": [],
  "evaluation_time_ms": 0.42,
  "trust_mode": "normal",
  "environment": "dev"
}
```

## OpenClaw Integration (Defense in Depth)

SafeSkillAgent integrates with [OpenClaw](https://openclaw.ai/) through **four defense layers**.
Each layer catches what the others miss -- the LLM cannot bypass all of them.

```
User: "run rm -rf /abc"
         |
         v
  Layer 1: Exec Approvals ──> "rm" not in allowlist ──> BLOCKED
         |                     (OpenClaw's own enforcement, LLM cannot bypass)
         v (if misconfigured)
  Layer 2: Shell Wrapper ────> SafeSkillAgent evaluates ──> BLOCKED
         |                     (intercepts actual shell execution)
         v (if agent down)
  Layer 3: Skill Prompt ─────> LLM told to check first ──> BLOCKED
         |                     (soft enforcement via SKILL.md)
         v (if LLM ignores)
  Layer 4: Bootstrap Hook ───> Agent verified at startup
                                (fail-closed if unreachable)
```

### Install OpenClaw Integration

```bash
# After installing the SafeSkill daemon (setup/install-macos.sh or setup/install-linux.sh):
./openclaw-skill/install.sh
```

This deploys:

| Layer | File | Location | Enforcement |
|-------|------|----------|-------------|
| 1 | `exec-approvals.json` | `~/.openclaw/exec-approvals.json` | OS-level allowlist gate (cannot be bypassed by LLM) |
| 2 | `safeskill-exec.sh` | `~/.openclaw/skills/safeskill/` | Shell wrapper that consults SafeSkillAgent before every command |
| 3 | `SKILL.md` | `~/.openclaw/skills/safeskill/` | LLM prompt requiring pre-execution security checks |
| 4 | `safeskill-hook/` | `~/.openclaw/hooks/safeskill-hook/` | Bootstrap hook that verifies agent and sets exec policy |

### How Each Layer Works

**Layer 1 -- Exec Approvals** (hardest to bypass):
OpenClaw's own exec tool checks `~/.openclaw/exec-approvals.json` before running any command
on the gateway/node host. We set `security: "allowlist"` so only explicitly allowlisted binaries
can run. Dangerous binaries like `rm`, `dd`, `mkfs`, `chmod` are NOT in the allowlist.

**Layer 2 -- Shell Wrapper** (catches obfuscated commands):
Even when a binary is allowlisted, the shell wrapper `safeskill-exec.sh` intercepts the actual
execution and sends the full command string to SafeSkillAgent for evaluation. This catches piped
commands, encoded payloads, and argument-level threats that binary allowlists miss.

**Layer 3 -- Skill Prompt** (LLM-level enforcement):
The `SKILL.md` file instructs the LLM to run `safeskill check "command"` before every `exec`
tool call. If blocked, the LLM is told to refuse and explain why. Includes anti-evasion rules
against encoding, splitting, or obfuscating commands.

**Layer 4 -- Bootstrap Hook** (startup verification):
When OpenClaw boots, the hook verifies SafeSkillAgent is running and reachable. If not, it
blocks agent bootstrap entirely (fail-closed). It also injects security context into the
system prompt and sets exec defaults to `allowlist` mode.

### Shell wrapper for direct use

```bash
./openclaw-skill/safeskill-wrapper.sh "your command here"
```

### Python integration

```python
import aiohttp

async def check_command(command: str) -> dict:
    conn = aiohttp.UnixConnector(path="/tmp/safeskill.sock")
    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.post(
            "http://localhost/evaluate",
            json={"command": command, "source": "openclaw"}
        ) as resp:
            return await resp.json()
```

## Auto-Updates (CrowdStrike-style)

SafeSkillAgent supports pulling signed policy and signature updates from a remote server.

### Setup

1. Generate signing keys:
   ```bash
   safeskill generate-keys /path/to/keys/
   ```

2. Deploy the public key to agents:
   ```bash
   cp update-public-key.pem /etc/safeskill/
   ```

3. Configure the update URL in `agent.yaml`:
   ```yaml
   auto_update: true
   update_url: "https://updates.yourcompany.com/safeskill"
   update_interval_seconds: 3600
   signature_verify: true
   ```

4. Host a manifest on your update server:
   ```json
   {
     "version": "2024.02.19",
     "files": [
       {
         "name": "signatures.yaml",
         "sha256": "abc123...",
         "url": "https://updates.yourcompany.com/safeskill/signatures.yaml"
       }
     ]
   }
   ```

Updates are verified by:
- RSA-PSS signature on the manifest
- SHA-256 hash verification on each file
- Atomic swap with backup of existing files

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## Service Management

### macOS

```bash
sudo launchctl load -w /Library/LaunchDaemons/com.safeskill.agent.plist
sudo launchctl unload -w /Library/LaunchDaemons/com.safeskill.agent.plist
sudo launchctl list | grep safeskill
```

### Linux

```bash
sudo systemctl start safeskill-agent
sudo systemctl stop safeskill-agent
sudo systemctl status safeskill-agent
journalctl -u safeskill-agent -f
```

## Uninstall

```bash
# macOS
sudo ./setup/uninstall-macos.sh

# Linux
sudo ./setup/uninstall-linux.sh
```

## Security Design

- **Fail-closed** -- If the agent can't be reached, the wrapper refuses to execute
- **Self-protecting** -- Detects and blocks attempts to stop/remove/tamper with itself
- **Hardcoded heuristics** -- Critical threats (fork bombs, reverse shells, crypto miners) cannot be disabled by policy
- **Hash-chained audit** -- Each log entry references the previous entry's SHA-256 hash
- **Signed updates** -- RSA-4096-PSS verified update packages
- **Minimal privileges** -- Linux systemd unit runs with full hardening (NoNewPrivileges, ProtectSystem=strict, etc.)
- **Restrictive socket permissions** -- Unix socket is owner+group only (660)
