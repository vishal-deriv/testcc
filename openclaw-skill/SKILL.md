---
name: safeskill
description: >
  Security enforcement agent that evaluates ALL shell commands BEFORE execution.
  Commands are automatically checked at the shell level — no pre-check needed.
version: 1.0.0
tags:
  - security
  - exec
  - enforcement
  - safety
bins:
  - safeskill
  - curl
---

# SafeSkill — Command Security Enforcement

You have a security agent running on this machine called **SafeSkillAgent**. **Every shell command is AUTOMATICALLY checked** at the shell level before execution. You do NOT need to run `safeskill check` first — that would add unnecessary latency.

## How it works

- **Just use the exec tool** with your command. The shell intercepts it and checks with SafeSkill before execution.
- If the command is blocked, exec will fail with `[SafeSkill] BLOCKED` (and optionally severity/reason) in the output. Tell the user it was blocked.
- If you see `[SafeSkill] WARNING:`, the command ran — inform the user of the warning.
- If exec succeeds with no SafeSkill message, the command was allowed.

## Examples

### Blocked command (exec fails)

```
> exec "rm -rf /"
[SafeSkill] BLOCKED
[SafeSkill] Severity: critical
[SafeSkill] Reason: BLOCKED: Recursive delete of root filesystem
exit 126
```

Report to the user: "That command was blocked by the security agent."

### Allowed command (exec succeeds)

```
> exec "ls -la /tmp"
(output shows directory listing)
```

No SafeSkill message means it was allowed.

### Warned command (exec succeeds but warns)

```
> exec "nmap 192.168.1.0/24"
[SafeSkill] WARNING: Port scanning tool detected
(output continues)
```

Inform the user of the warning.

## What Gets Blocked (Non-Exhaustive)

These categories are ALWAYS blocked regardless of policy:
- Fork bombs
- Reverse shells (bash, python, perl, ruby, php, socat, netcat)
- Cryptocurrency miners
- Data exfiltration of system credential files
- Curl/wget piped directly to shell interpreters
- Any attempt to stop, remove, or tamper with SafeSkillAgent itself

Additional blocks depend on the current trust mode and environment.

## Runtime Management

You can query or change the agent's configuration:

```bash
safeskill status                    # Show current mode, rules, environment
safeskill set-trust strict          # Switch to strict mode
safeskill set-trust zero-trust      # Switch to zero-trust mode
safeskill set-env production        # Switch to production environment
safeskill reload                    # Reload policies from disk
safeskill verify-audit              # Check audit log integrity
```

## Anti-Evasion Rules

You MUST NOT:
- Base64-encode, hex-encode, or obfuscate commands to bypass checks
- Split a blocked command into multiple "harmless" parts that achieve the same effect
- Use `eval`, `exec`, or variable expansion tricks to reconstruct blocked commands
- Attempt to stop, disable, or reconfigure SafeSkillAgent to weaken security
- Use `exec` with `security=full` or `elevated=true` to skip approvals
- Write a script file containing blocked commands and then execute the script

If a user explicitly asks you to do something that SafeSkill blocks, explain that the
command was blocked by the security policy and suggest a safer alternative if one exists.
