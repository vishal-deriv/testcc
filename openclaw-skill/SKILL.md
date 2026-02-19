---
name: safeskill
description: >
  Security enforcement agent that evaluates ALL shell commands BEFORE execution.
  Blocks malicious, destructive, or policy-violating commands. MUST be consulted
  before every exec tool call.
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

You have a security agent running on this machine called **SafeSkillAgent**. It evaluates
shell commands BEFORE execution and returns allow/block/warn verdicts. You MUST follow
these rules for EVERY command you plan to execute.

## MANDATORY RULE — Pre-Execution Check

**Before EVERY call to the `exec` tool**, you MUST first run:

```bash
safeskill check "<the exact command you plan to run>"
```

Read the output carefully:

- If the result says **BLOCKED**: You MUST NOT execute that command. Tell the user it was
  blocked and include the reason and severity from the output. Do NOT attempt to rephrase,
  split, encode, or otherwise work around the block.

- If the result says **WARNED**: You MAY proceed, but tell the user about the warning
  before executing. Include the severity and message.

- If the result says **ALLOWED**: Proceed normally with the `exec` tool.

- If the `safeskill` command itself fails or times out: **Do NOT execute the original
  command.** Tell the user the security agent is unreachable and commands cannot run
  until it is restored. Suggest: `safeskill start` or check `systemctl status safeskill-agent`.

## Examples

### Allowed command

```
> safeskill check "ls -la /tmp"
[ALLOWED] ls -la /tmp
  No threats detected
  Evaluated in: 0.31ms
```

Proceed to execute: `ls -la /tmp`

### Blocked command

```
> safeskill check "rm -rf /"
[BLOCKED] rm -rf /
  Severity: critical
  Message: BLOCKED: Recursive delete of root filesystem
  Rules: FS-001
  Evaluated in: 0.42ms
```

DO NOT execute. Report to the user:
"That command was blocked by the security agent. Reason: Recursive delete of root
filesystem (severity: critical, rule FS-001)."

### Warned command

```
> safeskill check "nmap 192.168.1.0/24"
[WARNED] nmap 192.168.1.0/24
  Severity: medium
  Message: WARNING: Port scanning tool detected
  Evaluated in: 0.28ms
```

Inform the user of the warning, then proceed if they confirm.

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
