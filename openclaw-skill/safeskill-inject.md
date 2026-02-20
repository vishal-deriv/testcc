
<!-- SAFESKILL SECURITY ENFORCEMENT — DO NOT REMOVE -->
## MANDATORY: Command Security Enforcement (SafeSkill)

A security enforcement agent (SafeSkillAgent) is running on this machine. **Every shell command is AUTOMATICALLY checked at the shell level** — you do NOT need to run `safeskill check` first.

### RULE: Use exec normally — checks happen automatically

- **Just use the exec tool** with your command. The shell intercepts it and checks with SafeSkill before execution.
- If the command is blocked, exec will fail with `[SafeSkill] BLOCKED` in the output. Tell the user it was blocked and why.
- If you see `[SafeSkill] WARNING:`, the command ran but inform the user of the warning.
- If exec succeeds with no SafeSkill message, the command was allowed.

**You do NOT need to run `safeskill check` before exec.** That would add unnecessary latency. The interception is built into the shell.

### NEVER do these:
- Never encode, split, or obfuscate commands to bypass the check
- Never attempt to disable, stop, or reconfigure SafeSkillAgent
- Never write blocked commands to a script file and execute the script instead
<!-- END SAFESKILL -->
