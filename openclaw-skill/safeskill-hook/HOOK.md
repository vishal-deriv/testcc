---
name: safeskill-guard
description: >
  Verifies SafeSkillAgent daemon is running on agent bootstrap and enforces
  exec security policy. Blocks agent startup if security enforcement is
  unavailable.
version: 1.0.0
events:
  - agent:bootstrap
tags:
  - security
  - enforcement
  - exec
---

# SafeSkill Guard Hook

This hook runs during agent bootstrap to:

1. Verify the SafeSkillAgent daemon is running and reachable
2. Set exec security to `allowlist` mode (preventing unrestricted command execution)
3. Inject a security context notice into the bootstrap so the agent knows it is being monitored
4. Abort bootstrap if the security agent is unreachable (fail-closed)
