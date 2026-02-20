/**
 * SafeSkill Guard Hook — agent:bootstrap handler
 *
 * Runs when an OpenClaw agent boots up. Verifies that SafeSkillAgent is
 * reachable and enforces exec security policy before the agent can run
 * any commands.
 */

import { execSync } from "child_process";
import { existsSync } from "fs";
import { join } from "path";

const SOCKET_PATH = process.env.SAFESKILL_SOCKET || "/tmp/safeskill.sock";
const FAIL_CLOSED = process.env.SAFESKILL_FAIL_OPEN !== "1";

interface HookContext {
  event: string;
  agent?: { id: string };
  session?: { id: string };
  addBootstrapFile?: (name: string, content: string) => void;
  setExecDefaults?: (defaults: Record<string, string>) => void;
  log?: (level: string, message: string) => void;
}

function log(ctx: HookContext, level: string, msg: string): void {
  if (ctx.log) {
    ctx.log(level, `[SafeSkill Guard] ${msg}`);
  } else {
    const prefix = level === "error" ? "ERROR" : level === "warn" ? "WARN" : "INFO";
    console.error(`[SafeSkill Guard] [${prefix}] ${msg}`);
  }
}

function checkAgentHealth(): { healthy: boolean; status: Record<string, unknown> | null } {
  if (!existsSync(SOCKET_PATH)) {
    return { healthy: false, status: null };
  }

  try {
    const result = execSync(
      `curl -sf --max-time 3 --unix-socket "${SOCKET_PATH}" http://localhost/health`,
      { encoding: "utf-8", timeout: 5000 }
    ).trim();

    const parsed = JSON.parse(result);
    return {
      healthy: parsed.status === "healthy" && parsed.running === true,
      status: parsed,
    };
  } catch {
    return { healthy: false, status: null };
  }
}

function getAgentStatus(): Record<string, unknown> | null {
  try {
    const result = execSync(
      `curl -sf --max-time 3 --unix-socket "${SOCKET_PATH}" http://localhost/status`,
      { encoding: "utf-8", timeout: 5000 }
    ).trim();
    return JSON.parse(result);
  } catch {
    return null;
  }
}

export default async function handler(ctx: HookContext): Promise<void> {
  log(ctx, "info", "Verifying SafeSkillAgent daemon...");

  const { healthy, status: healthStatus } = checkAgentHealth();

  if (!healthy) {
    const msg =
      "SafeSkillAgent daemon is NOT running or unreachable. " +
      `Socket: ${SOCKET_PATH}. ` +
      "Start it with: safeskill start";

    if (FAIL_CLOSED) {
      log(ctx, "error", `${msg} — BLOCKING agent bootstrap (fail-closed mode).`);
      throw new Error(
        `[SafeSkill Guard] Security agent unreachable. ${msg}`
      );
    } else {
      log(ctx, "warn", `${msg} — Continuing in FAIL-OPEN mode (SAFESKILL_FAIL_OPEN=1).`);
      if (ctx.addBootstrapFile) {
        ctx.addBootstrapFile(
          "safeskill-warning.md",
          "# WARNING: SafeSkillAgent is NOT running\n\n" +
            "The security enforcement agent is unreachable. Commands are NOT being " +
            "evaluated for safety. Start the agent immediately:\n\n" +
            "```bash\nsafeskill start\n```\n"
        );
      }
      return;
    }
  }

  const agentStatus = getAgentStatus();
  const trustMode = (agentStatus?.trust_mode as string) || "unknown";
  const environment = (agentStatus?.environment as string) || "unknown";
  const activeRules = (agentStatus?.active_rules as number) || 0;
  const sigCount = (agentStatus?.signatures_loaded as number) || 0;

  log(
    ctx,
    "info",
    `SafeSkillAgent is healthy. Mode: ${trustMode}, Env: ${environment}, ` +
      `Rules: ${activeRules}, Signatures: ${sigCount}`
  );

  // Enforce exec security policy — host=gateway is CRITICAL
  // Without it, OpenClaw runs in sandbox mode which skips all approval checks
  if (ctx.setExecDefaults) {
    ctx.setExecDefaults({
      host: "gateway",
      security: "allowlist",
      ask: "on-miss",
      askFallback: "deny",
    });
    log(ctx, "info", "Exec defaults set to: host=gateway, security=allowlist, ask=on-miss, askFallback=deny");
  }

  // Inject bootstrap context so the LLM knows about security enforcement
  if (ctx.addBootstrapFile) {
    ctx.addBootstrapFile(
      "safeskill-active.md",
      "# SafeSkillAgent Active\n\n" +
        "A security enforcement agent is running on this machine. " +
        "**Before executing ANY shell command**, you MUST first run:\n\n" +
        "```bash\nsafeskill check \"<command>\"\n```\n\n" +
        "If the result is BLOCKED, do NOT execute the command. " +
        "If the result is WARNED, inform the user before proceeding.\n\n" +
        `Current configuration: trust_mode=${trustMode}, environment=${environment}, ` +
        `active_rules=${activeRules}, signatures=${sigCount}\n`
    );
  }
}
