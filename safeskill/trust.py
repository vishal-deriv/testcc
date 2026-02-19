"""Trust mode enforcement logic."""

from __future__ import annotations

from .models import Action, Environment, Severity, TrustMode, Verdict


class TrustEnforcer:
    """Applies trust-mode-specific enforcement policies.

    Trust Modes:
    - normal:     Blocks critical/high, warns on medium, allows low
    - strict:     Blocks critical/high/medium, warns on low
    - zero-trust: Blocks everything not explicitly allowlisted
    """

    ALLOWLIST_ZERO_TRUST: set[str] = {
        "echo", "printf", "cat", "head", "tail", "wc", "sort", "uniq",
        "grep", "awk", "sed", "cut", "tr", "tee", "date", "cal",
        "pwd", "ls", "dir", "find", "which", "whereis", "type",
        "whoami", "id", "hostname", "uname",
        "true", "false", "test", "[",
        "basename", "dirname", "realpath", "readlink",
        "env", "printenv", "export",
        "cd", "pushd", "popd",
        "diff", "comm", "cmp", "md5sum", "sha256sum",
        "jq", "yq", "xargs",
        "man", "help", "info",
    }

    BLOCKED_COMMANDS_STRICT: set[str] = {
        "rm", "rmdir", "mkfs", "dd", "shred", "wipefs",
        "chmod", "chown", "chgrp",
        "kill", "killall", "pkill",
        "reboot", "shutdown", "halt", "poweroff", "init",
        "iptables", "ip6tables", "nft", "ufw", "firewall-cmd",
        "mount", "umount", "fdisk", "parted", "lvm",
        "useradd", "userdel", "usermod", "groupadd", "groupdel",
        "passwd", "chpasswd", "visudo",
        "systemctl", "service", "launchctl",
        "crontab", "at",
        "insmod", "rmmod", "modprobe",
        "sysctl",
    }

    def __init__(self, trust_mode: TrustMode, environment: Environment) -> None:
        self._trust_mode = trust_mode
        self._environment = environment

    @property
    def trust_mode(self) -> TrustMode:
        return self._trust_mode

    @trust_mode.setter
    def trust_mode(self, mode: TrustMode) -> None:
        self._trust_mode = mode

    def evaluate_severity(self, severity: Severity, action: Action) -> Verdict:
        """Determine verdict based on trust mode, severity, and rule action."""
        if action == Action.BLOCK:
            return Verdict.BLOCKED

        if action == Action.ALLOW:
            return Verdict.ALLOWED

        if self._trust_mode == TrustMode.ZERO_TRUST:
            return Verdict.BLOCKED

        if self._trust_mode == TrustMode.STRICT:
            if severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                return Verdict.BLOCKED
            return Verdict.WARNED

        # Normal mode
        if severity in (Severity.CRITICAL, Severity.HIGH):
            return Verdict.BLOCKED
        if severity == Severity.MEDIUM:
            return Verdict.WARNED
        return Verdict.ALLOWED

    def check_zero_trust_allowlist(self, base_command: str) -> bool:
        """In zero-trust mode, check if the command's base binary is allowlisted."""
        if self._trust_mode != TrustMode.ZERO_TRUST:
            return True
        return base_command.strip().split("/")[-1] in self.ALLOWLIST_ZERO_TRUST

    def check_strict_blocklist(self, base_command: str) -> bool:
        """In strict mode, check if the base command is in the blocked set."""
        if self._trust_mode not in (TrustMode.STRICT, TrustMode.ZERO_TRUST):
            return True
        binary = base_command.strip().split("/")[-1]
        return binary not in self.BLOCKED_COMMANDS_STRICT

    def get_environment_multiplier(self) -> float:
        """Production gets stricter scoring; dev is more lenient."""
        multipliers = {
            Environment.DEV: 0.8,
            Environment.STAGING: 1.0,
            Environment.PRODUCTION: 1.5,
        }
        return multipliers.get(self._environment, 1.0)
