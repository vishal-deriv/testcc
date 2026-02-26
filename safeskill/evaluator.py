"""Command evaluation engine - the core of SafeSkillAgent."""

from __future__ import annotations

import re
import shlex
import time
from typing import Any

import structlog

from .models import (
    Action,
    AgentConfig,
    Environment,
    EvaluationRequest,
    EvaluationResult,
    PolicyRule,
    Severity,
    TrustMode,
    Verdict,
)
from .policy import PolicyManager
from .signatures import SignatureManager
from .trust import TrustEnforcer

logger = structlog.get_logger(__name__)


class CommandEvaluator:
    """Evaluates shell commands against policies, signatures, and trust rules.

    This is the central decision engine. It NEVER executes commands --
    it only returns allow/block/warn verdicts.
    """

    SHELL_METACHARACTERS = re.compile(r"[;|&`$(){}]")
    ENCODED_PAYLOAD = re.compile(
        r"(base64\s+(--decode|-d)|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|%[0-9a-fA-F]{2})"
    )
    VARIABLE_EXPANSION = re.compile(r"\$\{.*\}|\$\(.*\)")
    HISTORY_EXPANSION = re.compile(r"![\w!]+")
    GLOB_BOMB = re.compile(r"(\*{2,}|/\*\*/\*)")
    PIPE_TO_SHELL = re.compile(
        r"\|\s*(bash|sh|zsh|fish|dash|ksh|csh|tcsh|python[23]?|perl|ruby|node|php)"
    )
    CURL_PIPE_SHELL = re.compile(
        r"(curl|wget)\s+.*\|\s*(bash|sh|zsh|sudo\s+bash|sudo\s+sh)"
    )
    REDIRECT_SENSITIVE = re.compile(
        r">\s*(/etc/|/usr/|/boot/|/sys/|/proc/|/dev/sd|/dev/nvme|/dev/disk)"
    )
    HIDDEN_FILE_WRITE = re.compile(r">\s*\.[\w]+")
    REVERSE_SHELL_PATTERNS = [
        re.compile(r"bash\s+-i\s+>(&|\s)/dev/tcp/", re.IGNORECASE),
        re.compile(r"nc\s+(-e|--exec)\s+", re.IGNORECASE),
        re.compile(r"ncat\s+(-e|--exec)\s+", re.IGNORECASE),
        re.compile(r"mkfifo\s+.*\s+nc\s+", re.IGNORECASE),
        re.compile(r"python[23]?\s+-c\s+.*socket.*connect", re.IGNORECASE),
        re.compile(r"perl\s+-e\s+.*socket.*INET", re.IGNORECASE),
        re.compile(r"ruby\s+-rsocket\s+-e", re.IGNORECASE),
        re.compile(r"php\s+-r\s+.*fsockopen", re.IGNORECASE),
        re.compile(r"socat\s+.*exec:", re.IGNORECASE),
        re.compile(r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+", re.IGNORECASE),
        re.compile(r"telnet\s+\d+\.\d+\.\d+\.\d+\s+\d+\s*\|", re.IGNORECASE),
    ]
    CRYPTO_MINER_PATTERNS = [
        re.compile(r"(xmrig|cgminer|bfgminer|cpuminer|minerd|ethminer)", re.IGNORECASE),
        re.compile(r"stratum\+tcp://", re.IGNORECASE),
        re.compile(r"--donate-level", re.IGNORECASE),
        re.compile(r"monero.*pool|pool.*monero", re.IGNORECASE),
    ]
    DATA_EXFIL_PATTERNS = [
        re.compile(
            r"(curl|wget|nc|ncat)\s+.*(-d\s+@/etc/passwd|-d\s+@/etc/shadow)", re.IGNORECASE
        ),
        re.compile(r"tar\s+.*\|\s*(curl|wget|nc)\s+", re.IGNORECASE),
        # Catch plain reads, pipes, and redirection variants like:
        # cat /etc/passwd
        # cat /etc/passwd | nc ...
        # cat /etc/passwd > /dev/null
        re.compile(r"cat\s+/etc/(passwd|shadow)(\s*(\||>|>>|<|$))", re.IGNORECASE),
        re.compile(r"cat\s+/etc/hosts\s*\|", re.IGNORECASE),
        re.compile(r"scp\s+/etc/(passwd|shadow)\s+", re.IGNORECASE),
    ]
    PRIVILEGE_ESCALATION = [
        re.compile(r"chmod\s+[0-7]*[4-7][0-7]{2}\s+", re.IGNORECASE),  # setuid/setgid
        re.compile(r"chmod\s+u\+s\s+", re.IGNORECASE),
        re.compile(r"chmod\s+g\+s\s+", re.IGNORECASE),
        re.compile(r"chmod\s+[0-7]*777\s+", re.IGNORECASE),
        re.compile(r"sudo\s+chmod\s+777\s+/", re.IGNORECASE),
        re.compile(r"echo\s+.*>>\s*/etc/sudoers", re.IGNORECASE),
        re.compile(r"visudo", re.IGNORECASE),
        re.compile(r"NOPASSWD", re.IGNORECASE),
    ]
    DISK_FORMAT = re.compile(r"\b(mkfs|mkfs\.\w+)\s+", re.IGNORECASE)
    DD_RAW_DISK = re.compile(
        r"\bdd\s+.*of=/dev/(sd[a-z]|nvme\d|hd[a-z]|vd[a-z]|disk\d|mmcblk\d)", re.IGNORECASE
    )
    SHRED_SYSTEM = re.compile(r"\bshred\s+.*(/etc/|/usr/|/boot/|/sys/|/var/)", re.IGNORECASE)
    WIPEFS = re.compile(r"\bwipefs\s+", re.IGNORECASE)
    FORK_BOMB = re.compile(r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;?\s*:|bomb\(\)\s*\{", re.IGNORECASE)
    DANGEROUS_EVALS = re.compile(
        r"\b(eval|exec)\s+[\"']|python[23]?\s+-c\s+[\"'].*__(import|builtins)__"
    )
    SKILL_INJECTION_PATTERNS = [
        re.compile(r"safeskill\s+(disable|stop|uninstall|remove)", re.IGNORECASE),
        re.compile(r"systemctl\s+(stop|disable|mask)\s+safeskill", re.IGNORECASE),
        re.compile(r"launchctl\s+(unload|remove)\s+.*safeskill", re.IGNORECASE),
        re.compile(r"kill.*safeskill", re.IGNORECASE),
        re.compile(r"rm\s+.*safeskill", re.IGNORECASE),
        re.compile(r">\s*/etc/safeskill/", re.IGNORECASE),
        re.compile(r">\s*/var/log/safeskill/", re.IGNORECASE),
    ]

    def __init__(
        self,
        config: AgentConfig,
        policy_manager: PolicyManager,
        signature_manager: SignatureManager,
        trust_enforcer: TrustEnforcer,
    ) -> None:
        self._config = config
        self._policy = policy_manager
        self._signatures = signature_manager
        self._trust = trust_enforcer

    def evaluate(self, request: EvaluationRequest) -> EvaluationResult:
        start = time.monotonic()
        command = request.command.strip()

        if not command:
            return self._make_result(
                command=command,
                verdict=Verdict.BLOCKED,
                message="Empty command rejected",
                start_time=start,
            )

        if len(command) > self._config.max_command_length:
            return self._make_result(
                command=command,
                verdict=Verdict.BLOCKED,
                severity=Severity.HIGH,
                message=f"Command exceeds max length ({len(command)} > {self._config.max_command_length})",
                start_time=start,
            )

        base_cmd = self._extract_base_command(command)

        tamper = self._check_self_protection(command)
        if tamper:
            return self._make_result(
                command=command,
                verdict=Verdict.BLOCKED,
                severity=Severity.CRITICAL,
                message=f"Self-protection: {tamper}",
                matched_rules=["SELF-PROTECT"],
                start_time=start,
            )

        if not self._trust.check_zero_trust_allowlist(base_cmd):
            return self._make_result(
                command=command,
                verdict=Verdict.BLOCKED,
                severity=Severity.HIGH,
                message=f"Zero-trust mode: '{base_cmd}' not in allowlist",
                matched_rules=["ZERO-TRUST-ALLOWLIST"],
                start_time=start,
            )

        if not self._trust.check_strict_blocklist(base_cmd):
            return self._make_result(
                command=command,
                verdict=Verdict.BLOCKED,
                severity=Severity.HIGH,
                message=f"Strict mode: '{base_cmd}' is in blocked commands list",
                matched_rules=["STRICT-BLOCKLIST"],
                start_time=start,
            )

        heuristic = self._run_heuristics(command)
        if heuristic:
            return self._make_result(
                command=command,
                verdict=Verdict.BLOCKED,
                severity=heuristic["severity"],
                message=heuristic["message"],
                matched_rules=[heuristic["rule"]],
                start_time=start,
            )

        matched_policy_rules: list[str] = []
        worst_severity: Severity | None = None
        worst_action: Action = Action.ALLOW
        worst_message: str = ""

        for rule in self._policy.active_rules:
            if self._match_policy_rule(command, rule):
                matched_policy_rules.append(rule.id)
                if worst_severity is None or _severity_rank(rule.severity) > _severity_rank(
                    worst_severity
                ):
                    worst_severity = rule.severity
                    worst_action = rule.action
                    worst_message = rule.message

        sig_matches = self._signatures.match(command)
        matched_sigs: list[str] = []
        for sm in sig_matches:
            matched_sigs.append(sm.signature_id)
            if worst_severity is None or _severity_rank(sm.severity) > _severity_rank(
                worst_severity
            ):
                worst_severity = sm.severity
                worst_action = Action.BLOCK
                worst_message = sm.description

        if matched_policy_rules or matched_sigs:
            verdict = self._trust.evaluate_severity(
                worst_severity or Severity.MEDIUM, worst_action
            )
            return self._make_result(
                command=command,
                verdict=verdict,
                severity=worst_severity,
                message=worst_message,
                matched_rules=matched_policy_rules,
                matched_signatures=matched_sigs,
                start_time=start,
            )

        return self._make_result(
            command=command,
            verdict=Verdict.ALLOWED,
            message="No threats detected",
            start_time=start,
        )

    def _extract_base_command(self, command: str) -> str:
        stripped = command.strip()
        # Loop until stable: strip all layers of prefixes (sudo nohup rm -> rm)
        prefixes = ("sudo ", "nohup ", "nice ", "time ", "env ", "strace ", "command ")
        changed = True
        while changed:
            changed = False
            for prefix in prefixes:
                if stripped.startswith(prefix):
                    stripped = stripped[len(prefix) :].lstrip()
                    changed = True
                    break

        try:
            tokens = shlex.split(stripped)
            if tokens:
                return tokens[0]
        except ValueError:
            pass

        parts = stripped.split()
        return parts[0] if parts else stripped

    def _check_self_protection(self, command: str) -> str | None:
        for pattern in self.SKILL_INJECTION_PATTERNS:
            if pattern.search(command):
                return "Attempt to tamper with SafeSkillAgent detected"
        return None

    def _run_heuristics(self, command: str) -> dict[str, Any] | None:
        if self.DISK_FORMAT.search(command):
            return {
                "rule": "HEUR-DISKFORMAT",
                "severity": Severity.CRITICAL,
                "message": "Disk formatting command detected",
            }

        if self.DD_RAW_DISK.search(command):
            return {
                "rule": "HEUR-DDRAWDISK",
                "severity": Severity.CRITICAL,
                "message": "dd write to raw disk device detected",
            }

        if self.SHRED_SYSTEM.search(command):
            return {
                "rule": "HEUR-SHREDSYS",
                "severity": Severity.CRITICAL,
                "message": "Shred of system files detected",
            }

        if self.WIPEFS.search(command):
            return {
                "rule": "HEUR-WIPEFS",
                "severity": Severity.CRITICAL,
                "message": "Filesystem wipe detected",
            }

        if self.FORK_BOMB.search(command):
            return {
                "rule": "HEUR-FORKBOMB",
                "severity": Severity.CRITICAL,
                "message": "Fork bomb detected",
            }

        for pattern in self.REVERSE_SHELL_PATTERNS:
            if pattern.search(command):
                return {
                    "rule": "HEUR-REVSHELL",
                    "severity": Severity.CRITICAL,
                    "message": "Reverse shell pattern detected",
                }

        for pattern in self.CRYPTO_MINER_PATTERNS:
            if pattern.search(command):
                return {
                    "rule": "HEUR-CRYPTOMINER",
                    "severity": Severity.CRITICAL,
                    "message": "Cryptocurrency miner detected",
                }

        for pattern in self.DATA_EXFIL_PATTERNS:
            if pattern.search(command):
                return {
                    "rule": "HEUR-DATAEXFIL",
                    "severity": Severity.CRITICAL,
                    "message": "Data exfiltration pattern detected",
                }

        for pattern in self.PRIVILEGE_ESCALATION:
            if pattern.search(command):
                return {
                    "rule": "HEUR-PRIVESC",
                    "severity": Severity.HIGH,
                    "message": "Privilege escalation pattern detected",
                }

        if self.CURL_PIPE_SHELL.search(command):
            return {
                "rule": "HEUR-CURLPIPE",
                "severity": Severity.CRITICAL,
                "message": "Curl/wget pipe to shell detected",
            }

        if self.PIPE_TO_SHELL.search(command):
            return {
                "rule": "HEUR-PIPESHELL",
                "severity": Severity.HIGH,
                "message": "Pipe to shell interpreter detected",
            }

        if self.REDIRECT_SENSITIVE.search(command):
            return {
                "rule": "HEUR-REDIRECT-SENSITIVE",
                "severity": Severity.HIGH,
                "message": "Redirect to sensitive system path detected",
            }

        if self.DANGEROUS_EVALS.search(command):
            return {
                "rule": "HEUR-EVAL",
                "severity": Severity.HIGH,
                "message": "Dangerous eval/exec pattern detected",
            }

        return None

    def _match_policy_rule(self, command: str, rule: PolicyRule) -> bool:
        try:
            if rule.pattern_type == "regex":
                return bool(re.search(rule.pattern, command, re.IGNORECASE))
            elif rule.pattern_type == "exact":
                return command.strip() == rule.pattern.strip()
            elif rule.pattern_type == "contains":
                return rule.pattern.lower() in command.lower()
            elif rule.pattern_type == "startswith":
                return command.strip().lower().startswith(rule.pattern.lower())
            else:
                logger.warning(
                    "unknown_pattern_type",
                    rule_id=rule.id,
                    pattern_type=rule.pattern_type,
                )
                return False
        except re.error as exc:
            logger.error(
                "regex_match_error",
                rule_id=rule.id,
                error=str(exc),
            )
            return False

    def _make_result(
        self,
        command: str,
        verdict: Verdict,
        severity: Severity | None = None,
        message: str = "",
        matched_rules: list[str] | None = None,
        matched_signatures: list[str] | None = None,
        start_time: float = 0.0,
    ) -> EvaluationResult:
        elapsed = (time.monotonic() - start_time) * 1000 if start_time else 0.0

        result = EvaluationResult(
            verdict=verdict,
            command=command,
            matched_rules=matched_rules or [],
            matched_signatures=matched_signatures or [],
            severity=severity,
            message=message,
            evaluation_time_ms=round(elapsed, 3),
            trust_mode=self._trust.trust_mode,
            environment=self._config.environment,
        )

        log_fn = logger.info if verdict == Verdict.ALLOWED else logger.warning
        log_fn(
            "command_evaluated",
            verdict=verdict.value,
            command=_truncate(command, 200),
            severity=severity.value if severity else None,
            matched_rules=matched_rules,
            matched_signatures=matched_signatures,
            elapsed_ms=result.evaluation_time_ms,
        )

        return result


def _severity_rank(severity: Severity) -> int:
    return {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }.get(severity, 0)


def _truncate(s: str, max_len: int) -> str:
    return s[:max_len] + "..." if len(s) > max_len else s
