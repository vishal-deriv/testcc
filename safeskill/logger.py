"""SIEM-friendly audit logging for SafeSkillAgent."""

from __future__ import annotations

import json
import os
import socket
import stat
import sys
import threading
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog
from filelock import FileLock

from .models import AgentConfig, EvaluationResult, Severity

logger = structlog.get_logger(__name__)

SEVERITY_TO_RISK = {Severity.CRITICAL: 100, Severity.HIGH: 75, Severity.MEDIUM: 50, Severity.LOW: 25}


class AuditLogger:
    """SIEM-friendly append-only audit logger.
    Outputs flat JSONL compatible with SIEM ingestion.
    """

    def __init__(self, config: AgentConfig) -> None:
        self._config = config
        self._log_dir = Path(config.log_dir)
        self._lock: FileLock | None = None
        self._initialized = False
        self._hostname = config.default_hostname or socket.gethostname()
        self._default_user = config.default_user or ""
        self._default_source_ip = config.default_source_ip or ""

    def initialize(self) -> None:
        """Set up log directory and file."""
        self._log_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(str(self._log_dir), stat.S_IRWXU)
        except OSError:
            pass
        self._lock = FileLock(str(self._log_dir / ".audit.lock"), timeout=5)
        self._initialized = True
        logger.info("audit_logger_initialized", log_dir=str(self._log_dir))

    def log_evaluation(self, result: EvaluationResult, source: str = "", user: str = "") -> None:
        """Log an evaluation in SIEM format."""
        if not self._initialized:
            self.initialize()

        risk = SEVERITY_TO_RISK.get(result.severity, 0) if result.severity else 0

        blocked = result.verdict.value == "blocked"
        entry = {
            "event_timestamp": result.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "hostname": self._hostname,
            "event_action": "evaluate",
            "event_outcome": result.verdict.value,
            "blocked": blocked,
            "risk_score": risk,
            "system_command": result.command,
            "user_name": user or self._default_user,
            "user_email": "",
            "source_ip": self._default_source_ip,
            "source": source,
            "severity": result.severity.value if result.severity else None,
            "matched_rules": result.matched_rules,
            "matched_signatures": result.matched_signatures,
            "message": result.message,
        }

        self._write_entry(entry)

        if self._config.siem_endpoint_url:
            threading.Thread(
                target=self._forward_to_siem,
                args=(entry,),
                daemon=True,
            ).start()

    def _forward_to_siem(self, entry: dict[str, Any]) -> None:
        """POST audit entry to SIEM endpoint (fire-and-forget)."""
        try:
            data = json.dumps(entry).encode("utf-8")
            headers: dict[str, str] = {"Content-Type": "application/json"}
            if self._config.siem_auth_header:
                headers[self._config.siem_auth_header_name] = self._config.siem_auth_header
            req = urllib.request.Request(
                self._config.siem_endpoint_url,
                data=data,
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status >= 400:
                    logger.warning(
                        "siem_forward_failed",
                        status=resp.status,
                        url=self._config.siem_endpoint_url,
                    )
        except Exception as exc:
            logger.warning(
                "siem_forward_error",
                error=str(exc),
                url=self._config.siem_endpoint_url,
            )

    def log_event(self, event_type: str, details: dict[str, Any] | None = None) -> None:
        """Log a non-evaluation event."""
        if not self._initialized:
            self.initialize()

        now = datetime.now(timezone.utc)
        entry = {
            "event_timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "hostname": self._hostname,
            "event_action": event_type,
            "event_outcome": "success",
            "risk_score": 0,
            "system_command": "",
            "user_name": self._default_user,
            "user_email": "",
            "source_ip": self._default_source_ip,
            "source": "daemon",
            "details": details or {},
        }

        self._write_entry(entry)

    def verify_chain(self) -> tuple[bool, int, int]:
        """Return (valid, total_entries, broken_at). Always valid for SIEM format."""
        audit_file = self._current_audit_file()
        if not audit_file.exists():
            return True, 0, -1
        count = sum(1 for _ in open(audit_file, encoding="utf-8") if _.strip())
        return True, count, -1

    def _current_audit_file(self) -> Path:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self._log_dir / f"audit-{today}.jsonl"

    def _write_entry(self, entry: dict[str, Any]) -> None:
        audit_file = self._current_audit_file()
        line = json.dumps(entry, separators=(",", ":")) + "\n"

        if self._lock:
            with self._lock:
                with open(audit_file, "a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
        else:
            with open(audit_file, "a", encoding="utf-8") as f:
                f.write(line)
        try:
            os.chmod(str(audit_file), stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass


def configure_structlog(log_dir: str | None = None) -> None:
    """Configure structlog for the agent."""
    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
    ]

    if sys.stderr.isatty():
        processors.append(structlog.dev.ConsoleRenderer())
    else:
        processors.append(structlog.processors.JSONRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(0),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
