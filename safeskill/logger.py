"""Tamper-resistant audit logging for SafeSkillAgent."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog
from filelock import FileLock

from .models import AgentConfig, EvaluationResult

logger = structlog.get_logger(__name__)


class AuditLogger:
    """Append-only, hash-chained audit logger.

    Each log entry includes a SHA-256 hash of the previous entry,
    creating a tamper-evident chain. The log file is opened in append
    mode with restrictive permissions.
    """

    def __init__(self, config: AgentConfig) -> None:
        self._config = config
        self._log_dir = Path(config.log_dir)
        self._prev_hash = "0" * 64  # Genesis hash
        self._lock: FileLock | None = None
        self._initialized = False

    def initialize(self) -> None:
        """Set up log directory and file with secure permissions."""
        self._log_dir.mkdir(parents=True, exist_ok=True)

        try:
            os.chmod(str(self._log_dir), stat.S_IRWXU)  # 700
        except OSError:
            pass  # May not have permission in some setups

        self._lock = FileLock(str(self._log_dir / ".audit.lock"), timeout=5)

        audit_file = self._current_audit_file()
        if audit_file.exists():
            self._recover_chain_hash(audit_file)

        self._initialized = True
        logger.info("audit_logger_initialized", log_dir=str(self._log_dir))

    def log_evaluation(self, result: EvaluationResult, source: str = "") -> None:
        """Log an evaluation result to the audit trail."""
        if not self._initialized:
            self.initialize()

        entry = {
            "timestamp": result.timestamp.isoformat(),
            "verdict": result.verdict.value,
            "command_hash": hashlib.sha256(result.command.encode()).hexdigest(),
            "command_preview": result.command[:100],
            "matched_rules": result.matched_rules,
            "matched_signatures": result.matched_signatures,
            "severity": result.severity.value if result.severity else None,
            "message": result.message,
            "trust_mode": result.trust_mode.value,
            "environment": result.environment.value,
            "evaluation_time_ms": result.evaluation_time_ms,
            "source": source,
            "prev_hash": self._prev_hash,
        }

        entry_json = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        entry_hash = hashlib.sha256(entry_json.encode()).hexdigest()
        entry["entry_hash"] = entry_hash

        self._write_entry(entry)
        self._prev_hash = entry_hash

    def log_event(self, event_type: str, details: dict[str, Any] | None = None) -> None:
        """Log a non-evaluation event (startup, config change, etc.)."""
        if not self._initialized:
            self.initialize()

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "details": details or {},
            "prev_hash": self._prev_hash,
        }

        entry_json = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        entry_hash = hashlib.sha256(entry_json.encode()).hexdigest()
        entry["entry_hash"] = entry_hash

        self._write_entry(entry)
        self._prev_hash = entry_hash

    def verify_chain(self) -> tuple[bool, int, int]:
        """Verify the integrity of the audit chain. Returns (valid, total, broken_at)."""
        audit_file = self._current_audit_file()
        if not audit_file.exists():
            return True, 0, -1

        prev_hash = "0" * 64
        line_num = 0

        with open(audit_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False, line_num, line_num

                if entry.get("prev_hash") != prev_hash:
                    return False, line_num, line_num

                stored_hash = entry.pop("entry_hash", "")
                entry_json = json.dumps(entry, sort_keys=True, separators=(",", ":"))
                computed_hash = hashlib.sha256(entry_json.encode()).hexdigest()

                if stored_hash != computed_hash:
                    return False, line_num, line_num

                prev_hash = stored_hash
                line_num += 1

        return True, line_num, -1

    def _current_audit_file(self) -> Path:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self._log_dir / f"audit-{today}.jsonl"

    def _write_entry(self, entry: dict[str, Any]) -> None:
        audit_file = self._current_audit_file()
        line = json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n"

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
            os.chmod(str(audit_file), stat.S_IRUSR | stat.S_IWUSR)  # 600
        except OSError:
            pass

    def _recover_chain_hash(self, audit_file: Path) -> None:
        """Read the last entry's hash to continue the chain."""
        try:
            last_line = ""
            with open(audit_file, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped
            if last_line:
                entry = json.loads(last_line)
                self._prev_hash = entry.get("entry_hash", "0" * 64)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("chain_recovery_failed", error=str(exc))


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
