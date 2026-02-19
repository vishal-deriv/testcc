"""Signature-based threat detection engine."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

import structlog
import yaml

from .models import AgentConfig, Severity, SignatureEntry

logger = structlog.get_logger(__name__)


class SignatureManager:
    """Manages and matches command signatures against known threat patterns."""

    def __init__(self, config: AgentConfig) -> None:
        self._config = config
        self._signatures: list[SignatureEntry] = []
        self._compiled_patterns: dict[str, list[re.Pattern[str]]] = {}
        self._sig_hash: str = ""

    @property
    def signature_count(self) -> int:
        return len(self._signatures)

    def load(self) -> None:
        """Load signatures from config directory."""
        sig_path = Path(self._config.config_dir) / "signatures.yaml"
        if not sig_path.exists():
            logger.warning("signatures_file_not_found", path=str(sig_path))
            return
        self._load_from_file(sig_path)

    def reload_if_changed(self) -> bool:
        sig_path = Path(self._config.config_dir) / "signatures.yaml"
        if not sig_path.exists():
            return False
        current_hash = self._file_hash(sig_path)
        if current_hash != self._sig_hash:
            logger.info("signature_change_detected", reloading=True)
            self._load_from_file(sig_path)
            return True
        return False

    def match(self, command: str) -> list[SignatureMatch]:
        """Match a command against all loaded signatures."""
        matches: list[SignatureMatch] = []
        normalized = self._normalize_command(command)

        for sig in self._signatures:
            if not sig.enabled:
                continue
            compiled = self._compiled_patterns.get(sig.id, [])
            for pattern in compiled:
                if pattern.search(normalized) or pattern.search(command):
                    matches.append(
                        SignatureMatch(
                            signature_id=sig.id,
                            signature_name=sig.name,
                            category=sig.category,
                            severity=sig.severity,
                            description=sig.description,
                            matched_pattern=pattern.pattern,
                        )
                    )
                    break  # One match per signature is enough
        return matches

    def inject_signatures(self, signatures: list[dict[str, Any]]) -> int:
        """Inject additional signatures at runtime."""
        added = 0
        for sig_data in signatures:
            try:
                sig = SignatureEntry(**sig_data)
                self._signatures.append(sig)
                self._compile_signature(sig)
                added += 1
            except Exception as exc:
                logger.error("signature_injection_failed", error=str(exc))
        logger.info("signatures_injected", count=added)
        return added

    def _load_from_file(self, path: Path) -> None:
        max_size = 10 * 1024 * 1024
        if path.stat().st_size > max_size:
            logger.error("signatures_file_too_large", path=str(path))
            return

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        self._sig_hash = self._file_hash(path)

        if not isinstance(data, dict) or "signatures" not in data:
            logger.error("invalid_signatures_format", path=str(path))
            return

        self._signatures = []
        self._compiled_patterns = {}

        for sig_data in data["signatures"]:
            try:
                sig = SignatureEntry(**sig_data)
                self._signatures.append(sig)
                self._compile_signature(sig)
            except Exception as exc:
                logger.error(
                    "signature_load_failed",
                    signature=sig_data.get("id", "unknown"),
                    error=str(exc),
                )

        logger.info("signatures_loaded", count=len(self._signatures))

    def _compile_signature(self, sig: SignatureEntry) -> None:
        compiled: list[re.Pattern[str]] = []
        for pattern_str in sig.patterns:
            try:
                compiled.append(re.compile(pattern_str, re.IGNORECASE))
            except re.error as exc:
                logger.error(
                    "signature_pattern_compile_failed",
                    signature_id=sig.id,
                    pattern=pattern_str,
                    error=str(exc),
                )
        self._compiled_patterns[sig.id] = compiled

    @staticmethod
    def _normalize_command(command: str) -> str:
        """Normalize command for matching (collapse whitespace, strip)."""
        return " ".join(command.split()).strip()

    @staticmethod
    def _file_hash(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()


class SignatureMatch:
    """Represents a matched signature."""

    __slots__ = (
        "signature_id",
        "signature_name",
        "category",
        "severity",
        "description",
        "matched_pattern",
    )

    def __init__(
        self,
        signature_id: str,
        signature_name: str,
        category: str,
        severity: Severity,
        description: str,
        matched_pattern: str,
    ) -> None:
        self.signature_id = signature_id
        self.signature_name = signature_name
        self.category = category
        self.severity = severity
        self.description = description
        self.matched_pattern = matched_pattern

    def to_dict(self) -> dict[str, str]:
        return {
            "signature_id": self.signature_id,
            "signature_name": self.signature_name,
            "category": self.category,
            "severity": self.severity.value,
            "description": self.description,
        }
