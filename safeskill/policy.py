"""Policy management with hot-reload support."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

import structlog
import yaml

from .models import (
    Action,
    AgentConfig,
    Environment,
    PolicyRule,
    Severity,
    TrustMode,
)

logger = structlog.get_logger(__name__)


class PolicyValidationError(Exception):
    pass


class PolicyManager:
    """Loads, validates, and manages security policies with hot-reload."""

    def __init__(self, config: AgentConfig) -> None:
        self._config = config
        self._base_rules: list[PolicyRule] = []
        self._runtime_rules: list[PolicyRule] = []
        self._environment_overrides: dict[str, Any] = {}
        self._policy_hashes: dict[str, str] = {}
        self._rule_index: dict[str, PolicyRule] = {}

    @property
    def active_rules(self) -> list[PolicyRule]:
        """Return all active rules filtered by current environment and trust mode."""
        all_rules = self._base_rules + self._runtime_rules
        active: list[PolicyRule] = []
        for rule in all_rules:
            if not rule.enabled:
                continue
            if (
                rule.environments
                and self._config.environment not in rule.environments
            ):
                continue
            if (
                rule.trust_modes
                and self._config.trust_mode not in rule.trust_modes
            ):
                continue
            active.append(rule)
        return active

    def load_all(self) -> None:
        """Load all policy files from config directory."""
        config_dir = Path(self._config.config_dir)
        base_policy = config_dir / "base-policy.yaml"
        runtime_policy = config_dir / "runtime-policy.yaml"
        env_dir = config_dir / "environments"
        env_file = env_dir / f"{self._config.environment.value}.yaml"

        if base_policy.exists():
            self._load_base_policy(base_policy)
        else:
            logger.warning("base_policy_not_found", path=str(base_policy))

        if runtime_policy.exists():
            self._load_runtime_policy(runtime_policy)

        if env_file.exists():
            self._load_environment_overrides(env_file)

        self._rebuild_index()
        logger.info(
            "policies_loaded",
            base_rules=len(self._base_rules),
            runtime_rules=len(self._runtime_rules),
            active_rules=len(self.active_rules),
            environment=self._config.environment.value,
            trust_mode=self._config.trust_mode.value,
        )

    def reload_if_changed(self) -> bool:
        """Reload policies only if files have changed. Returns True if reloaded."""
        config_dir = Path(self._config.config_dir)
        changed = False

        for name in ("base-policy.yaml", "runtime-policy.yaml"):
            filepath = config_dir / name
            if filepath.exists():
                current_hash = self._file_hash(filepath)
                if self._policy_hashes.get(name) != current_hash:
                    changed = True
                    break

        env_file = (
            config_dir / "environments" / f"{self._config.environment.value}.yaml"
        )
        if env_file.exists():
            current_hash = self._file_hash(env_file)
            if self._policy_hashes.get(env_file.name) != current_hash:
                changed = True

        if changed:
            logger.info("policy_change_detected", reloading=True)
            self.load_all()
            return True
        return False

    def get_rule(self, rule_id: str) -> PolicyRule | None:
        return self._rule_index.get(rule_id)

    def inject_runtime_rules(self, rules: list[dict[str, Any]]) -> int:
        """Inject runtime policy rules dynamically. Returns count of rules added."""
        added = 0
        for rule_data in rules:
            try:
                rule = PolicyRule(**rule_data)
                self._validate_rule(rule)
                self._runtime_rules.append(rule)
                added += 1
            except Exception as exc:
                logger.error("runtime_rule_injection_failed", error=str(exc), rule=rule_data)
        self._rebuild_index()
        logger.info("runtime_rules_injected", count=added)
        return added

    def clear_runtime_rules(self) -> None:
        self._runtime_rules.clear()
        self._rebuild_index()
        logger.info("runtime_rules_cleared")

    def _load_base_policy(self, path: Path) -> None:
        data = self._safe_yaml_load(path)
        self._policy_hashes[path.name] = self._file_hash(path)
        if not isinstance(data, dict) or "rules" not in data:
            raise PolicyValidationError(f"Invalid base policy format in {path}")
        self._base_rules = []
        for rule_data in data["rules"]:
            rule = PolicyRule(**rule_data)
            self._validate_rule(rule)
            self._base_rules.append(rule)

    def _load_runtime_policy(self, path: Path) -> None:
        data = self._safe_yaml_load(path)
        self._policy_hashes[path.name] = self._file_hash(path)
        if not isinstance(data, dict):
            return
        rules_data = data.get("rules", [])
        self._runtime_rules = []
        for rule_data in rules_data:
            rule = PolicyRule(**rule_data)
            self._validate_rule(rule)
            self._runtime_rules.append(rule)

    def _load_environment_overrides(self, path: Path) -> None:
        data = self._safe_yaml_load(path)
        self._policy_hashes[path.name] = self._file_hash(path)
        if isinstance(data, dict):
            self._environment_overrides = data
            disabled_rules = data.get("disabled_rules", [])
            for rule_id in disabled_rules:
                for rule in self._base_rules + self._runtime_rules:
                    if rule.id == rule_id:
                        rule.enabled = False

            severity_overrides = data.get("severity_overrides", {})
            for rule_id, new_severity in severity_overrides.items():
                for rule in self._base_rules + self._runtime_rules:
                    if rule.id == rule_id:
                        rule.severity = Severity(new_severity)

            action_overrides = data.get("action_overrides", {})
            for rule_id, new_action in action_overrides.items():
                for rule in self._base_rules + self._runtime_rules:
                    if rule.id == rule_id:
                        rule.action = Action(new_action)

    def _validate_rule(self, rule: PolicyRule) -> None:
        if not rule.id or not rule.id.strip():
            raise PolicyValidationError("Rule must have a non-empty id")
        if not rule.pattern or not rule.pattern.strip():
            raise PolicyValidationError(f"Rule {rule.id} must have a non-empty pattern")
        if len(rule.pattern) > 4096:
            raise PolicyValidationError(f"Rule {rule.id} pattern exceeds max length")

    def _rebuild_index(self) -> None:
        self._rule_index = {}
        for rule in self._base_rules + self._runtime_rules:
            self._rule_index[rule.id] = rule

    @staticmethod
    def _safe_yaml_load(path: Path) -> Any:
        max_size = 10 * 1024 * 1024  # 10 MB
        file_size = path.stat().st_size
        if file_size > max_size:
            raise PolicyValidationError(
                f"Policy file {path} exceeds max size ({file_size} > {max_size})"
            )
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    @staticmethod
    def _file_hash(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
