"""Tests for policy management."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml

from safeskill.models import AgentConfig, Environment, Severity, TrustMode
from safeskill.policy import PolicyManager, PolicyValidationError


@pytest.fixture
def config_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        envs_dir = Path(tmpdir) / "environments"
        envs_dir.mkdir()
        for env in ("dev", "staging", "production"):
            with open(envs_dir / f"{env}.yaml", "w") as f:
                yaml.dump({"description": f"{env} config"}, f)
        yield tmpdir


@pytest.fixture
def config(config_dir: str):
    return AgentConfig(
        config_dir=config_dir,
        log_dir=tempfile.mkdtemp(),
        trust_mode=TrustMode.NORMAL,
        environment=Environment.DEV,
    )


class TestPolicyLoading:
    def test_load_empty_config(self, config: AgentConfig):
        pm = PolicyManager(config)
        pm.load_all()
        assert len(pm.active_rules) == 0

    def test_load_base_policy(self, config: AgentConfig):
        policy_data = {
            "version": "1.0",
            "rules": [
                {
                    "id": "R-001",
                    "name": "Test Rule",
                    "severity": "high",
                    "pattern": "rm -rf /",
                    "action": "block",
                }
            ],
        }
        with open(Path(config.config_dir) / "base-policy.yaml", "w") as f:
            yaml.dump(policy_data, f)

        pm = PolicyManager(config)
        pm.load_all()
        assert len(pm.active_rules) == 1
        assert pm.active_rules[0].id == "R-001"

    def test_environment_disable_rule(self, config: AgentConfig):
        policy_data = {
            "version": "1.0",
            "rules": [
                {
                    "id": "R-001",
                    "name": "Test Rule",
                    "severity": "medium",
                    "pattern": "test",
                    "action": "warn",
                }
            ],
        }
        with open(Path(config.config_dir) / "base-policy.yaml", "w") as f:
            yaml.dump(policy_data, f)

        env_data = {"disabled_rules": ["R-001"]}
        with open(
            Path(config.config_dir) / "environments" / "dev.yaml", "w"
        ) as f:
            yaml.dump(env_data, f)

        pm = PolicyManager(config)
        pm.load_all()
        assert len(pm.active_rules) == 0

    def test_severity_override(self, config: AgentConfig):
        policy_data = {
            "version": "1.0",
            "rules": [
                {
                    "id": "R-001",
                    "name": "Test",
                    "severity": "low",
                    "pattern": "test",
                    "action": "warn",
                }
            ],
        }
        with open(Path(config.config_dir) / "base-policy.yaml", "w") as f:
            yaml.dump(policy_data, f)

        env_data = {"severity_overrides": {"R-001": "critical"}}
        with open(
            Path(config.config_dir) / "environments" / "dev.yaml", "w"
        ) as f:
            yaml.dump(env_data, f)

        pm = PolicyManager(config)
        pm.load_all()
        rule = pm.get_rule("R-001")
        assert rule is not None
        assert rule.severity == Severity.CRITICAL


class TestRuntimeInjection:
    def test_inject_rules(self, config: AgentConfig):
        pm = PolicyManager(config)
        pm.load_all()

        count = pm.inject_runtime_rules([
            {
                "id": "RT-001",
                "name": "Runtime rule",
                "severity": "high",
                "pattern": "block_this",
                "action": "block",
            }
        ])
        assert count == 1
        assert len(pm.active_rules) == 1

    def test_clear_runtime_rules(self, config: AgentConfig):
        pm = PolicyManager(config)
        pm.load_all()
        pm.inject_runtime_rules([
            {
                "id": "RT-001",
                "name": "Runtime rule",
                "severity": "high",
                "pattern": "test",
                "action": "block",
            }
        ])
        assert len(pm.active_rules) == 1
        pm.clear_runtime_rules()
        assert len(pm.active_rules) == 0


class TestHotReload:
    def test_reload_detects_change(self, config: AgentConfig):
        policy_data = {
            "version": "1.0",
            "rules": [
                {
                    "id": "R-001",
                    "name": "Test",
                    "severity": "low",
                    "pattern": "test",
                    "action": "warn",
                }
            ],
        }
        policy_path = Path(config.config_dir) / "base-policy.yaml"
        with open(policy_path, "w") as f:
            yaml.dump(policy_data, f)

        pm = PolicyManager(config)
        pm.load_all()
        assert len(pm.active_rules) == 1

        policy_data["rules"].append(
            {
                "id": "R-002",
                "name": "Test 2",
                "severity": "high",
                "pattern": "test2",
                "action": "block",
            }
        )
        with open(policy_path, "w") as f:
            yaml.dump(policy_data, f)

        reloaded = pm.reload_if_changed()
        assert reloaded is True
        assert len(pm.active_rules) == 2
