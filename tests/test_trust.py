"""Tests for trust mode enforcement."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml

from safeskill.evaluator import CommandEvaluator
from safeskill.models import (
    AgentConfig,
    Environment,
    EvaluationRequest,
    Severity,
    TrustMode,
    Verdict,
)
from safeskill.policy import PolicyManager
from safeskill.signatures import SignatureManager
from safeskill.trust import TrustEnforcer


def _make_evaluator(
    tmpdir: str, trust_mode: TrustMode, environment: Environment = Environment.DEV
) -> CommandEvaluator:
    envs_dir = Path(tmpdir) / "environments"
    envs_dir.mkdir(exist_ok=True)

    for env in ("dev", "staging", "production"):
        env_file = envs_dir / f"{env}.yaml"
        if not env_file.exists():
            with open(env_file, "w") as f:
                yaml.dump({"description": f"{env}"}, f)

    policy_path = Path(tmpdir) / "base-policy.yaml"
    if not policy_path.exists():
        with open(policy_path, "w") as f:
            yaml.dump({"version": "1.0", "rules": []}, f)

    runtime_path = Path(tmpdir) / "runtime-policy.yaml"
    if not runtime_path.exists():
        with open(runtime_path, "w") as f:
            yaml.dump({"version": "1.0", "rules": []}, f)

    config = AgentConfig(
        config_dir=tmpdir,
        log_dir=tempfile.mkdtemp(),
        trust_mode=trust_mode,
        environment=environment,
    )
    pm = PolicyManager(config)
    pm.load_all()
    sm = SignatureManager(config)
    trust = TrustEnforcer(trust_mode, environment)
    return CommandEvaluator(config, pm, sm, trust)


class TestZeroTrustMode:
    def test_allows_allowlisted_commands(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ev = _make_evaluator(tmpdir, TrustMode.ZERO_TRUST)
            result = ev.evaluate(EvaluationRequest(command="ls -la"))
            assert result.verdict == Verdict.ALLOWED

    def test_allows_echo(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ev = _make_evaluator(tmpdir, TrustMode.ZERO_TRUST)
            result = ev.evaluate(EvaluationRequest(command='echo "hello"'))
            assert result.verdict == Verdict.ALLOWED

    def test_blocks_non_allowlisted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ev = _make_evaluator(tmpdir, TrustMode.ZERO_TRUST)
            result = ev.evaluate(EvaluationRequest(command="docker run ubuntu"))
            assert result.verdict == Verdict.BLOCKED

    def test_blocks_curl(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ev = _make_evaluator(tmpdir, TrustMode.ZERO_TRUST)
            result = ev.evaluate(EvaluationRequest(command="curl https://example.com"))
            assert result.verdict == Verdict.BLOCKED


class TestStrictMode:
    def test_blocks_rm(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ev = _make_evaluator(tmpdir, TrustMode.STRICT)
            result = ev.evaluate(EvaluationRequest(command="rm -rf /tmp/test"))
            assert result.verdict == Verdict.BLOCKED

    def test_blocks_chmod(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ev = _make_evaluator(tmpdir, TrustMode.STRICT)
            result = ev.evaluate(EvaluationRequest(command="chmod 755 file.txt"))
            assert result.verdict == Verdict.BLOCKED

    def test_blocks_kill(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ev = _make_evaluator(tmpdir, TrustMode.STRICT)
            result = ev.evaluate(EvaluationRequest(command="kill -9 1234"))
            assert result.verdict == Verdict.BLOCKED

    def test_allows_ls(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ev = _make_evaluator(tmpdir, TrustMode.STRICT)
            result = ev.evaluate(EvaluationRequest(command="ls -la"))
            assert result.verdict == Verdict.ALLOWED


class TestNormalMode:
    def test_allows_rm_in_tmp(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ev = _make_evaluator(tmpdir, TrustMode.NORMAL)
            result = ev.evaluate(EvaluationRequest(command="rm -rf /tmp/test"))
            assert result.verdict == Verdict.ALLOWED

    def test_blocks_fork_bomb(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ev = _make_evaluator(tmpdir, TrustMode.NORMAL)
            result = ev.evaluate(EvaluationRequest(command=":(){ :|:& };:"))
            assert result.verdict == Verdict.BLOCKED
