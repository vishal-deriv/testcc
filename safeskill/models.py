"""Data models for SafeSkillAgent."""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class TrustMode(str, enum.Enum):
    NORMAL = "normal"
    STRICT = "strict"
    ZERO_TRUST = "zero-trust"


class Environment(str, enum.Enum):
    DEV = "dev"
    STAGING = "staging"
    PRODUCTION = "production"


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, enum.Enum):
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"
    AUDIT = "audit"


class Verdict(str, enum.Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    WARNED = "warned"


class PolicyRule(BaseModel):
    id: str
    name: str
    description: str = ""
    severity: Severity
    pattern: str
    pattern_type: str = "regex"
    action: Action = Action.BLOCK
    message: str = ""
    environments: list[Environment] = Field(default_factory=lambda: list(Environment))
    trust_modes: list[TrustMode] = Field(default_factory=lambda: list(TrustMode))
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)


class SignatureEntry(BaseModel):
    id: str
    name: str
    category: str
    severity: Severity
    patterns: list[str]
    description: str = ""
    references: list[str] = Field(default_factory=list)
    enabled: bool = True


class EvaluationRequest(BaseModel):
    command: str
    source: str = "openclaw"
    user: str = ""
    working_directory: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvaluationResult(BaseModel):
    verdict: Verdict
    command: str
    matched_rules: list[str] = Field(default_factory=list)
    matched_signatures: list[str] = Field(default_factory=list)
    severity: Severity | None = None
    message: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evaluation_time_ms: float = 0.0
    trust_mode: TrustMode = TrustMode.NORMAL
    environment: Environment = Environment.DEV
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentConfig(BaseModel):
    trust_mode: TrustMode = TrustMode.NORMAL
    environment: Environment = Environment.DEV
    socket_path: str = "/tmp/safeskill.sock"
    http_port: int = 0
    log_dir: str = "/var/log/safeskill"
    config_dir: str = "/etc/safeskill"
    update_url: str = ""
    update_interval_seconds: int = 3600
    auto_update: bool = False
    max_command_length: int = 8192
    evaluation_timeout_seconds: float = 5.0
    audit_log_enabled: bool = True
    hot_reload: bool = True
    signature_verify: bool = True
