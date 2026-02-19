"""SafeSkillAgent daemon entry point."""

from __future__ import annotations

import asyncio
import os
import sys

import click

from .cli import DEFAULT_CONFIG_DIR, DEFAULT_LOG_DIR, DEFAULT_SOCKET, _load_agent_config
from .logger import configure_structlog
from .server import run_server


def main() -> None:
    """Entry point for the safeskill-agent binary."""
    config_dir = os.environ.get("SAFESKILL_CONFIG_DIR", DEFAULT_CONFIG_DIR)
    log_dir = os.environ.get("SAFESKILL_LOG_DIR", DEFAULT_LOG_DIR)
    socket_path = os.environ.get("SAFESKILL_SOCKET", DEFAULT_SOCKET)
    trust_mode = os.environ.get("SAFESKILL_TRUST_MODE", "normal")
    environment = os.environ.get("SAFESKILL_ENVIRONMENT", "dev")
    http_port = int(os.environ.get("SAFESKILL_HTTP_PORT", "0"))

    configure_structlog(log_dir)

    config = _load_agent_config(
        config_dir=config_dir,
        log_dir=log_dir,
        socket_path=socket_path,
        trust_mode=trust_mode,
        environment=environment,
        http_port=http_port,
    )

    try:
        asyncio.run(run_server(config))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
