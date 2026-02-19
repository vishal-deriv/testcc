"""Config directory initialization helper."""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

BUNDLED_CONFIG = Path(__file__).parent.parent / "config"


def initialize_config(config_dir: str) -> None:
    """Copy bundled default configs to the target config directory."""
    target = Path(config_dir)
    target.mkdir(parents=True, exist_ok=True)

    environments_dir = target / "environments"
    environments_dir.mkdir(parents=True, exist_ok=True)

    files_to_copy = [
        "base-policy.yaml",
        "runtime-policy.yaml",
        "signatures.yaml",
    ]
    env_files = ["dev.yaml", "staging.yaml", "production.yaml"]

    for filename in files_to_copy:
        src = BUNDLED_CONFIG / filename
        dst = target / filename
        if not dst.exists() and src.exists():
            shutil.copy2(str(src), str(dst))
            logger.info("config_file_created", file=str(dst))
        elif dst.exists():
            logger.info("config_file_exists", file=str(dst))

    for filename in env_files:
        src = BUNDLED_CONFIG / "environments" / filename
        dst = environments_dir / filename
        if not dst.exists() and src.exists():
            shutil.copy2(str(src), str(dst))
            logger.info("config_file_created", file=str(dst))

    try:
        os.chmod(str(target), stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
    except OSError:
        pass
