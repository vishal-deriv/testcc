"""File system watcher for hot-reloading policies and signatures."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Callable

import structlog
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from .models import AgentConfig

logger = structlog.get_logger(__name__)


class _PolicyFileHandler(FileSystemEventHandler):
    """Debounced handler for policy/signature file changes."""

    WATCHED_EXTENSIONS = {".yaml", ".yml"}
    DEBOUNCE_SECONDS = 2.0

    def __init__(self, callback: Callable[[], None]) -> None:
        super().__init__()
        self._callback = callback
        self._last_trigger = 0.0
        self._lock = threading.Lock()

    def on_modified(self, event: FileSystemEvent) -> None:
        self._maybe_trigger(event)

    def on_created(self, event: FileSystemEvent) -> None:
        self._maybe_trigger(event)

    def _maybe_trigger(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.suffix not in self.WATCHED_EXTENSIONS:
            return

        with self._lock:
            now = time.monotonic()
            if now - self._last_trigger < self.DEBOUNCE_SECONDS:
                return
            self._last_trigger = now

        logger.info("policy_file_changed", path=str(path))
        try:
            self._callback()
        except Exception as exc:
            logger.error("hot_reload_callback_failed", error=str(exc))


class PolicyWatcher:
    """Watches config directory for policy and signature changes."""

    def __init__(self, config: AgentConfig, on_change: Callable[[], None]) -> None:
        self._config_dir = Path(config.config_dir)
        self._on_change = on_change
        self._observer: Observer | None = None

    def start(self) -> None:
        if not self._config_dir.exists():
            logger.warning("config_dir_not_found", path=str(self._config_dir))
            return

        self._observer = Observer()
        handler = _PolicyFileHandler(self._on_change)
        self._observer.schedule(handler, str(self._config_dir), recursive=True)
        self._observer.daemon = True
        self._observer.start()
        logger.info("policy_watcher_started", watching=str(self._config_dir))

    def stop(self) -> None:
        if self._observer and self._observer.is_alive():
            self._observer.stop()
            self._observer.join(timeout=5)
            logger.info("policy_watcher_stopped")
