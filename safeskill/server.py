"""Unix socket and HTTP IPC server for SafeSkillAgent."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import signal
import stat
import sys
from pathlib import Path
from typing import Any

import structlog
from aiohttp import web

from .evaluator import CommandEvaluator
from .logger import AuditLogger
from .models import (
    AgentConfig,
    Environment,
    EvaluationRequest,
    TrustMode,
    Verdict,
)
from .policy import PolicyManager
from .signatures import SignatureManager
from .trust import TrustEnforcer
from .watcher import PolicyWatcher

logger = structlog.get_logger(__name__)


class SafeSkillServer:
    """IPC server that listens on a Unix domain socket (and optionally HTTP).

    Clients send JSON evaluation requests and receive JSON verdicts.
    """

    def __init__(self, config: AgentConfig) -> None:
        self._config = config
        self._policy_manager = PolicyManager(config)
        self._signature_manager = SignatureManager(config)
        self._trust_enforcer = TrustEnforcer(config.trust_mode, config.environment)
        self._evaluator = CommandEvaluator(
            config, self._policy_manager, self._signature_manager, self._trust_enforcer
        )
        self._audit = AuditLogger(config)
        self._watcher: PolicyWatcher | None = None
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None
        self._running = False

    async def start(self) -> None:
        """Initialize and start the server."""
        self._policy_manager.load_all()
        self._signature_manager.load()
        self._audit.initialize()
        self._audit.log_event("agent_started", {
            "trust_mode": self._config.trust_mode.value,
            "environment": self._config.environment.value,
            "socket_path": self._config.socket_path,
            "pid": os.getpid(),
        })

        if self._config.hot_reload:
            self._watcher = PolicyWatcher(
                self._config,
                on_change=self._on_policy_change,
            )
            self._watcher.start()

        self._app = web.Application(middlewares=[self._auth_middleware])
        self._app.router.add_post("/evaluate", self._handle_evaluate)
        self._app.router.add_get("/health", self._handle_health)
        self._app.router.add_get("/status", self._handle_status)
        self._app.router.add_post("/policy/reload", self._handle_reload)
        self._app.router.add_post("/policy/inject", self._handle_inject_rules)
        self._app.router.add_post("/trust-mode", self._handle_set_trust_mode)
        self._app.router.add_post("/environment", self._handle_set_environment)
        self._app.router.add_get("/audit/verify", self._handle_verify_audit)

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()

        # Create /var/run/safeskill (root-owned, 0755) — only daemon can create socket there
        socket_dir = Path(self._config.socket_path).parent
        socket_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(socket_dir, 0o755)
        except OSError:
            pass

        # Generate client token for /evaluate; trap reads and sends it
        self._client_token = secrets.token_urlsafe(32)
        token_path = Path(self._config.client_token_path)
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(self._client_token, encoding="utf-8")
        try:
            os.chmod(self._config.client_token_path, 0o644)
        except OSError:
            pass

        # Load admin token for admin endpoints (root-only)
        self._admin_token: str | None = None
        admin_path = Path(self._config.admin_token_path)
        if admin_path.exists():
            try:
                self._admin_token = admin_path.read_text(encoding="utf-8").strip()
            except OSError:
                pass

        socket_path = self._config.socket_path
        self._cleanup_socket(socket_path)

        unix_site = web.UnixSite(self._runner, socket_path)
        await unix_site.start()

        try:
            # Socket: world-readable/writable so non-root OpenClaw can connect
            os.chmod(socket_path, 0o666)
        except OSError:
            pass

        self._running = True
        logger.info(
            "server_started",
            socket=socket_path,
            trust_mode=self._config.trust_mode.value,
            environment=self._config.environment.value,
            rules_loaded=len(self._policy_manager.active_rules),
            signatures_loaded=self._signature_manager.signature_count,
        )

        if self._config.http_port > 0:
            tcp_site = web.TCPSite(self._runner, "127.0.0.1", self._config.http_port)
            await tcp_site.start()
            logger.info("http_server_started", port=self._config.http_port)

    @web.middleware
    async def _auth_middleware(
        self, request: web.Request, handler: Any
    ) -> web.Response:
        """Validate tokens for /evaluate and admin endpoints."""
        path = request.path
        if path == "/evaluate":
            token = request.headers.get("X-SafeSkill-Token", "")
            if token != self._client_token:
                return web.json_response(
                    {"error": "Missing or invalid X-SafeSkill-Token"}, status=401
                )
        elif path in ("/policy/reload", "/policy/inject", "/trust-mode", "/environment"):
            if self._admin_token:
                admin = request.headers.get("X-SafeSkill-Admin-Token", "")
                if admin != self._admin_token:
                    return web.json_response(
                        {"error": "Missing or invalid X-SafeSkill-Admin-Token"},
                        status=401,
                    )
        return await handler(request)

    async def stop(self) -> None:
        """Gracefully stop the server."""
        self._running = False
        if self._watcher:
            self._watcher.stop()
        if self._runner:
            await self._runner.cleanup()
        self._cleanup_socket(self._config.socket_path)
        self._audit.log_event("agent_stopped")
        logger.info("server_stopped")

    async def _handle_evaluate(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return web.json_response(
                {"error": "Invalid JSON"}, status=400
            )

        try:
            eval_request = EvaluationRequest(**body)
        except Exception:
            return web.json_response(
                {"error": "Invalid request format"}, status=400
            )

        result = self._evaluator.evaluate(eval_request)
        self._audit.log_evaluation(result, source=eval_request.source, user=eval_request.user)

        return web.json_response({
            "verdict": result.verdict.value,
            "blocked": result.verdict == Verdict.BLOCKED,
            "severity": result.severity.value if result.severity else None,
            "message": result.message,
            "matched_rules": result.matched_rules,
            "matched_signatures": result.matched_signatures,
            "evaluation_time_ms": result.evaluation_time_ms,
            "trust_mode": result.trust_mode.value,
            "environment": result.environment.value,
        })

    async def _handle_health(self, _request: web.Request) -> web.Response:
        return web.json_response({
            "status": "healthy",
            "running": self._running,
            "pid": os.getpid(),
        })

    async def _handle_status(self, _request: web.Request) -> web.Response:
        return web.json_response({
            "agent": "SafeSkillAgent",
            "version": "1.0.0",
            "running": self._running,
            "trust_mode": self._config.trust_mode.value,
            "environment": self._config.environment.value,
            "active_rules": len(self._policy_manager.active_rules),
            "signatures_loaded": self._signature_manager.signature_count,
            "hot_reload": self._config.hot_reload,
            "pid": os.getpid(),
        })

    async def _handle_reload(self, _request: web.Request) -> web.Response:
        self._policy_manager.load_all()
        self._signature_manager.load()
        self._audit.log_event("manual_reload")
        return web.json_response({
            "status": "reloaded",
            "active_rules": len(self._policy_manager.active_rules),
            "signatures_loaded": self._signature_manager.signature_count,
        })

    async def _handle_inject_rules(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        rules = body.get("rules", [])
        if not isinstance(rules, list):
            return web.json_response({"error": "rules must be a list"}, status=400)

        count = self._policy_manager.inject_runtime_rules(rules)
        self._audit.log_event("rules_injected", {"count": count})
        return web.json_response({"status": "injected", "count": count})

    async def _handle_set_trust_mode(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        mode_str = body.get("trust_mode", "")
        try:
            mode = TrustMode(mode_str)
        except ValueError:
            return web.json_response(
                {"error": f"Invalid trust mode: {mode_str}. Use: normal, strict, zero-trust"},
                status=400,
            )

        self._config.trust_mode = mode
        self._trust_enforcer.trust_mode = mode
        self._audit.log_event("trust_mode_changed", {"new_mode": mode.value})
        logger.info("trust_mode_changed", new_mode=mode.value)

        return web.json_response({"status": "updated", "trust_mode": mode.value})

    async def _handle_set_environment(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        env_str = body.get("environment", "")
        try:
            env = Environment(env_str)
        except ValueError:
            return web.json_response(
                {"error": f"Invalid environment: {env_str}. Use: dev, staging, production"},
                status=400,
            )

        self._config.environment = env
        self._policy_manager.load_all()
        self._audit.log_event("environment_changed", {"new_environment": env.value})

        return web.json_response({"status": "updated", "environment": env.value})

    async def _handle_verify_audit(self, _request: web.Request) -> web.Response:
        valid, total, broken_at = self._audit.verify_chain()
        return web.json_response({
            "valid": valid,
            "total_entries": total,
            "broken_at_line": broken_at,
        })

    def _on_policy_change(self) -> None:
        """Callback when policy files change on disk."""
        reloaded_policy = self._policy_manager.reload_if_changed()
        reloaded_sigs = self._signature_manager.reload_if_changed()
        if reloaded_policy or reloaded_sigs:
            self._audit.log_event("hot_reload", {
                "policy_reloaded": reloaded_policy,
                "signatures_reloaded": reloaded_sigs,
            })

    @staticmethod
    def _cleanup_socket(path: str) -> None:
        try:
            if os.path.exists(path):
                os.unlink(path)
        except OSError:
            pass


async def run_server(config: AgentConfig) -> None:
    """Run the SafeSkillAgent server with graceful shutdown."""
    server = SafeSkillServer(config)
    loop = asyncio.get_event_loop()
    shutdown_event = asyncio.Event()

    def _signal_handler(signum: int, _frame: Any) -> None:
        logger.info("shutdown_signal_received", signal=signum)
        shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _signal_handler)

    await server.start()

    try:
        await shutdown_event.wait()
    finally:
        await server.stop()
