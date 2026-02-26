"""CLI interface for SafeSkillAgent."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .logger import configure_structlog
from .models import AgentConfig, Environment, TrustMode
from .server import run_server
from .updater import generate_update_keypair

console = Console()

DEFAULT_CONFIG_DIR = "/etc/safeskill"
DEFAULT_LOG_DIR = "/var/log/safeskill"
DEFAULT_SOCKET = "/var/run/safeskill/safeskill.sock"


def _load_agent_config(
    config_dir: str,
    log_dir: str,
    socket_path: str,
    trust_mode: str,
    environment: str,
    http_port: int,
) -> AgentConfig:
    agent_config_file = Path(config_dir) / "agent.yaml"
    config_data: dict = {}

    if agent_config_file.exists():
        import yaml
        with open(agent_config_file, "r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
            if isinstance(loaded, dict):
                config_data = loaded

    config_data.setdefault("config_dir", config_dir)
    config_data.setdefault("log_dir", log_dir)
    config_data.setdefault("socket_path", socket_path)
    config_data.setdefault("http_port", http_port)

    if trust_mode:
        config_data["trust_mode"] = trust_mode
    if environment:
        config_data["environment"] = environment

    env_trust = os.environ.get("SAFESKILL_TRUST_MODE")
    if env_trust:
        config_data["trust_mode"] = env_trust

    env_env = os.environ.get("SAFESKILL_ENVIRONMENT")
    if env_env:
        config_data["environment"] = env_env

    return AgentConfig(**config_data)


def _read_token(path: str) -> str | None:
    """Read token from file if readable."""
    try:
        p = Path(path)
        if p.exists() and p.is_file():
            return p.read_text(encoding="utf-8").strip()
    except OSError:
        pass
    return None


def _send_to_socket(
    socket_path: str,
    method: str,
    path: str,
    body: dict | None = None,
    *,
    client_token: str | None = None,
    admin_token: str | None = None,
) -> dict:
    """Send an HTTP-like request over Unix socket and return the JSON response."""
    import aiohttp

    headers: dict[str, str] = {}
    if path == "/evaluate" and client_token:
        headers["X-SafeSkill-Token"] = client_token
    elif path in ("/policy/reload", "/policy/inject", "/trust-mode", "/environment") and admin_token:
        headers["X-SafeSkill-Admin-Token"] = admin_token

    async def _do() -> dict:
        conn = aiohttp.UnixConnector(path=socket_path)
        async with aiohttp.ClientSession(connector=conn) as session:
            url = f"http://localhost{path}"
            if method == "GET":
                async with session.get(url, headers=headers or None) as resp:
                    return await resp.json()  # type: ignore[no-any-return]
            else:
                async with session.post(url, json=body or {}, headers=headers or None) as resp:
                    return await resp.json()  # type: ignore[no-any-return]

    return asyncio.run(_do())


@click.group()
@click.version_option(__version__, prog_name="SafeSkillAgent")
def main() -> None:
    """SafeSkillAgent - Command security enforcement for OpenClaw."""
    pass


@main.command()
@click.option("--config-dir", default=DEFAULT_CONFIG_DIR, help="Config directory")
@click.option("--log-dir", default=DEFAULT_LOG_DIR, help="Log directory")
@click.option("--socket", "socket_path", default=DEFAULT_SOCKET, help="Unix socket path")
@click.option(
    "--trust-mode",
    type=click.Choice(["normal", "strict", "zero-trust"]),
    default="normal",
    help="Trust mode",
)
@click.option(
    "--environment",
    type=click.Choice(["dev", "staging", "production"]),
    default="dev",
    help="Environment",
)
@click.option("--http-port", default=0, type=int, help="Optional HTTP port (0 = disabled)")
def start(
    config_dir: str,
    log_dir: str,
    socket_path: str,
    trust_mode: str,
    environment: str,
    http_port: int,
) -> None:
    """Start the SafeSkillAgent daemon."""
    configure_structlog(log_dir)
    config = _load_agent_config(config_dir, log_dir, socket_path, trust_mode, environment, http_port)

    console.print(Panel.fit(
        f"[bold green]SafeSkillAgent v{__version__}[/bold green]\n"
        f"Trust Mode: [bold]{config.trust_mode.value}[/bold]\n"
        f"Environment: [bold]{config.environment.value}[/bold]\n"
        f"Socket: {config.socket_path}\n"
        f"Config: {config.config_dir}\n"
        f"Logs: {config.log_dir}",
        title="Starting Agent",
    ))

    try:
        asyncio.run(run_server(config))
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down...[/yellow]")


@main.command()
@click.option("--socket", "socket_path", default=DEFAULT_SOCKET, help="Unix socket path")
@click.argument("command")
def check(socket_path: str, command: str) -> None:
    """Check a command against the security policy."""
    token = _read_token("/var/run/safeskill/client.token")
    if not token:
        console.print("[red]Client token not found. Is the daemon running?[/red]")
        sys.exit(1)
    try:
        result = _send_to_socket(
            socket_path, "POST", "/evaluate", {"command": command}, client_token=token
        )
    except Exception as exc:
        console.print(f"[red]Error connecting to agent: {exc}[/red]")
        console.print("Is the agent running? Start it with: safeskill start")
        sys.exit(1)

    blocked = result.get("blocked", False)
    verdict = result.get("verdict", "unknown")
    severity = result.get("severity")
    message = result.get("message", "")

    if blocked:
        color = "red"
        icon = "BLOCKED"
    elif verdict == "warned":
        color = "yellow"
        icon = "WARNED"
    else:
        color = "green"
        icon = "ALLOWED"

    console.print(f"\n[bold {color}][{icon}][/bold {color}] {command}")
    if severity:
        console.print(f"  Severity: [bold]{severity}[/bold]")
    if message:
        console.print(f"  Message: {message}")
    if result.get("matched_rules"):
        console.print(f"  Rules: {', '.join(result['matched_rules'])}")
    if result.get("matched_signatures"):
        console.print(f"  Signatures: {', '.join(result['matched_signatures'])}")
    console.print(f"  Evaluated in: {result.get('evaluation_time_ms', 0):.2f}ms\n")

    sys.exit(1 if blocked else 0)


@main.command()
@click.option("--socket", "socket_path", default=DEFAULT_SOCKET, help="Unix socket path")
def status(socket_path: str) -> None:
    """Show agent status."""
    try:
        result = _send_to_socket(socket_path, "GET", "/status")
    except Exception as exc:
        console.print(f"[red]Agent not running: {exc}[/red]")
        sys.exit(1)

    table = Table(title="SafeSkillAgent Status")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    for key, value in result.items():
        table.add_row(key, str(value))

    console.print(table)


@main.command()
@click.option("--socket", "socket_path", default=DEFAULT_SOCKET, help="Unix socket path")
def reload(socket_path: str) -> None:
    """Reload policies and signatures (requires admin token)."""
    admin = _read_token("/etc/safeskill/admin.token")
    try:
        result = _send_to_socket(
            socket_path, "POST", "/policy/reload", admin_token=admin
        )
        console.print(f"[green]Reloaded:[/green] {result}")
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        sys.exit(1)


@main.command("set-trust")
@click.option("--socket", "socket_path", default=DEFAULT_SOCKET, help="Unix socket path")
@click.argument("mode", type=click.Choice(["normal", "strict", "zero-trust"]))
def set_trust(socket_path: str, mode: str) -> None:
    """Change trust mode at runtime (requires admin token, typically sudo)."""
    admin = _read_token("/etc/safeskill/admin.token")
    try:
        result = _send_to_socket(
            socket_path, "POST", "/trust-mode", {"trust_mode": mode}, admin_token=admin
        )
        console.print(f"[green]Trust mode set to: {result.get('trust_mode')}[/green]")
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        sys.exit(1)


@main.command("set-env")
@click.option("--socket", "socket_path", default=DEFAULT_SOCKET, help="Unix socket path")
@click.argument("env", type=click.Choice(["dev", "staging", "production"]))
def set_env(socket_path: str, env: str) -> None:
    """Change environment at runtime (requires admin token, typically sudo)."""
    admin = _read_token("/etc/safeskill/admin.token")
    try:
        result = _send_to_socket(
            socket_path, "POST", "/environment", {"environment": env}, admin_token=admin
        )
        console.print(f"[green]Environment set to: {result.get('environment')}[/green]")
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        sys.exit(1)


@main.command("verify-audit")
@click.option("--socket", "socket_path", default=DEFAULT_SOCKET, help="Unix socket path")
def verify_audit(socket_path: str) -> None:
    """Verify audit log chain integrity."""
    try:
        result = _send_to_socket(socket_path, "GET", "/audit/verify")
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        sys.exit(1)

    if result.get("valid"):
        console.print(
            f"[green]Audit chain VALID[/green] ({result.get('total_entries', 0)} entries)"
        )
    else:
        console.print(
            f"[red]Audit chain BROKEN at line {result.get('broken_at_line')}[/red]"
        )
        sys.exit(1)


@main.command("generate-keys")
@click.argument("output_dir", default=".")
def generate_keys(output_dir: str) -> None:
    """Generate RSA keypair for update signature verification."""
    priv, pub = generate_update_keypair(output_dir)
    console.print(f"[green]Private key:[/green] {priv}")
    console.print(f"[green]Public key:[/green] {pub}")
    console.print("[yellow]Keep the private key secure! Deploy the public key to agents.[/yellow]")


@main.command()
@click.option("--config-dir", default=DEFAULT_CONFIG_DIR, help="Config directory")
def init(config_dir: str) -> None:
    """Initialize config directory with default policies."""
    from .setup import initialize_config

    initialize_config(config_dir)
    console.print(f"[green]Config initialized at {config_dir}[/green]")


if __name__ == "__main__":
    main()
