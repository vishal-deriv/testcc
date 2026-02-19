"""Auto-update mechanism for signatures and policies (CrowdStrike-style)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog
import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

from .models import AgentConfig

logger = structlog.get_logger(__name__)


class UpdateVerificationError(Exception):
    pass


class SignatureVerifier:
    """Verifies update package signatures using RSA-PSS."""

    def __init__(self, public_key_path: str | None = None) -> None:
        self._public_key: rsa.RSAPublicKey | None = None
        if public_key_path:
            self._load_public_key(public_key_path)

    def _load_public_key(self, path: str) -> None:
        key_path = Path(path)
        if not key_path.exists():
            logger.warning("update_public_key_not_found", path=path)
            return
        with open(key_path, "rb") as f:
            self._public_key = serialization.load_pem_public_key(f.read())  # type: ignore[assignment]

    def verify(self, data: bytes, signature: bytes) -> bool:
        if self._public_key is None:
            raise UpdateVerificationError("No public key loaded for signature verification")
        try:
            self._public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception as exc:
            logger.error("signature_verification_failed", error=str(exc))
            return False


class Updater:
    """Pulls and applies policy/signature updates from a remote source.

    Update flow:
    1. Fetch update manifest from update_url
    2. Verify manifest signature (RSA-PSS)
    3. Download updated files
    4. Verify each file's SHA-256 hash
    5. Atomic swap into config directory
    6. Trigger hot-reload
    """

    def __init__(
        self,
        config: AgentConfig,
        on_update: Any | None = None,
    ) -> None:
        self._config = config
        self._on_update = on_update
        self._verifier: SignatureVerifier | None = None
        self._running = False

        public_key_path = str(Path(config.config_dir) / "update-public-key.pem")
        if Path(public_key_path).exists():
            self._verifier = SignatureVerifier(public_key_path)

    async def start_polling(self) -> None:
        """Start the background update polling loop."""
        if not self._config.auto_update or not self._config.update_url:
            logger.info("auto_update_disabled")
            return

        self._running = True
        logger.info(
            "update_polling_started",
            interval=self._config.update_interval_seconds,
            url=self._config.update_url,
        )

        while self._running:
            try:
                await self._check_for_updates()
            except Exception as exc:
                logger.error("update_check_failed", error=str(exc))
            await asyncio.sleep(self._config.update_interval_seconds)

    def stop(self) -> None:
        self._running = False

    async def _check_for_updates(self) -> None:
        """Check remote for available updates."""
        import aiohttp

        async with aiohttp.ClientSession() as session:
            manifest_url = self._config.update_url.rstrip("/") + "/manifest.json"
            async with session.get(manifest_url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status != 200:
                    logger.warning("update_manifest_fetch_failed", status=resp.status)
                    return
                manifest_bytes = await resp.read()

            if self._config.signature_verify and self._verifier:
                sig_url = self._config.update_url.rstrip("/") + "/manifest.sig"
                async with session.get(sig_url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status != 200:
                        logger.warning("update_signature_fetch_failed", status=resp.status)
                        return
                    sig_bytes = await resp.read()

                if not self._verifier.verify(manifest_bytes, sig_bytes):
                    raise UpdateVerificationError("Manifest signature verification failed")

            manifest = json.loads(manifest_bytes)
            await self._apply_manifest(session, manifest)

    async def _apply_manifest(
        self, session: Any, manifest: dict[str, Any]
    ) -> None:
        """Download and apply files from the update manifest."""
        import aiohttp

        files = manifest.get("files", [])
        if not files:
            return

        config_dir = Path(self._config.config_dir)
        staging_dir = Path(tempfile.mkdtemp(prefix="safeskill-update-"))

        try:
            for file_info in files:
                filename = file_info["name"]
                expected_hash = file_info["sha256"]
                file_url = file_info["url"]

                safe_name = Path(filename).name
                if safe_name != filename or ".." in filename:
                    logger.error("suspicious_update_filename", filename=filename)
                    continue

                async with session.get(
                    file_url, timeout=aiohttp.ClientTimeout(total=60)
                ) as resp:
                    if resp.status != 200:
                        logger.error(
                            "update_file_download_failed",
                            file=filename,
                            status=resp.status,
                        )
                        continue
                    data = await resp.read()

                actual_hash = hashlib.sha256(data).hexdigest()
                if actual_hash != expected_hash:
                    logger.error(
                        "update_file_hash_mismatch",
                        file=filename,
                        expected=expected_hash,
                        actual=actual_hash,
                    )
                    continue

                staging_path = staging_dir / safe_name
                with open(staging_path, "wb") as f:
                    f.write(data)

            for staged_file in staging_dir.iterdir():
                target = config_dir / staged_file.name
                backup = config_dir / f".{staged_file.name}.bak"

                if target.exists():
                    shutil.copy2(str(target), str(backup))

                shutil.move(str(staged_file), str(target))
                logger.info("update_file_applied", file=staged_file.name)

            if self._on_update:
                self._on_update()

            logger.info("update_applied", files_count=len(files))

        finally:
            shutil.rmtree(str(staging_dir), ignore_errors=True)


def generate_update_keypair(output_dir: str) -> tuple[str, str]:
    """Generate RSA keypair for signing updates. Run once during setup."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    public_key = private_key.public_key()

    priv_path = str(Path(output_dir) / "update-private-key.pem")
    pub_path = str(Path(output_dir) / "update-public-key.pem")

    with open(priv_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(pub_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    os.chmod(priv_path, 0o600)
    os.chmod(pub_path, 0o644)

    return priv_path, pub_path
