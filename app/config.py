"""Configuratie uit environment variables + een klein stukje persistente state."""
from __future__ import annotations

import json
import os
import secrets
import threading
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name)
    if not raw:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name) or default)
    except ValueError:
        return default


class Settings:
    def __init__(self) -> None:
        self.api_token = _env("CF_API_TOKEN")
        self.account_id = _env("CF_ACCOUNT_ID")
        self.env_tunnel_id = _env("CF_TUNNEL_ID")
        self.password = _env("CFZT_PASSWORD")
        self.session_hours = _env_int("CFZT_SESSION_HOURS", 12)
        self.secure_cookie = _env_bool("CFZT_SECURE_COOKIE", False)
        self.default_origin_host = _env("CFZT_DEFAULT_ORIGIN_HOST", "127.0.0.1")
        self.data_dir = Path(_env("CFZT_DATA_DIR", "./data"))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.secret_key = _env("CFZT_SECRET_KEY") or self._persisted_secret()

    @property
    def auth_enabled(self) -> bool:
        return bool(self.password)

    @property
    def configured(self) -> bool:
        return bool(self.api_token and self.account_id)

    def _persisted_secret(self) -> str:
        """Geen SECRET_KEY opgegeven: er wordt er een gegenereerd en bewaard,
        zodat sessies een herstart overleven."""
        path = self.data_dir / "secret.key"
        try:
            if path.exists():
                value = path.read_text(encoding="utf-8").strip()
                if value:
                    return value
            value = secrets.token_hex(32)
            path.write_text(value, encoding="utf-8")
            try:
                path.chmod(0o600)
            except OSError:
                pass
            return value
        except OSError:
            return secrets.token_hex(32)


class State:
    """Kleine key/value store op schijf (op dit moment: de gekozen tunnel)."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._data: dict = {}
        self._load()

    def _load(self) -> None:
        try:
            if self._path.exists():
                self._data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self._data = {}

    def get(self, key: str, default=None):
        return self._data.get(key, default)

    def set(self, key: str, value) -> None:
        with self._lock:
            self._data[key] = value
            tmp = self._path.with_suffix(".tmp")
            try:
                tmp.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
                tmp.replace(self._path)
            except OSError:
                pass


settings = Settings()
state = State(settings.data_dir / "state.json")


def active_tunnel_id() -> str:
    return settings.env_tunnel_id or state.get("tunnel_id") or ""


def set_active_tunnel_id(tunnel_id: str) -> None:
    state.set("tunnel_id", tunnel_id)
