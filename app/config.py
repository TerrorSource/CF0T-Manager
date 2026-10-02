"""Configuration, resolved from environment variables first and the stored
config in /data second, so the whole tool can be set up from the web UI."""
from __future__ import annotations

import json
import os
import secrets
import threading
from pathlib import Path
from typing import Any

# Settings that can come from the environment. Anything set here wins over the
# stored config and is shown as read-only in the UI.
ENV_KEYS = {
    "api_token": "CF_API_TOKEN",
    "account_id": "CF_ACCOUNT_ID",
    "tunnel_id": "CF_TUNNEL_ID",
    "password": "CFZT_PASSWORD",
    "session_hours": "CFZT_SESSION_HOURS",
    "secure_cookie": "CFZT_SECURE_COOKIE",
    "default_origin_host": "CFZT_DEFAULT_ORIGIN_HOST",
}

DEFAULTS = {
    "session_hours": 12,
    "secure_cookie": False,
    "default_origin_host": "192.168.1.9",
}


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: Any, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


class Store:
    """JSON file in /data holding everything configured through the web UI."""

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

    def update(self, **values) -> None:
        with self._lock:
            self._data.update(values)
            self._write()

    def clear(self) -> None:
        with self._lock:
            self._data = {}
            self._write()

    def _write(self) -> None:
        tmp = self._path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
            try:
                tmp.chmod(0o600)  # holds the API token
            except OSError:
                pass
            tmp.replace(self._path)
        except OSError:
            pass


class Settings:
    def __init__(self) -> None:
        self.data_dir = Path(os.environ.get("CFZT_DATA_DIR", "./data").strip() or "./data")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.store = Store(self.data_dir / "config.json")
        self.secret_key = os.environ.get("CFZT_SECRET_KEY", "").strip() or self._persisted_secret()
        self._migrate_state_json()

    # ---------- resolution ----------
    def env(self, field: str) -> str:
        return (os.environ.get(ENV_KEYS[field]) or "").strip()

    def source(self, field: str) -> str:
        """Where a setting comes from: 'env', 'config' or 'unset'."""
        if self.env(field):
            return "env"
        if self.store.get(field) not in (None, ""):
            return "config"
        return "unset"

    def _resolve(self, field: str, default=None):
        value = self.env(field)
        if value:
            return value
        stored = self.store.get(field)
        return stored if stored not in (None, "") else default

    # ---------- Cloudflare ----------
    @property
    def api_token(self) -> str:
        return self._resolve("api_token", "") or ""

    @property
    def account_id(self) -> str:
        return self._resolve("account_id", "") or ""

    @property
    def tunnel_id(self) -> str:
        return self._resolve("tunnel_id", "") or ""

    @property
    def tunnel_pinned(self) -> bool:
        return bool(self.env("tunnel_id"))

    # ---------- this tool ----------
    @property
    def env_password(self) -> str:
        return self.env("password")

    @property
    def password_hash(self) -> str:
        return self.store.get("password_hash") or ""

    @property
    def login_disabled(self) -> bool:
        return _as_bool(os.environ.get("CFZT_DISABLE_LOGIN"), False)

    @property
    def auth_enabled(self) -> bool:
        if self.login_disabled:
            return False
        return bool(self.env_password or self.password_hash)

    @property
    def session_hours(self) -> int:
        return _as_int(self._resolve("session_hours"), DEFAULTS["session_hours"])

    @property
    def secure_cookie(self) -> bool:
        return _as_bool(self._resolve("secure_cookie"), DEFAULTS["secure_cookie"])

    @property
    def default_origin_host(self) -> str:
        return self._resolve("default_origin_host", DEFAULTS["default_origin_host"])

    @property
    def session_epoch(self) -> int:
        """Bumped on a password change so existing sessions stop working."""
        return _as_int(self.store.get("session_epoch"), 0)

    # ---------- state ----------
    @property
    def configured(self) -> bool:
        return bool(self.api_token and self.account_id)

    @property
    def needs_setup(self) -> bool:
        """True until the first-run wizard has been completed."""
        if not self.configured:
            return True
        return not (self.auth_enabled or self.login_disabled)

    # ---------- writing ----------
    def save(self, **values) -> None:
        """Store settings that are not pinned through the environment."""
        writable = {k: v for k, v in values.items()
                    if k not in ENV_KEYS or not self.env(k)}
        if writable:
            self.store.update(**writable)

    def set_password_hash(self, password_hash: str) -> None:
        # A counter, not a timestamp: two changes within the same second must
        # still invalidate the sessions issued in between.
        self.store.update(password_hash=password_hash, session_epoch=self.session_epoch + 1)

    # ---------- helpers ----------
    def _persisted_secret(self) -> str:
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

    def _migrate_state_json(self) -> None:
        """Older versions kept the chosen tunnel in state.json."""
        legacy = self.data_dir / "state.json"
        if not legacy.exists() or self.store.get("tunnel_id"):
            return
        try:
            data = json.loads(legacy.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if data.get("tunnel_id"):
            self.store.update(tunnel_id=data["tunnel_id"])


settings = Settings()


def active_tunnel_id() -> str:
    return settings.tunnel_id


def set_active_tunnel_id(tunnel_id: str) -> None:
    settings.save(tunnel_id=tunnel_id)
