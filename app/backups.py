"""Backups kept inside the /data volume: scheduled, before a delete, or on demand."""
from __future__ import annotations

import json
import re
import secrets
import time
from pathlib import Path
from typing import Any

from .config import settings

FORMAT = "cf0t-manager/1"
# Backups written before the rename are still restorable.
LEGACY_FORMATS = ("cfzerotrustcontrol/1",)


def is_ours(value: str) -> bool:
    return value == FORMAT or value in LEGACY_FORMATS
KINDS = ("auto", "predelete", "manual")
SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,120}\.json$")


def backup_dir() -> Path:
    path = settings.data_dir / "backups"
    path.mkdir(parents=True, exist_ok=True)
    return path


def build_payload(tunnel_id: str, tunnel_name: str, config: dict, apps: list[dict],
                  policies: list[dict], reason: str = "manual") -> dict:
    return {
        "format": FORMAT,
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "reason": reason,
        "account_id": settings.account_id,
        "tunnel": {"id": tunnel_id, "name": tunnel_name},
        "tunnel_config": config,
        "access_apps": apps,
        "policies": policies,
    }


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")[:40]


def write(payload: dict, kind: str = "manual", label: str = "") -> Path:
    kind = kind if kind in KINDS else "manual"
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    suffix = f"-{_slug(label)}" if label else ""
    path = backup_dir() / f"{kind}-{stamp}{suffix}.json"
    # Two backups within the same second must not overwrite each other.
    while path.exists():
        path = backup_dir() / f"{kind}-{stamp}{suffix}-{secrets.token_hex(2)}.json"
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def resolve(name: str) -> Path | None:
    """Only ever a plain file name inside the backup directory."""
    if not name or not SAFE_NAME.match(name):
        return None
    path = (backup_dir() / name).resolve()
    if path.parent != backup_dir().resolve() or not path.is_file():
        return None
    return path


def read(name: str) -> dict | None:
    path = resolve(name)
    if path is None:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def remove(name: str) -> bool:
    path = resolve(name)
    if path is None:
        return False
    try:
        path.unlink()
        return True
    except OSError:
        return False


def listing() -> list[dict[str, Any]]:
    """Newest first, with whatever the file itself says about where it came from."""
    out: list[dict[str, Any]] = []
    for path in backup_dir().glob("*.json"):
        try:
            stat = path.stat()
        except OSError:
            continue
        kind = path.name.split("-", 1)[0]
        entry = {
            "name": path.name,
            "kind": kind if kind in KINDS else "manual",
            "modified": stat.st_mtime,
            "when": time.strftime("%Y-%m-%d %H:%M", time.localtime(stat.st_mtime)),
            "size_kb": max(1, round(stat.st_size / 1024)),
            "routes": None,
            "apps": None,
            "reason": "",
        }
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            ingress = (data.get("tunnel_config") or {}).get("ingress") or []
            entry["routes"] = len([r for r in ingress if r.get("hostname")])
            entry["apps"] = len(data.get("access_apps") or [])
            entry["reason"] = data.get("reason") or ""
        except (OSError, ValueError):
            pass
        out.append(entry)
    out.sort(key=lambda e: e["modified"], reverse=True)
    return out


def newest_time(kind: str) -> float | None:
    times = [e["modified"] for e in listing() if e["kind"] == kind]
    return max(times) if times else None


def prune(kind: str, keep: int) -> int:
    """Keep the newest `keep` backups of one kind, delete the rest."""
    of_kind = [e for e in listing() if e["kind"] == kind]
    removed = 0
    for entry in of_kind[max(0, keep):]:
        if remove(entry["name"]):
            removed += 1
    return removed
