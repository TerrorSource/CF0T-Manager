"""An append-only record of what this tool changed, kept in /data."""
from __future__ import annotations

import json
import time
from typing import Any

from .config import settings

FILE = "changes.log"
MAX_LINES = 2000


def _path():
    return settings.data_dir / FILE


def record(action: str, target: str, detail: str = "", who: str = "") -> None:
    """Never raises: a change that happened must not fail over its own logging."""
    entry = {
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "action": action,
        "target": target,
        "detail": detail,
        "from": who,
    }
    try:
        with _path().open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        return
    _trim()


def _trim() -> None:
    try:
        path = _path()
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) > MAX_LINES:
            path.write_text("\n".join(lines[-MAX_LINES:]) + "\n", encoding="utf-8")
    except OSError:
        pass


def entries(limit: int = 200) -> list[dict[str, Any]]:
    """Newest first."""
    try:
        lines = _path().read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in reversed(lines[-limit:]):
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        stamp = entry.get("at", "")
        try:
            parsed = time.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ")
            entry["when"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(time.mktime(parsed)
                                                                          - time.timezone))
        except (ValueError, OverflowError):
            entry["when"] = stamp
        out.append(entry)
    return out
