"""Session login for the web UI: one password, stored as a scrypt hash."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time

from fastapi import Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .config import settings

COOKIE_NAME = "cfzt_session"
_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1, "dklen": 32}
_serializer = URLSafeTimedSerializer(settings.secret_key, salt="cfzt-login")

MIN_PASSWORD_LENGTH = 8

# Login throttling. Per address, plus a global counter: the per-address one can
# be sidestepped by anyone able to set X-Forwarded-For, the global one cannot.
MAX_ATTEMPTS = 10
MAX_ATTEMPTS_GLOBAL = 50
LOCKOUT_SECONDS = 900
MAX_TRACKED_ADDRESSES = 1000

_failures: dict[str, tuple[int, float]] = {}
_global_failures: list[float] = []


def _humanise(seconds: float) -> str:
    minutes = int(seconds // 60)
    if minutes >= 1:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    return f"{max(1, int(seconds))} seconds"


def _prune(now: float) -> None:
    """Drop everything older than the lockout window, so the table cannot grow
    without bound on forged addresses."""
    for who, (_, last) in list(_failures.items()):
        if now - last >= LOCKOUT_SECONDS:
            _failures.pop(who, None)
    while _global_failures and now - _global_failures[0] >= LOCKOUT_SECONDS:
        _global_failures.pop(0)
    if len(_failures) > MAX_TRACKED_ADDRESSES:
        for who in sorted(_failures, key=lambda k: _failures[k][1])[:len(_failures) // 2]:
            _failures.pop(who, None)


def lockout_remaining(who: str) -> str:
    """Empty when a login may be tried, otherwise how long it still has to wait."""
    now = time.monotonic()
    _prune(now)

    if len(_global_failures) >= MAX_ATTEMPTS_GLOBAL:
        return _humanise(LOCKOUT_SECONDS - (now - _global_failures[0]))

    count, last = _failures.get(who, (0, 0.0))
    if count >= MAX_ATTEMPTS:
        return _humanise(LOCKOUT_SECONDS - (now - last))
    return ""


def register_failure(who: str) -> int:
    """Count a wrong password. Returns how many attempts are left, 0 once locked."""
    now = time.monotonic()
    _prune(now)
    count, _ = _failures.get(who, (0, 0.0))
    _failures[who] = (count + 1, now)
    _global_failures.append(now)
    return max(0, MAX_ATTEMPTS - (count + 1))


def register_success(who: str) -> None:
    _failures.pop(who, None)


def reset_throttle() -> None:
    _failures.clear()
    _global_failures.clear()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_hash(password: str, stored: str) -> bool:
    try:
        scheme, salt_hex, digest_hex = stored.split("$")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    try:
        digest = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex), **_SCRYPT)
    except ValueError:
        return False
    return hmac.compare_digest(digest.hex(), digest_hex)


def check_password(candidate: str) -> bool:
    """A password in the environment wins; otherwise check the stored hash."""
    if not settings.auth_enabled:
        return True
    if settings.env_password:
        return hmac.compare_digest(candidate or "", settings.env_password)
    stored = settings.password_hash
    return bool(stored) and verify_hash(candidate or "", stored)


def password_problem(password: str, confirm: str) -> str:
    if len(password or "") < MIN_PASSWORD_LENGTH:
        return f"The password must be at least {MIN_PASSWORD_LENGTH} characters."
    if password != confirm:
        return "The two passwords do not match."
    return ""


def make_token() -> str:
    return _serializer.dumps({"e": settings.session_epoch})


def is_logged_in(request: Request) -> bool:
    if not settings.auth_enabled:
        return True
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return False
    try:
        payload = _serializer.loads(token, max_age=settings.session_hours * 3600)
    except (BadSignature, SignatureExpired):
        return False
    # A password change bumps the epoch, which signs out every other session.
    return int(payload.get("e", 0)) == settings.session_epoch


def set_session_cookie(response, token: str) -> None:
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=settings.session_hours * 3600,
        httponly=True,
        samesite="lax",
        secure=settings.secure_cookie,
        path="/",
    )


def clear_session_cookie(response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/")
