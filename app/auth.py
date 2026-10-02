"""Session login for the web UI: one password, stored as a scrypt hash."""
from __future__ import annotations

import hashlib
import hmac
import secrets

from fastapi import Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .config import settings

COOKIE_NAME = "cfzt_session"
_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1, "dklen": 32}
_serializer = URLSafeTimedSerializer(settings.secret_key, salt="cfzt-login")

MIN_PASSWORD_LENGTH = 8


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
