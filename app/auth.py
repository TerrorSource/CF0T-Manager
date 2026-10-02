"""Session login for the web UI (one shared password)."""
from __future__ import annotations

import hmac

from fastapi import Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .config import settings

COOKIE_NAME = "cfzt_session"
_serializer = URLSafeTimedSerializer(settings.secret_key, salt="cfzt-login")


def check_password(candidate: str) -> bool:
    if not settings.auth_enabled:
        return True
    return hmac.compare_digest(candidate or "", settings.password)


def make_token() -> str:
    return _serializer.dumps({"ok": True})


def is_logged_in(request: Request) -> bool:
    if not settings.auth_enabled:
        return True
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return False
    try:
        _serializer.loads(token, max_age=settings.session_hours * 3600)
    except (BadSignature, SignatureExpired):
        return False
    return True


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
