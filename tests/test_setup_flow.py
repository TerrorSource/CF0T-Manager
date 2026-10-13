"""The first-run wizard and the settings screens, with nothing in the environment."""
import pytest
from fastapi.testclient import TestClient

from test_app import TUNNEL, login, make_client  # noqa: F401  (shared mock transport)
from app import auth, main
from app.config import settings

# both spellings: CF0T_* is current, CFZT_* is still honoured
CF_ENV = ("CF_API_TOKEN", "CF_ACCOUNT_ID", "CF0T_PASSWORD", "CFZT_PASSWORD")


@pytest.fixture
def blank_install(monkeypatch):
    """No environment variables and an empty /data config: a fresh container."""
    for key in CF_ENV:
        monkeypatch.delenv(key, raising=False)
    saved = dict(settings.store._data)
    settings.store.clear()
    main.reset_client()
    yield TestClient(main.app)
    settings.store.clear()
    settings.store.update(**saved)
    main.reset_client()


def test_everything_redirects_to_the_wizard(blank_install):
    assert settings.needs_setup is True
    for path in ("/", "/new", "/settings", "/backup"):
        r = blank_install.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/welcome", path
    assert "Welcome to CF0T-Manager" in blank_install.get("/welcome").text


def test_wizard_rejects_bad_credentials(blank_install):
    r = blank_install.post("/welcome", data={
        "password": "longenough1", "password_confirm": "longenough1",
        "api_token": "not-a-real-token", "account_id": "acct123",
    })
    assert r.status_code == 200
    assert "Cloudflare rejected these credentials" in r.text
    assert settings.needs_setup is True, "nothing may be stored when the token is wrong"


def test_wizard_rejects_weak_or_mismatched_password(blank_install):
    r = blank_install.post("/welcome", data={
        "password": "short", "password_confirm": "short",
        "api_token": "fake-token", "account_id": "acct123"})
    assert "at least 8 characters" in r.text
    r = blank_install.post("/welcome", data={
        "password": "longenough1", "password_confirm": "longenough2",
        "api_token": "fake-token", "account_id": "acct123"})
    assert "do not match" in r.text
    assert settings.needs_setup is True


def test_wizard_completes_and_logs_you_in(blank_install):
    r = blank_install.post("/welcome", data={
        "password": "longenough1", "password_confirm": "longenough1",
        "api_token": "fake-token", "account_id": "acct123",
    }, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"

    assert settings.needs_setup is False
    assert settings.api_token == "fake-token"
    assert settings.account_id == "acct123"
    assert settings.tunnel_id == TUNNEL, "the only tunnel is selected automatically"
    assert settings.store.get("password_hash"), "the password is stored hashed"
    assert "longenough1" not in str(settings.store._data), "never stored in plain text"

    # The wizard hands out a session, so the dashboard is reachable straight away.
    assert "ha.makooy.nl" in blank_install.get("/").text
    # And the wizard is closed afterwards.
    r = blank_install.get("/welcome", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"


def test_password_change_signs_out_other_sessions(blank_install):
    blank_install.post("/welcome", data={
        "password": "longenough1", "password_confirm": "longenough1",
        "api_token": "fake-token", "account_id": "acct123"}, follow_redirects=False)

    other = TestClient(main.app)
    other.post("/login", data={"password": "longenough1"}, follow_redirects=False)
    assert other.get("/", follow_redirects=False).status_code == 200

    r = blank_install.post("/settings/password", data={
        "current_password": "longenough1",
        "password": "brandnewpass2", "password_confirm": "brandnewpass2",
    }, follow_redirects=False)
    assert r.status_code == 303 and "err=" not in r.headers["location"], r.headers["location"]

    assert auth.check_password("brandnewpass2")
    assert not auth.check_password("longenough1")
    assert other.get("/", follow_redirects=False).headers["location"] == "/login"
    assert blank_install.get("/", follow_redirects=False).status_code == 200, "own session stays"


def test_password_change_needs_the_current_one(blank_install):
    blank_install.post("/welcome", data={
        "password": "longenough1", "password_confirm": "longenough1",
        "api_token": "fake-token", "account_id": "acct123"}, follow_redirects=False)
    r = blank_install.post("/settings/password", data={
        "current_password": "wrong", "password": "brandnewpass2",
        "password_confirm": "brandnewpass2"}, follow_redirects=False)
    assert "err=" in r.headers["location"]
    assert auth.check_password("longenough1"), "password unchanged"


def test_settings_can_replace_the_token(blank_install):
    blank_install.post("/welcome", data={
        "password": "longenough1", "password_confirm": "longenough1",
        "api_token": "fake-token", "account_id": "acct123"}, follow_redirects=False)

    r = blank_install.post("/settings/cloudflare", data={
        "api_token": "rubbish", "account_id": "acct123"}, follow_redirects=False)
    assert "err=" in r.headers["location"]
    assert settings.api_token == "fake-token", "a rejected token is not stored"

    r = blank_install.post("/settings/cloudflare", data={
        "api_token": "replacement-token", "account_id": "acct123"}, follow_redirects=False)
    assert "err=" not in r.headers["location"], r.headers["location"]
    assert settings.api_token == "replacement-token"


def test_preferences_round_trip(blank_install):
    blank_install.post("/welcome", data={
        "password": "longenough1", "password_confirm": "longenough1",
        "api_token": "fake-token", "account_id": "acct123"}, follow_redirects=False)
    blank_install.post("/settings/preferences", data={
        "session_hours": "48", "secure_cookie": "1", "default_origin_host": "10.0.0.5"},
        follow_redirects=False)
    assert settings.session_hours == 48
    assert settings.secure_cookie is True
    assert settings.default_origin_host == "10.0.0.5"
    assert "10.0.0.5" in blank_install.get("/new").text, "used as the form default"


def test_environment_still_wins(blank_install, monkeypatch):
    monkeypatch.setenv("CF_API_TOKEN", "fake-token")
    monkeypatch.setenv("CF_ACCOUNT_ID", "acct123")
    assert settings.source("api_token") == "env"
    settings.save(api_token="ignored-by-env")
    assert settings.api_token == "fake-token", "the environment keeps precedence"
