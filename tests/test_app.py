"""Smoke/unit tests against a fake Cloudflare API (httpx MockTransport)."""
import json, os, sys

os.environ.setdefault("TESTDATA", "/tmp/cfzt-test-data")
os.environ.update({
    "CF_API_TOKEN": "fake-token", "CF_ACCOUNT_ID": "acct123",
    "CFZT_PASSWORD": "secret", "CFZT_SECRET_KEY": "x" * 32,
    "CFZT_DATA_DIR": os.environ["TESTDATA"],
})
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
import pytest
from fastapi.testclient import TestClient
from app import auth, cf, services, main
from app.config import settings

TUNNEL = "tunnel-abc-123"
VALID_TOKENS = {"fake-token", "replacement-token"}
STATE = {}


def reset_state():
    STATE.clear()
    STATE.update({
        "config": {"ingress": [
            {"hostname": "ha.makooy.nl", "service": "https://192.168.1.12:8123",
             "originRequest": {"noTLSVerify": True}},
            {"hostname": "sonarr.makooy.nl", "service": "http://192.168.1.9:8989"},
            {"service": "http_status:404"},
        ]},
        "apps": [{"id": "app1", "name": "Sonarr", "domain": "sonarr.makooy.nl",
                  "type": "self_hosted", "session_duration": "24h",
                  "policies": [{"id": "pol1", "name": "GoogleIDP-Marc-Policy", "precedence": 1}]}],
        "dns": [{"id": "dns1", "type": "CNAME", "name": "sonarr.makooy.nl",
                 "content": f"{TUNNEL}.cfargotunnel.com", "proxied": True}],
    })


reset_state()


def handler(request: httpx.Request) -> httpx.Response:
    path, method = request.url.path, request.method
    body = json.loads(request.content) if request.content else None
    page = request.url.params.get("page", "1")

    def ok(result):
        return httpx.Response(200, json={"success": True, "errors": [], "result": result})

    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    if token not in VALID_TOKENS:
        return httpx.Response(400, json={"success": False, "result": None, "errors": [
            {"code": 6003, "message": "Invalid request headers"}]})

    if path.endswith("/user/tokens/verify"):
        return ok({"status": "active"})
    if path.endswith("/cfd_tunnel") and method == "GET":
        return ok([{"id": TUNNEL, "name": "HATunnel", "status": "healthy"}] if page == "1" else [])
    if path.endswith(f"/cfd_tunnel/{TUNNEL}"):
        return ok({"id": TUNNEL, "name": "HATunnel", "status": "healthy"})
    if path.endswith("/configurations"):
        if method == "PUT":
            STATE["config"] = body["config"]
            return ok({"config": body["config"]})
        return ok({"config": STATE["config"]})
    if path.endswith("/access/apps") and method == "GET":
        return ok(STATE["apps"] if page == "1" else [])
    if path.endswith("/access/apps") and method == "POST":
        new = dict(body, id=f"app{len(STATE['apps']) + 1}")
        new["policies"] = [{"id": p["id"], "name": "pol", "precedence": p["precedence"]}
                           for p in body.get("policies", [])]
        STATE["apps"].append(new)
        return ok(new)
    if "/access/apps/" in path and method == "PUT":
        aid = path.rsplit("/", 1)[-1]
        for i, a in enumerate(STATE["apps"]):
            if a["id"] == aid:
                STATE["apps"][i] = dict(a, **body)
        return ok(body)
    if "/access/apps/" in path and method == "DELETE":
        aid = path.rsplit("/", 1)[-1]
        STATE["apps"] = [a for a in STATE["apps"] if a["id"] != aid]
        return ok({"id": aid})
    if path.endswith("/access/policies"):
        return ok([{"id": "pol1", "name": "GoogleIDP-Marc-Policy", "decision": "allow"},
                   {"id": "pol2", "name": "Everyone-Policy", "decision": "allow"}] if page == "1" else [])
    if path == "/client/v4/zones":
        return ok([{"id": "zone1", "name": "makooy.nl"}] if page == "1" else [])
    if path.endswith("/dns_records") and method == "GET":
        name = request.url.params.get("name")
        recs = [r for r in STATE["dns"] if not name or r["name"] == name]
        return ok(recs if page == "1" else [])
    if path.endswith("/dns_records") and method == "POST":
        rec = dict(body, id=f"dns{len(STATE['dns']) + 1}")
        STATE["dns"].append(rec)
        return ok(rec)
    if "/dns_records/" in path and method == "DELETE":
        rid = path.rsplit("/", 1)[-1]
        STATE["dns"] = [r for r in STATE["dns"] if r["id"] != rid]
        return ok({"id": rid})
    return httpx.Response(404, json={"success": False, "result": None, "errors": [
        {"code": 1, "message": f"no mock for {method} {path}"}]})


def make_client(token: str, account_id: str, timeout: float = 30.0) -> cf.CloudflareClient:
    """A CloudflareClient whose transport is the mock above."""
    client = cf.CloudflareClient.__new__(cf.CloudflareClient)
    client.account_id = account_id
    client._client = httpx.AsyncClient(
        base_url=cf.API_BASE, transport=httpx.MockTransport(handler),
        headers={"Authorization": f"Bearer {token}"},
    )
    return client


main.CloudflareClient = make_client
settings.store.clear()
settings.save(tunnel_id=TUNNEL)

tc = TestClient(main.app)


@pytest.fixture(autouse=True)
def clean_state():
    main.reset_client()
    yield


def login(client=tc, password="secret"):
    r = client.post("/login", data={"password": password}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return r


# ----------------------------------------------------------------- basics ---
def test_auth_required():
    fresh = TestClient(main.app)
    r = fresh.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    r = fresh.post("/login", data={"password": "wrong"}, follow_redirects=False)
    assert "err=" in r.headers["location"]


def test_dashboard():
    reset_state()
    login()
    r = tc.get("/")
    assert r.status_code == 200
    assert "ha.makooy.nl" in r.text and "sonarr.makooy.nl" in r.text
    assert "GoogleIDP-Marc-Policy" in r.text
    assert "https://192.168.1.12:8123" in r.text


# ------------------------------------------------------------------- crud ---
def test_create_full_app():
    reset_state()
    login()
    r = tc.post("/new", data={
        "hostname": "jellyfin", "zone": "makooy.nl", "scheme": "http",
        "origin_host": "192.168.1.9", "origin_port": "8096",
        "create_app": "1", "app_name": "Jellyfin", "session_duration": "24h",
        "policies": ["pol1", "pol2"], "launcher_visible": "1", "create_dns": "1",
    }, follow_redirects=False)
    assert r.status_code == 303 and "err=" not in r.headers["location"], r.headers["location"]

    rule = cf.find_rule(STATE["config"]["ingress"], "jellyfin.makooy.nl")
    assert rule and rule["service"] == "http://192.168.1.9:8096"
    assert cf.is_catch_all(STATE["config"]["ingress"][-1]), "catch-all must stay last"
    app = [a for a in STATE["apps"] if a["domain"] == "jellyfin.makooy.nl"][0]
    assert app["type"] == "self_hosted"
    assert [p["id"] for p in app["policies"]] == ["pol1", "pol2"], "both policies attached"
    assert any(d["name"] == "jellyfin.makooy.nl" and d["content"].endswith("cfargotunnel.com")
               for d in STATE["dns"])


def test_edit_changes_service_and_policies():
    reset_state()
    login()
    r = tc.get("/edit?h=sonarr.makooy.nl&p=")
    assert r.status_code == 200 and "8989" in r.text
    r = tc.post("/edit", data={
        "original_hostname": "sonarr.makooy.nl", "original_path": "",
        "hostname": "sonarr.makooy.nl", "scheme": "http",
        "origin_host": "192.168.1.9", "origin_port": "9999", "noTLSVerify": "1",
        "create_app": "1", "app_name": "Sonarr", "session_duration": "6h",
        "policies": ["pol2"], "launcher_visible": "1",
    }, follow_redirects=False)
    assert r.status_code == 303 and "err=" not in r.headers["location"], r.headers["location"]
    rule = cf.find_rule(STATE["config"]["ingress"], "sonarr.makooy.nl")
    assert rule["service"] == "http://192.168.1.9:9999"
    assert rule["originRequest"]["noTLSVerify"] is True
    app = [a for a in STATE["apps"] if a["domain"] == "sonarr.makooy.nl"][0]
    assert app["session_duration"] == "6h"
    assert len(STATE["config"]["ingress"]) == 3, "no duplicate rule"


def test_delete_everything():
    reset_state()
    login()
    r = tc.post("/delete", data={"hostname": "sonarr.makooy.nl", "path": "",
                                 "del_route": "1", "del_app": "1", "del_dns": "1"},
                follow_redirects=False)
    assert r.status_code == 303 and "err=" not in r.headers["location"], r.headers["location"]
    assert cf.find_rule(STATE["config"]["ingress"], "sonarr.makooy.nl") is None
    assert not [a for a in STATE["apps"] if a["domain"] == "sonarr.makooy.nl"]
    assert not [d for d in STATE["dns"] if d["name"] == "sonarr.makooy.nl"]


def test_backup_roundtrip():
    reset_state()
    login()
    r = tc.get("/backup/export")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    data = r.json()
    assert data["format"] == "cfzerotrustcontrol/1"

    STATE["config"] = cf.remove_rule(STATE["config"], "ha.makooy.nl")
    assert cf.find_rule(STATE["config"]["ingress"], "ha.makooy.nl") is None
    r = tc.post("/backup/preview", files={"backup": ("b.json", json.dumps(data), "application/json")})
    assert r.status_code == 200 and "ha.makooy.nl" in r.text
    token = r.text.split('name="token" value="')[1].split('"')[0]
    r = tc.post("/backup/apply", data={"token": token, "restore_routes": "1", "restore_apps": "1"},
                follow_redirects=False)
    assert r.status_code == 303 and "err=" not in r.headers["location"], r.headers["location"]
    assert cf.find_rule(STATE["config"]["ingress"], "ha.makooy.nl") is not None


# -------------------------------------------------------------- unit bits ---
def test_ingress_helpers():
    cfg = {"ingress": [{"hostname": "a.nl", "service": "http://1:1"}, {"service": "http_status:404"}]}
    out = cf.upsert_rule(cfg, {"hostname": "b.nl", "service": "http://2:2"})
    assert [r.get("hostname") for r in out["ingress"]] == ["a.nl", "b.nl", None]
    out = cf.upsert_rule(out, {"hostname": "a.nl", "service": "http://9:9"})
    assert len(out["ingress"]) == 3 and out["ingress"][0]["service"] == "http://9:9"
    out = cf.remove_rule(out, "a.nl")
    assert len(out["ingress"]) == 2 and cf.is_catch_all(out["ingress"][-1])
    out = cf.upsert_rule({"ingress": []}, {"hostname": "c.nl", "service": "http://3:3"})
    assert out["ingress"][-1]["service"] == "http_status:404", "a config without a catch-all gets one"


def test_service_url_parsing():
    assert services.build_service_url("http", "192.168.1.9", "8096") == "http://192.168.1.9:8096"
    assert services.build_service_url("https", "1.2.3.4", "") == "https://1.2.3.4"
    assert services.build_service_url("http", "", "", "http_status:404") == "http_status:404"
    assert services.parse_service_url("https://192.168.1.18:8006") == {
        "scheme": "https", "host": "192.168.1.18", "port": "8006", "raw": ""}
    assert services.normalize_domain("App.Example.com/api/") == ("app.example.com", "/api")


def test_password_hashing():
    stored = auth.hash_password("hunter2hunter2")
    assert auth.verify_hash("hunter2hunter2", stored)
    assert not auth.verify_hash("something else", stored)
    assert not auth.verify_hash("hunter2hunter2", "garbage")
    assert auth.password_problem("short", "short")
    assert auth.password_problem("longenough", "different")
    assert auth.password_problem("longenough", "longenough") == ""


def test_api_endpoint():
    reset_state()
    login()
    r = tc.get("/api/services")
    assert r.status_code == 200
    assert "ha.makooy.nl" in [x["hostname"] for x in r.json()]
