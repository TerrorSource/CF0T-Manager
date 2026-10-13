"""Thin async client around the Cloudflare API, plus tunnel-ingress helpers."""
from __future__ import annotations

import copy
from typing import Any

import httpx

API_BASE = "https://api.cloudflare.com/client/v4"
CATCH_ALL_SERVICE = "http_status:404"


class CloudflareError(Exception):
    def __init__(self, message: str, status: int | None = None, errors: list | None = None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.errors = errors or []


class CloudflareClient:
    def __init__(self, token: str, account_id: str, timeout: float = 30.0) -> None:
        self.account_id = account_id
        self._client = httpx.AsyncClient(
            base_url=API_BASE,
            timeout=timeout,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "CF0T-Manager/1.0",
            },
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _request(self, method: str, path: str, **kwargs) -> Any:
        try:
            resp = await self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise CloudflareError(f"Network error talking to Cloudflare: {exc}") from exc

        if resp.status_code == 204 or not resp.content:
            return None

        try:
            payload = resp.json()
        except ValueError:
            raise CloudflareError(
                f"Unexpected response from Cloudflare (HTTP {resp.status_code})", resp.status_code
            )

        if not isinstance(payload, dict) or not payload.get("success", False):
            errors = (payload or {}).get("errors") or []
            parts = []
            for err in errors:
                code = err.get("code")
                msg = err.get("message", "")
                chain = err.get("error_chain") or []
                for sub in chain:
                    msg += f" ({sub.get('message', '')})"
                parts.append(f"[{code}] {msg}" if code else msg)
            message = "; ".join(p for p in parts if p) or f"HTTP {resp.status_code}"
            raise CloudflareError(message, resp.status_code, errors)

        return payload.get("result")

    async def _paginated(self, path: str, params: dict | None = None) -> list[dict]:
        results: list[dict] = []
        page = 1
        while True:
            query = dict(params or {})
            query.update({"page": page, "per_page": 100})
            chunk = await self._request("GET", path, params=query)
            if not chunk:
                break
            results.extend(chunk)
            if len(chunk) < 100:
                break
            page += 1
            if page > 50:  # safety net
                break
        return results

    # ---------- token ----------
    async def verify_token(self) -> dict:
        return await self._request("GET", "/user/tokens/verify")

    # ---------- tunnels ----------
    async def list_tunnels(self) -> list[dict]:
        tunnels = await self._paginated(
            f"/accounts/{self.account_id}/cfd_tunnel", {"is_deleted": "false"}
        )
        return [t for t in tunnels if not t.get("deleted_at")]

    async def get_tunnel(self, tunnel_id: str) -> dict:
        return await self._request("GET", f"/accounts/{self.account_id}/cfd_tunnel/{tunnel_id}")

    async def get_tunnel_config(self, tunnel_id: str) -> dict:
        result = await self._request(
            "GET", f"/accounts/{self.account_id}/cfd_tunnel/{tunnel_id}/configurations"
        )
        config = (result or {}).get("config") or {}
        config.setdefault("ingress", [])
        return config

    async def put_tunnel_config(self, tunnel_id: str, config: dict) -> dict:
        return await self._request(
            "PUT",
            f"/accounts/{self.account_id}/cfd_tunnel/{tunnel_id}/configurations",
            json={"config": config},
        )

    # ---------- access ----------
    async def list_access_apps(self) -> list[dict]:
        return await self._paginated(f"/accounts/{self.account_id}/access/apps")

    async def get_access_app(self, app_id: str) -> dict:
        return await self._request("GET", f"/accounts/{self.account_id}/access/apps/{app_id}")

    async def create_access_app(self, payload: dict) -> dict:
        return await self._request(
            "POST", f"/accounts/{self.account_id}/access/apps", json=payload
        )

    async def update_access_app(self, app_id: str, payload: dict) -> dict:
        return await self._request(
            "PUT", f"/accounts/{self.account_id}/access/apps/{app_id}", json=payload
        )

    async def delete_access_app(self, app_id: str) -> Any:
        return await self._request("DELETE", f"/accounts/{self.account_id}/access/apps/{app_id}")

    async def list_policies(self) -> list[dict]:
        return await self._paginated(f"/accounts/{self.account_id}/access/policies")

    # ---------- dns ----------
    async def list_zones(self) -> list[dict]:
        return await self._paginated("/zones", {"account.id": self.account_id, "status": "active"})

    async def list_dns_records(self, zone_id: str, name: str | None = None) -> list[dict]:
        params: dict = {}
        if name:
            params["name"] = name
        return await self._paginated(f"/zones/{zone_id}/dns_records", params)

    async def create_dns_record(self, zone_id: str, payload: dict) -> dict:
        return await self._request("POST", f"/zones/{zone_id}/dns_records", json=payload)

    async def update_dns_record(self, zone_id: str, record_id: str, payload: dict) -> dict:
        return await self._request(
            "PATCH", f"/zones/{zone_id}/dns_records/{record_id}", json=payload
        )

    async def delete_dns_record(self, zone_id: str, record_id: str) -> Any:
        return await self._request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")


# --------------------------------------------------------------------------
# Ingress helpers. The PUT replaces the whole list, so always work from the
# current config and keep the catch-all as the last rule.
# --------------------------------------------------------------------------

def rule_key(hostname: str | None, path: str | None) -> tuple[str, str]:
    return ((hostname or "").strip().lower(), (path or "").strip())


def is_catch_all(rule: dict) -> bool:
    return not (rule.get("hostname") or "").strip()


def split_ingress(ingress: list[dict]) -> tuple[list[dict], dict]:
    """Split into (hostname rules, catch-all)."""
    rules = [r for r in ingress if not is_catch_all(r)]
    catch_alls = [r for r in ingress if is_catch_all(r)]
    catch_all = catch_alls[-1] if catch_alls else {"service": CATCH_ALL_SERVICE}
    return rules, catch_all


def build_ingress(rules: list[dict], catch_all: dict) -> list[dict]:
    return [*rules, catch_all]


def find_rule(ingress: list[dict], hostname: str, path: str = "") -> dict | None:
    key = rule_key(hostname, path)
    for rule in ingress:
        if is_catch_all(rule):
            continue
        if rule_key(rule.get("hostname"), rule.get("path")) == key:
            return rule
    return None


def upsert_rule(config: dict, rule: dict, original_hostname: str = "", original_path: str = "") -> dict:
    """Add a rule, or replace an existing one (matched on hostname + path)."""
    config = copy.deepcopy(config)
    rules, catch_all = split_ingress(config.get("ingress") or [])
    target = rule_key(original_hostname or rule.get("hostname"), original_path or rule.get("path"))

    replaced = False
    new_rules = []
    for existing in rules:
        if not replaced and rule_key(existing.get("hostname"), existing.get("path")) == target:
            new_rules.append(rule)
            replaced = True
        else:
            new_rules.append(existing)
    if not replaced:
        new_rules.append(rule)

    config["ingress"] = build_ingress(new_rules, catch_all)
    return config


def remove_rule(config: dict, hostname: str, path: str = "") -> dict:
    config = copy.deepcopy(config)
    rules, catch_all = split_ingress(config.get("ingress") or [])
    target = rule_key(hostname, path)
    config["ingress"] = build_ingress(
        [r for r in rules if rule_key(r.get("hostname"), r.get("path")) != target], catch_all
    )
    return config


def reorder_rules(config: dict, ordered_keys: list[tuple[str, str]]) -> dict:
    config = copy.deepcopy(config)
    rules, catch_all = split_ingress(config.get("ingress") or [])
    by_key = {rule_key(r.get("hostname"), r.get("path")): r for r in rules}
    ordered = [by_key.pop(k) for k in ordered_keys if k in by_key]
    ordered.extend(by_key.values())  # keep unlisted rules at the end
    config["ingress"] = build_ingress(ordered, catch_all)
    return config
