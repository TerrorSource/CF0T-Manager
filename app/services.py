"""Business logic: treat tunnel route, Access app and DNS as one unit."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import cf
from .cf import CloudflareClient, CloudflareError

class DnsConflict(Exception):
    """A different record already exists on this hostname, so the user decides."""

    def __init__(self, hostname: str, record: dict, target: str):
        super().__init__(f"{hostname} already has a DNS record")
        self.hostname = hostname
        self.record = record
        self.target = target


ORIGIN_BOOL_FIELDS = ("noTLSVerify", "http2Origin", "disableChunkedEncoding", "noHappyEyeballs")
ORIGIN_STR_FIELDS = ("httpHostHeader", "originServerName", "caPool", "proxyType")
ORIGIN_INT_FIELDS = ("connectTimeout", "tlsTimeout", "tcpKeepAlive", "keepAliveTimeout",
                     "keepAliveConnections")


@dataclass
class ServiceRow:
    """One hostname, with everything attached to it."""
    hostname: str
    path: str = ""
    rule: dict | None = None
    app: dict | None = None
    dns: dict | None = None
    zone_id: str | None = None

    @property
    def key(self) -> str:
        return f"{self.hostname}|{self.path}"

    @property
    def service(self) -> str:
        return (self.rule or {}).get("service", "")

    @property
    def app_name(self) -> str:
        return (self.app or {}).get("name", "")

    @property
    def policies(self) -> list[dict]:
        return (self.app or {}).get("policies") or []

    @property
    def has_route(self) -> bool:
        return self.rule is not None

    @property
    def has_app(self) -> bool:
        return self.app is not None

    @property
    def dns_ok(self) -> bool:
        return self.dns is not None


def normalize_domain(value: str) -> tuple[str, str]:
    """'app.example.com/path' -> ('app.example.com', '/path')."""
    value = (value or "").strip().lower().rstrip("/")
    value = value.removeprefix("https://").removeprefix("http://")
    if "/" in value:
        host, _, rest = value.partition("/")
        return host, f"/{rest}" if rest else ""
    return value, ""


def normalize_path(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    return value if value.startswith("/") else f"/{value}"


def build_origin_request(form: dict[str, Any]) -> dict:
    """Only send origin options that were actually filled in."""
    origin: dict[str, Any] = {}
    for key in ORIGIN_BOOL_FIELDS:
        if form.get(key):
            origin[key] = True
    for key in ORIGIN_STR_FIELDS:
        value = (form.get(key) or "").strip()
        if value:
            origin[key] = value
    for key in ORIGIN_INT_FIELDS:
        raw = str(form.get(key) or "").strip()
        if raw:
            try:
                origin[key] = int(raw)
            except ValueError:
                continue
    return origin


def build_service_url(scheme: str, host: str, port: str, raw: str = "") -> str:
    raw = (raw or "").strip()
    if raw:
        return raw
    scheme = (scheme or "http").strip()
    host = (host or "").strip()
    port = str(port or "").strip()
    if scheme in {"unix", "http_status"}:
        return f"{scheme}:{host or port}"
    if not host:
        raise ValueError("Origin host is required.")
    return f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}"


def parse_service_url(service: str) -> dict:
    """Inverse of build_service_url, for the edit form."""
    service = (service or "").strip()
    out = {"scheme": "http", "host": "", "port": "", "raw": ""}
    if "://" not in service:
        out["raw"] = service
        if ":" in service:
            out["scheme"] = service.split(":", 1)[0]
        return out
    scheme, _, rest = service.partition("://")
    out["scheme"] = scheme
    if rest.count(":") == 1:
        host, _, port = rest.partition(":")
        out["host"], out["port"] = host, port
    else:
        out["host"] = rest
    return out


def zone_for_hostname(hostname: str, zones: list[dict]) -> dict | None:
    hostname = (hostname or "").lower()
    best = None
    for zone in zones:
        name = (zone.get("name") or "").lower()
        if hostname == name or hostname.endswith("." + name):
            if best is None or len(name) > len(best.get("name", "")):
                best = zone
    return best


class ZeroTrustManager:
    def __init__(self, client: CloudflareClient, tunnel_id: str) -> None:
        self.cf = client
        self.tunnel_id = tunnel_id

    # ---------------- reading ----------------
    async def load_overview(self, with_dns: bool = True) -> tuple[list[ServiceRow], dict]:
        config = await self.cf.get_tunnel_config(self.tunnel_id)
        apps = await self.cf.list_access_apps()

        apps_by_domain: dict[tuple[str, str], dict] = {}
        for app in apps:
            host, path = normalize_domain(app.get("domain") or "")
            if host:
                apps_by_domain[(host, path)] = app

        rows: list[ServiceRow] = []
        matched_app_ids: set[str] = set()
        for rule in config.get("ingress") or []:
            if cf.is_catch_all(rule):
                continue
            host = (rule.get("hostname") or "").lower()
            path = normalize_path(rule.get("path") or "")
            app = apps_by_domain.get((host, path))
            if app and app.get("id"):
                matched_app_ids.add(app["id"])
            rows.append(ServiceRow(hostname=host, path=path, rule=rule, app=app))

        # Also show Access apps that have no matching tunnel route
        for (host, path), app in apps_by_domain.items():
            if app.get("id") in matched_app_ids:
                continue
            rows.append(ServiceRow(hostname=host, path=path, rule=None, app=app))

        meta: dict[str, Any] = {"config": config, "apps": apps, "zones": [], "dns_error": None}

        if with_dns:
            try:
                zones = await self.cf.list_zones()
                meta["zones"] = zones
                dns_by_name: dict[str, dict] = {}
                for zone in zones:
                    for record in await self.cf.list_dns_records(zone["id"]):
                        if record.get("type") in {"CNAME", "A", "AAAA"}:
                            dns_by_name.setdefault((record.get("name") or "").lower(), record)
                for row in rows:
                    row.dns = dns_by_name.get(row.hostname)
                    zone = zone_for_hostname(row.hostname, zones)
                    row.zone_id = zone["id"] if zone else None

                # Records still pointing at a tunnel while their route and app
                # are gone - usually left behind by a rename.
                known = {r.hostname for r in rows}
                for name, record in dns_by_name.items():
                    if name in known:
                        continue
                    if not str(record.get("content") or "").endswith(".cfargotunnel.com"):
                        continue
                    zone = zone_for_hostname(name, zones)
                    rows.append(ServiceRow(hostname=name, rule=None, app=None, dns=record,
                                           zone_id=zone["id"] if zone else None))
            except CloudflareError as exc:
                meta["dns_error"] = str(exc)

        rows.sort(key=lambda r: (r.hostname, r.path))
        return rows, meta

    async def get_row(self, hostname: str, path: str = "") -> ServiceRow | None:
        rows, _ = await self.load_overview(with_dns=True)
        host = (hostname or "").lower()
        path = normalize_path(path)
        for row in rows:
            if row.hostname == host and row.path == path:
                return row
        for row in rows:
            if row.hostname == host:
                return row
        return None

    # ---------------- writing ----------------
    async def save_route(self, hostname: str, path: str, service: str, origin: dict,
                         original_hostname: str = "", original_path: str = "") -> None:
        rule: dict = {"hostname": hostname, "service": service}
        if path:
            rule["path"] = path
        if origin:
            rule["originRequest"] = origin
        config = await self.cf.get_tunnel_config(self.tunnel_id)
        config = cf.upsert_rule(config, rule, original_hostname, original_path)
        await self.cf.put_tunnel_config(self.tunnel_id, config)

    async def delete_route(self, hostname: str, path: str = "") -> None:
        config = await self.cf.get_tunnel_config(self.tunnel_id)
        config = cf.remove_rule(config, hostname, path)
        await self.cf.put_tunnel_config(self.tunnel_id, config)

    async def create_app(self, name: str, domain: str, policy_ids: list[str],
                         session_duration: str = "24h", launcher_visible: bool = True,
                         app_type: str = "self_hosted") -> dict:
        payload: dict[str, Any] = {
            "name": name,
            "domain": domain,
            "type": app_type,
            "session_duration": session_duration,
            "app_launcher_visible": launcher_visible,
        }
        if policy_ids:
            payload["policies"] = [
                {"id": pid, "precedence": idx + 1} for idx, pid in enumerate(policy_ids)
            ]
        return await self.cf.create_access_app(payload)

    async def update_app(self, app: dict, name: str, domain: str, policy_ids: list[str],
                         session_duration: str, launcher_visible: bool) -> dict:
        payload: dict[str, Any] = {
            "name": name,
            "domain": domain,
            "type": app.get("type") or "self_hosted",
            "session_duration": session_duration,
            "app_launcher_visible": launcher_visible,
            "policies": [{"id": pid, "precedence": i + 1} for i, pid in enumerate(policy_ids)],
        }
        return await self.cf.update_access_app(app["id"], payload)

    async def ensure_dns(self, hostname: str, zones: list[dict], overwrite: bool = False) -> str:
        """Create the CNAME to <tunnel>.cfargotunnel.com if it isn't there yet.

        A record that already exists and points somewhere else is never
        changed on our own: that raises DnsConflict so the user can decide.
        """
        zone = zone_for_hostname(hostname, zones)
        if not zone:
            raise CloudflareError(f"No zone found for {hostname}.")
        target = f"{self.tunnel_id}.cfargotunnel.com"
        existing = await self.cf.list_dns_records(zone["id"], name=hostname)

        for record in existing:
            if record.get("type") == "CNAME" and record.get("content") == target:
                return "DNS record already existed."

        clashing = [r for r in existing if r.get("type") in {"CNAME", "A", "AAAA"}]
        if clashing:
            if not overwrite:
                raise DnsConflict(hostname, clashing[0], target)
            await self.cf.update_dns_record(zone["id"], clashing[0]["id"], {
                "type": "CNAME", "name": hostname, "content": target, "proxied": True,
            })
            return "Existing DNS record repointed at the tunnel."

        await self.cf.create_dns_record(zone["id"], {
            "type": "CNAME",
            "name": hostname,
            "content": target,
            "proxied": True,
        })
        return "DNS CNAME created."

    async def delete_dns(self, hostname: str, zones: list[dict]) -> str:
        zone = zone_for_hostname(hostname, zones)
        if not zone:
            return "No zone found, skipped DNS."
        records = await self.cf.list_dns_records(zone["id"], name=hostname)
        removed = 0
        for record in records:
            if record.get("type") in {"CNAME", "A", "AAAA"}:
                await self.cf.delete_dns_record(zone["id"], record["id"])
                removed += 1
        return f"Deleted {removed} DNS record(s)." if removed else "No DNS record found."
