"""Business logic: treat tunnel route, Access app and DNS as one unit."""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from . import cf
from .cf import CloudflareClient, CloudflareError

# The overview needs four or five round trips to Cloudflare, so it is kept
# briefly and thrown away as soon as anything is written.
OVERVIEW_TTL = 60.0
_overview_cache: dict[str, tuple[float, list, dict]] = {}


def invalidate_overview(tunnel_id: str = "") -> None:
    if tunnel_id:
        _overview_cache.pop(tunnel_id, None)
    else:
        _overview_cache.clear()


class DnsConflict(Exception):
    """A different record already exists on this hostname, so the user decides."""

    def __init__(self, hostname: str, record: dict, target: str):
        super().__init__(f"{hostname} already has a DNS record")
        self.hostname = hostname
        self.record = record
        self.target = target


# Fields the API returns but will not accept back on a PUT.
READ_ONLY_APP_FIELDS = ("id", "aud", "created_at", "updated_at")

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
    def app_type(self) -> str:
        return (self.app or {}).get("type", "") or ""

    @property
    def is_self_hosted(self) -> bool:
        return not self.app or self.app_type == SELF_HOSTED

    @property
    def editable(self) -> bool:
        """SaaS, infrastructure and the rest are not tunnel-backed, so the
        origin form does not apply to them."""
        return self.has_route or self.is_self_hosted

    @property
    def other_hostnames(self) -> list[str]:
        if not self.app:
            return []
        return [h for h, _ in app_hostnames(self.app) if h != self.hostname]

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


SELF_HOSTED = "self_hosted"


def app_hostnames(app: dict) -> list[tuple[str, str]]:
    """Every public hostname an application covers: its domain plus the extra
    entries in destinations, which is where a second hostname ends up."""
    found = [normalize_domain(app.get("domain") or "")]
    for dest in app.get("destinations") or []:
        if not isinstance(dest, dict):
            continue
        if (dest.get("type") or "public") != "public":
            continue
        uri = dest.get("uri") or ""
        if uri:
            found.append(normalize_domain(uri))
    seen, out = set(), []
    for host, path in found:
        if host and (host, path) not in seen:
            seen.add((host, path))
            out.append((host, path))
    return out


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


def split_hostname(hostname: str, zones: list[dict]) -> tuple[str, str]:
    """'app.example.com' + the example.com zone -> ('app', 'example.com').

    Returns the hostname unchanged with an empty zone when no zone matches, or
    when the hostname *is* the zone, since there is no subdomain to split off.
    """
    zone = zone_for_hostname(hostname, zones)
    if not zone:
        return hostname, ""
    name = zone["name"]
    if hostname.lower() == name.lower():
        return hostname, ""
    return hostname[: -(len(name) + 1)], name


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
    async def _zones_and_dns(self) -> tuple[list[dict], dict[str, dict], str]:
        """Zones plus their records, in parallel. Missing permissions are not
        fatal: the rest of the overview works without DNS."""
        try:
            zones = await self.cf.list_zones()
            per_zone = await asyncio.gather(
                *(self.cf.list_dns_records(zone["id"]) for zone in zones)
            )
        except CloudflareError as exc:
            return [], {}, str(exc)

        by_name: dict[str, dict] = {}
        for records in per_zone:
            for record in records:
                if record.get("type") in {"CNAME", "A", "AAAA"}:
                    by_name.setdefault((record.get("name") or "").lower(), record)
        return zones, by_name, ""

    async def load_overview(self, with_dns: bool = True,
                            refresh: bool = False) -> tuple[list[ServiceRow], dict]:
        cached = _overview_cache.get(self.tunnel_id)
        if cached and not refresh and time.monotonic() - cached[0] < OVERVIEW_TTL:
            return cached[1], cached[2]

        if with_dns:
            config, apps, (zones, dns_by_name, dns_error) = await asyncio.gather(
                self.cf.get_tunnel_config(self.tunnel_id),
                self.cf.list_access_apps(),
                self._zones_and_dns(),
            )
        else:
            config, apps = await asyncio.gather(
                self.cf.get_tunnel_config(self.tunnel_id), self.cf.list_access_apps()
            )
            zones, dns_by_name, dns_error = [], {}, ""

        apps_by_domain: dict[tuple[str, str], dict] = {}
        for app in apps:
            for key in app_hostnames(app):
                apps_by_domain.setdefault(key, app)

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
            matched_app_ids.add(app.get("id"))  # one row per app, on its own domain
            primary = app_hostnames(app)[0] if app_hostnames(app) else (host, path)
            rows.append(ServiceRow(hostname=primary[0], path=primary[1], rule=None, app=app))

        meta: dict[str, Any] = {"config": config, "apps": apps, "zones": zones,
                                "dns_error": dns_error or None}

        if dns_by_name:
            for row in rows:
                row.dns = dns_by_name.get(row.hostname)
                zone = zone_for_hostname(row.hostname, zones)
                row.zone_id = zone["id"] if zone else None

            # Records still pointing at a tunnel while their route and app are
            # gone - usually left behind by a rename.
            known = {r.hostname for r in rows}
            for name, record in dns_by_name.items():
                if name in known:
                    continue
                if not str(record.get("content") or "").endswith(".cfargotunnel.com"):
                    continue
                zone = zone_for_hostname(name, zones)
                rows.append(ServiceRow(hostname=name, rule=None, app=None, dns=record,
                                       zone_id=zone["id"] if zone else None))

        rows.sort(key=lambda r: (r.hostname, r.path))
        _overview_cache[self.tunnel_id] = (time.monotonic(), rows, meta)
        return rows, meta

    async def get_row(self, hostname: str, path: str = "") -> ServiceRow | None:
        """Exact match only. Falling back to another path on the same hostname
        would edit or delete a rule the user did not pick."""
        rows, _ = await self.load_overview(with_dns=True)
        host = (hostname or "").lower()
        path = normalize_path(path)
        for row in rows:
            if row.hostname == host and row.path == path:
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

        # Adding a hostname that already has a route, or renaming onto one,
        # would quietly overwrite it. Refuse instead.
        target = cf.rule_key(hostname, path)
        previous = cf.rule_key(original_hostname, original_path) if original_hostname else None
        if previous != target and cf.find_rule(config.get("ingress") or [], hostname, path):
            raise CloudflareError(
                f"{hostname}{path} already has a tunnel route. Edit that one instead, "
                f"or remove it first."
            )

        config = cf.upsert_rule(config, rule, original_hostname, original_path)
        await self.cf.put_tunnel_config(self.tunnel_id, config)
        invalidate_overview(self.tunnel_id)

    async def delete_route(self, hostname: str, path: str = "") -> None:
        config = await self.cf.get_tunnel_config(self.tunnel_id)
        config = cf.remove_rule(config, hostname, path)
        await self.cf.put_tunnel_config(self.tunnel_id, config)
        invalidate_overview(self.tunnel_id)

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
        invalidate_overview(self.tunnel_id)
        return await self.cf.create_access_app(payload)

    async def recreate_app(self, app_def: dict) -> dict:
        """Restore an application from a backup with all of its settings, not
        just the handful this tool manages."""
        payload = {k: v for k, v in app_def.items() if k not in READ_ONLY_APP_FIELDS}
        reusable = [p for p in (app_def.get("policies") or [])
                    if p.get("id") and p.get("reusable", True)]
        payload["policies"] = [{"id": p["id"], "precedence": i + 1}
                               for i, p in enumerate(reusable)]
        invalidate_overview(self.tunnel_id)
        return await self.cf.create_access_app(payload)

    async def update_app(self, app: dict, name: str, domain: str, policy_ids: list[str],
                         session_duration: str, launcher_visible: bool) -> dict:
        """Updating an Access app is a PUT that replaces the whole object, so
        start from what Cloudflare has and change only our own fields.
        Anything configured elsewhere - identity providers, instant auth,
        custom pages, CORS - has to survive untouched."""
        old_domain = (app.get("domain") or "").strip()
        payload: dict[str, Any] = {k: v for k, v in app.items()
                                   if k not in READ_ONLY_APP_FIELDS}
        payload.update({
            "name": name,
            "domain": domain,
            "type": app.get("type") or "self_hosted",
            "session_duration": session_duration,
            "app_launcher_visible": launcher_visible,
            "policies": [{"id": pid, "precedence": i + 1} for i, pid in enumerate(policy_ids)],
        })

        # A rename has to move the hostname in the secondary destination lists too.
        if old_domain and domain != old_domain:
            if isinstance(payload.get("destinations"), list):
                payload["destinations"] = [
                    {**d, "uri": d["uri"].replace(old_domain, domain, 1)}
                    if isinstance(d, dict) and old_domain in (d.get("uri") or "") else d
                    for d in payload["destinations"]
                ]
            if isinstance(payload.get("self_hosted_domains"), list):
                payload["self_hosted_domains"] = [
                    domain if d == old_domain else d for d in payload["self_hosted_domains"]
                ]
        invalidate_overview(self.tunnel_id)
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
            invalidate_overview(self.tunnel_id)
            return "Existing DNS record repointed at the tunnel."

        await self.cf.create_dns_record(zone["id"], {
            "type": "CNAME",
            "name": hostname,
            "content": target,
            "proxied": True,
        })
        invalidate_overview(self.tunnel_id)
        return "DNS CNAME created."

    async def dns_snapshot(self, zones: list[dict]) -> list[dict]:
        """Address records per zone, so a backup can put DNS back too."""
        per_zone = await asyncio.gather(
            *(self.cf.list_dns_records(zone["id"]) for zone in zones)
        )
        out = []
        for zone, records in zip(zones, per_zone):
            kept = [{k: r.get(k) for k in ("id", "type", "name", "content", "proxied", "ttl")}
                    for r in records if r.get("type") in {"CNAME", "A", "AAAA"}]
            out.append({"zone_id": zone["id"], "zone_name": zone.get("name", ""),
                        "records": kept})
        return out

    async def restore_dns(self, snapshot: list[dict]) -> tuple[int, int]:
        """Recreate records that are gone. Existing names are left alone, the
        same rule the rest of the tool follows for DNS."""
        created = skipped = 0
        for zone in snapshot:
            zone_id = zone.get("zone_id")
            if not zone_id:
                continue
            try:
                present = {(r.get("name") or "").lower()
                           for r in await self.cf.list_dns_records(zone_id)}
            except CloudflareError:
                continue
            for record in zone.get("records") or []:
                name = (record.get("name") or "").lower()
                if not name or name in present:
                    skipped += 1
                    continue
                await self.cf.create_dns_record(zone_id, {
                    "type": record.get("type", "CNAME"),
                    "name": record.get("name"),
                    "content": record.get("content"),
                    "proxied": bool(record.get("proxied")),
                })
                present.add(name)
                created += 1
        if created:
            invalidate_overview(self.tunnel_id)
        return created, skipped

    async def dns_records_for(self, hostname: str, zones: list[dict]) -> list[dict]:
        """Every address record on this hostname, so the delete screen can show
        all of them instead of just the first."""
        zone = zone_for_hostname(hostname, zones)
        if not zone:
            return []
        records = await self.cf.list_dns_records(zone["id"], name=hostname)
        return [r for r in records if r.get("type") in {"CNAME", "A", "AAAA"}]

    async def delete_dns(self, hostname: str, zones: list[dict],
                         record_ids: list[str]) -> str:
        """Delete exactly the records the user ticked, never more."""
        zone = zone_for_hostname(hostname, zones)
        if not zone:
            return "No zone found, skipped DNS."
        existing = {r["id"]: r for r in await self.dns_records_for(hostname, zones)}
        wanted = [rid for rid in record_ids if rid in existing]
        for rid in wanted:
            await self.cf.delete_dns_record(zone["id"], rid)
        if wanted:
            invalidate_overview(self.tunnel_id)
            return f"Deleted {len(wanted)} DNS record(s)."
        return "No DNS record deleted."
