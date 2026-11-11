"""What differs between a stored backup and the live configuration, and
whether the change log of this tool accounts for it."""
from __future__ import annotations

import re
from typing import Any

from . import cf, services

# What makes a policy behave differently. Counters and timestamps on the
# object move without anyone touching the policy, so only these are compared.
POLICY_FIELDS = ("name", "decision", "include", "exclude", "require", "session_duration",
                 "approval_required", "approval_groups", "purpose_justification_required",
                 "purpose_justification_prompt", "isolation_required")
# Identity and bookkeeping on an application; policies are compared on their own.
APP_IGNORED = {"id", "uid", "aud", "created_at", "updated_at", "policies"}
APP_LABELS = {
    "allowed_idps": "login methods",
    "session_duration": "session duration",
    "auto_redirect_to_identity": "skip the login page",
    "app_launcher_visible": "shown in the App Launcher",
    "destinations": "hostnames",
    "self_hosted_domains": "hostnames",
}


def _empty(value: Any) -> bool:
    """Cloudflare leaves a field out, or sends null, false or an empty list,
    and means the same by all of them."""
    return value is None or value is False or value == "" or value == [] or value == {}


def _same(old: Any, new: Any) -> bool:
    return (_empty(old) and _empty(new)) or old == new


def _show(value: Any) -> str | None:
    """Something short enough to print, or None when it is not."""
    if _empty(value):
        return "off" if value is False else "nothing"
    if value is True:
        return "on"
    if isinstance(value, (str, int, float)):
        return str(value)
    if isinstance(value, list) and all(isinstance(v, (str, int)) for v in value):
        return ", ".join(str(v) for v in value)
    if isinstance(value, list) and all(isinstance(v, dict) and v.get("uri") for v in value):
        return ", ".join(str(v["uri"]) for v in value)
    return None


def _detail(label: str, old: Any, new: Any) -> str:
    before, after = _show(old), _show(new)
    if before is None or after is None:
        return f"{label} changed"
    return f"{label}: {before} → {after}"


def _difference(kind: str, change: str, name: str, details: list[str] | None = None,
                hostnames: list[str] | None = None, order: bool = False) -> dict:
    return {"kind": kind, "change": change, "name": name, "details": details or [],
            "hostnames": hostnames or [], "order": order, "logged": []}


# ------------------------------------------------------------------ routes ---
def _routes(old: dict, new: dict) -> list[dict]:
    old_rules, old_catch = cf.split_ingress((old.get("tunnel_config") or {}).get("ingress") or [])
    new_rules, new_catch = cf.split_ingress((new.get("tunnel_config") or {}).get("ingress") or [])
    before = {cf.rule_key(r.get("hostname"), r.get("path")): r for r in old_rules}
    after = {cf.rule_key(r.get("hostname"), r.get("path")): r for r in new_rules}
    out = []

    for key in sorted(after.keys() - before.keys()):
        out.append(_difference("route", "added", key[0] + key[1],
                               [f"to {after[key].get('service', '')}"], [key[0]]))
    for key in sorted(before.keys() - after.keys()):
        out.append(_difference("route", "removed", key[0] + key[1],
                               [f"was {before[key].get('service', '')}"], [key[0]]))
    for key in sorted(before.keys() & after.keys()):
        a, b = before[key], after[key]
        details = []
        if not _same(a.get("service"), b.get("service")):
            details.append(_detail("origin", a.get("service"), b.get("service")))
        a_origin, b_origin = a.get("originRequest") or {}, b.get("originRequest") or {}
        for option in sorted(set(a_origin) | set(b_origin)):
            if not _same(a_origin.get(option), b_origin.get(option)):
                details.append(_detail(f"origin option {option}",
                                       a_origin.get(option), b_origin.get(option)))
        if details:
            out.append(_difference("route", "changed", key[0] + key[1], details, [key[0]]))

    if not _same(old_catch.get("service"), new_catch.get("service")):
        out.append(_difference("route", "changed", "catch-all rule",
                               [_detail("answer", old_catch.get("service"),
                                        new_catch.get("service"))]))

    # Order only means something for the rules both sides have.
    shared = before.keys() & after.keys()
    if [k for k in before if k in shared] != [k for k in after if k in shared]:
        out.append(_difference("route", "changed", "route order",
                               ["the rules are matched in a different order"], order=True))
    return out


# ------------------------------------------------------------ applications ---
def _app_name(app: dict) -> str:
    name, domain = app.get("name") or "", app.get("domain") or ""
    if name and domain:
        return f"{name} ({domain})"
    return name or domain or app.get("id") or "application"


def _app_hosts(*apps: dict) -> list[str]:
    hosts: list[str] = []
    for app in apps:
        for host, _ in services.app_hostnames(app):
            if host not in hosts:
                hosts.append(host)
    return hosts


def _policy_changes(old: dict, new: dict) -> list[str]:
    return [field.replace("_", " ") for field in POLICY_FIELDS
            if not _same(old.get(field), new.get(field))]


def _methods(value: Any, idp_names: dict[str, str]) -> str:
    if _empty(value):
        return "every method"
    return ", ".join(idp_names.get(i, "an unknown provider") for i in value)


def _app_details(a: dict, b: dict, reusable_ids: set[str], idp_names: dict[str, str]) -> list[str]:
    details = []
    for field in sorted((set(a) | set(b)) - APP_IGNORED):
        if _same(a.get(field), b.get(field)):
            continue
        if field == "allowed_idps":
            details.append(f"login methods: {_methods(a.get(field), idp_names)} → "
                           f"{_methods(b.get(field), idp_names)}")
        else:
            details.append(_detail(APP_LABELS.get(field, field.replace("_", " ")),
                                   a.get(field), b.get(field)))

    a_policies, b_policies = a.get("policies") or [], b.get("policies") or []
    if [p.get("id") for p in a_policies] != [p.get("id") for p in b_policies]:
        details.append("policies: "
                       + (", ".join(p.get("name") or "unnamed" for p in a_policies) or "none")
                       + " → "
                       + (", ".join(p.get("name") or "unnamed" for p in b_policies) or "none"))
    # A reusable policy is reported once under policies; one that lives inside
    # the application has nowhere else to show up.
    b_by_id = {p.get("id"): p for p in b_policies}
    for policy in a_policies:
        other = b_by_id.get(policy.get("id"))
        if other is None or policy.get("id") in reusable_ids:
            continue
        changed = _policy_changes(policy, other)
        if changed:
            details.append(f"policy {policy.get('name') or 'unnamed'}: "
                           f"{', '.join(changed)} changed")
    return details


def _apps(old: dict, new: dict, idp_names: dict[str, str]) -> list[dict]:
    before = {a.get("id"): a for a in old.get("access_apps") or [] if a.get("id")}
    after = {a.get("id"): a for a in new.get("access_apps") or [] if a.get("id")}
    reusable_ids = {p.get("id") for side in (old, new) for p in side.get("policies") or []}
    out = []
    for key in after.keys() - before.keys():
        out.append(_difference("application", "added", _app_name(after[key]),
                               hostnames=_app_hosts(after[key])))
    for key in before.keys() - after.keys():
        out.append(_difference("application", "removed", _app_name(before[key]),
                               hostnames=_app_hosts(before[key])))
    for key in before.keys() & after.keys():
        details = _app_details(before[key], after[key], reusable_ids, idp_names)
        if details:
            out.append(_difference("application", "changed", _app_name(after[key]), details,
                                   _app_hosts(before[key], after[key])))
    return sorted(out, key=lambda d: d["name"].lower())


# ---------------------------------------------------------------- policies ---
def _policies(old: dict, new: dict) -> list[dict]:
    before = {p.get("id"): p for p in old.get("policies") or [] if p.get("id")}
    after = {p.get("id"): p for p in new.get("policies") or [] if p.get("id")}
    out = []
    for key in after.keys() - before.keys():
        out.append(_difference("policy", "added", after[key].get("name") or key))
    for key in before.keys() - after.keys():
        out.append(_difference("policy", "removed", before[key].get("name") or key))
    for key in before.keys() & after.keys():
        a, b = before[key], after[key]
        details = []
        for field in POLICY_FIELDS:
            if _same(a.get(field), b.get(field)):
                continue
            label = field.replace("_", " ")
            # Who a policy lets in is the part that matters, and too long to print.
            details.append(f"{label} changed" if field in ("include", "exclude", "require")
                           else _detail(label, a.get(field), b.get(field)))
        if details:
            out.append(_difference("policy", "changed", b.get("name") or key, details))
    return sorted(out, key=lambda d: d["name"].lower())


# --------------------------------------------------------------------- dns ---
def _records(zone: dict) -> dict[tuple[str, str], list[tuple[str, bool]]]:
    """Several records may share a name, so each name holds all its answers."""
    grouped: dict[tuple[str, str], list[tuple[str, bool]]] = {}
    for record in zone.get("records") or []:
        key = ((record.get("name") or "").lower(), record.get("type") or "")
        grouped.setdefault(key, []).append((str(record.get("content") or ""),
                                            bool(record.get("proxied"))))
    return {key: sorted(values) for key, values in grouped.items()}


def _answers(values: list[tuple[str, bool]]) -> str:
    return ", ".join(content for content, _ in values)


def _dns(old: dict, new: dict) -> tuple[list[dict], list[str]]:
    old_zones = {z.get("zone_id"): z for z in old.get("dns_zones") or [] if z.get("zone_id")}
    new_zones = {z.get("zone_id"): z for z in new.get("dns_zones") or [] if z.get("zone_id")}
    if not old_zones:
        return [], ["This backup holds no DNS records, so DNS was not compared."]
    if not new_zones:
        return [], ["DNS could not be read from Cloudflare just now, so it was not compared."]

    out, notes = [], []
    for zone_id, zone in old_zones.items():
        if zone_id not in new_zones:
            notes.append(f"The zone {zone.get('zone_name') or zone_id} is in the backup but "
                         f"could not be read now, so its records were not compared.")
            continue
        before, after = _records(zone), _records(new_zones[zone_id])
        for key in sorted(after.keys() - before.keys()):
            out.append(_difference("dns", "added", f"{key[0]} ({key[1]})",
                                   [f"points at {_answers(after[key])}"], [key[0]]))
        for key in sorted(before.keys() - after.keys()):
            out.append(_difference("dns", "removed", f"{key[0]} ({key[1]})",
                                   [f"pointed at {_answers(before[key])}"], [key[0]]))
        for key in sorted(before.keys() & after.keys()):
            a, b = before[key], after[key]
            details = []
            if _answers(a) != _answers(b):
                details.append(f"points at: {_answers(a)} → {_answers(b)}")
            if [proxied for _, proxied in a] != [proxied for _, proxied in b]:
                details.append(_detail("proxied", a[0][1], b[0][1]))
            if details:
                out.append(_difference("dns", "changed", f"{key[0]} ({key[1]})", details,
                                       [key[0]]))
    for zone_id, zone in new_zones.items():
        if zone_id not in old_zones:
            notes.append(f"The zone {zone.get('zone_name') or zone_id} is not in this backup, "
                         f"so its records were not compared.")
    return out, notes


# ------------------------------------------------------------------ public ---
def compare(old: dict, new: dict,
            idp_names: dict[str, str] | None = None) -> tuple[list[dict], list[str]]:
    """Everything that differs between two backup payloads, plus notes on what
    could not be compared. `old` is the backup, `new` the live state."""
    notes = []
    old_tunnel, new_tunnel = old.get("tunnel") or {}, new.get("tunnel") or {}
    if old_tunnel.get("id") and new_tunnel.get("id") and old_tunnel["id"] != new_tunnel["id"]:
        notes.append(f"This backup is of the tunnel {old_tunnel.get('name') or old_tunnel['id']}, "
                     f"not the one selected now, so the routes will not line up.")
    dns, dns_notes = _dns(old, new)
    differences = [*_routes(old, new), *_apps(old, new, idp_names or {}),
                   *_policies(old, new), *dns]
    return differences, notes + dns_notes


def _mentions(text: str, hostname: str) -> bool:
    """The hostname as a whole word: ha.example.com is not in alpha.example.com."""
    return bool(re.search(rf"(?<![\w.-]){re.escape(hostname)}(?![\w.-])", text or ""))


def _explains(entry: dict, difference: dict) -> bool:
    if difference["order"]:
        return entry.get("action") == "reordered"
    text = f"{entry.get('target') or ''} {entry.get('detail') or ''}"
    return any(_mentions(text, host) for host in difference["hostnames"])


def attribute(differences: list[dict], log: list[dict], since: str) -> list[str]:
    """Hang the change-log entries written since the backup on the differences
    they account for. Returns notes on what the log cannot tell apart."""
    recent = [e for e in log if (e.get("at") or "") >= (since or "")]
    for difference in differences:
        difference["logged"] = [e for e in recent if _explains(e, difference)]
    restores = [e for e in recent if e.get("action") == "restored"]
    if restores and differences:
        return [f"A backup was restored through this tool on {restores[0].get('when') or restores[0].get('at')}. "
                f"A restore touches many hostnames at once and is logged as one entry, so some "
                f"of what is listed as changed elsewhere may come from it."]
    return []
