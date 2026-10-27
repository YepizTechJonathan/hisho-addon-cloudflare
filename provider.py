"""Cloudflare integration for Hisho (see addon.yaml). Runs inside Core.

Reads every domain the token can see (records, proxied or not, SSL mode, certificate status) and
changes DNS records: add, change, proxy on/off, delete. The dashboard asks before each change;
every change is written to the journal (``dns-change``) with what the record was before, so it
can be put back. Also provides the ``dns_records`` capability (list_records, set_record,
delete_record) for other add-ons and the CLI.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

API = "https://api.cloudflare.com/client/v4"
PROXYABLE = ("A", "AAAA", "CNAME")
TYPES = ("A", "AAAA", "CNAME", "TXT", "MX", "CAA", "SRV", "NS")
#: record types where one name may hold several records (so "set" adds rather than replaces)
MULTI = ("TXT", "MX", "CAA", "SRV", "NS")
KEEP = ("id", "type", "name", "content", "proxied", "ttl", "priority")


class CloudflareError(RuntimeError):
    pass


def call(entry: dict[str, Any], ctx: Any, path: str, method: str = "GET", body: Any = None) -> Any:
    req = urllib.request.Request(API + path, method=method,
                                 data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": f"Bearer {ctx.secret(entry['token'])}",
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.load(r)
    except urllib.error.HTTPError as exc:
        why = ""
        try:
            why = "; ".join(e.get("message", "") for e in json.load(exc).get("errors") or [])
        except Exception:  # noqa: BLE001
            pass
        if exc.code in (401, 403):
            raise CloudflareError("Cloudflare refused the token (wrong, expired, or missing a permission)"
                                  + (f": {why}" if why else ""))
        raise CloudflareError(f"Cloudflare answered {exc.code} on {path.split('?')[0]}" + (f": {why}" if why else ""))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CloudflareError(f"can't reach Cloudflare ({getattr(exc, 'reason', exc)})")
    if not data.get("success", False):
        raise CloudflareError("; ".join(e.get("message", "") for e in data.get("errors") or []) or "Cloudflare said no")
    return data.get("result")


def zones(entry: dict[str, Any], ctx: Any) -> list[dict[str, Any]]:
    return list(call(entry, ctx, "/zones?per_page=50") or [])


def records(entry: dict[str, Any], ctx: Any, zone_id: str) -> list[dict[str, Any]]:
    return list(call(entry, ctx, f"/zones/{zone_id}/dns_records?per_page=500") or [])


def ssl_mode(entry: dict[str, Any], ctx: Any, zone_id: str) -> str:
    try:
        return str((call(entry, ctx, f"/zones/{zone_id}/settings/ssl") or {}).get("value") or "?")
    except CloudflareError:
        return "?"


def certificates(entry: dict[str, Any], ctx: Any, zone_id: str) -> list[str]:
    """Problems with the zone's edge certificates: none of them active ([] when one is, or the token
    can't read them). Cloudflare keeps 'backup_issued' packs next to the active one; those are fine."""
    try:
        packs = list(call(entry, ctx, f"/zones/{zone_id}/ssl/certificate_packs?status=all") or [])
    except CloudflareError:
        return []
    if not packs or any(p.get("status") == "active" for p in packs):
        return []
    return [f"certificate for {', '.join(p.get('hosts') or [])} is {p.get('status')}" for p in packs]


# ── reading ────────────────────────────────────────────────────────────────

def summary(entries: dict[str, dict[str, Any]], ctx: Any) -> dict[str, Any]:
    n_zones = n_records = 0
    problems = []
    for name, entry in entries.items():
        try:
            zs = zones(entry, ctx)
        except CloudflareError as exc:
            problems.append({"entry": name, "severity": "warn", "title": f"Can't read Cloudflare ({name})",
                             "detail": str(exc)})
            continue
        n_zones += len(zs)
        for z in zs:
            if z.get("status") != "active":
                problems.append({"entry": name, "severity": "warn", "title": f"Cloudflare zone {z.get('name')} is {z.get('status')}",
                                 "detail": "It isn't serving DNS through Cloudflare."})
            for p in certificates(entry, ctx, z["id"]):
                problems.append({"entry": name, "severity": "warn", "title": f"{z.get('name')}: {p}",
                                 "detail": "Visitors may see a certificate warning. See SSL/TLS > Edge Certificates."})
            n_records += len(records(entry, ctx, z["id"]))
    return {"state": "warn" if problems else "ok",
            "headline": f"{n_zones} domain{'s' * (n_zones != 1)} · {n_records} DNS records", "problems": problems}


def _short(r: dict[str, Any]) -> str:
    return f"{r.get('type')} {r.get('name')} → {str(r.get('content'))[:80]}"


def _record_item(r: dict[str, Any]) -> dict[str, Any]:
    proxied, proxyable = r.get("proxied"), r.get("type") in PROXYABLE
    actions = [{"id": "change", "label": "change",
                "ask": f"New value for {r.get('type')} {r.get('name')} (now {r.get('content')})"
                       + (". For MX: priority then host, e.g. 10 mail.example.com" if r.get("type") == "MX" else "")}]
    if proxyable:
        actions.append({"id": "unproxy" if proxied else "proxy", "label": "proxy off" if proxied else "proxy on",
                        "confirm": (f"Stop proxying {r.get('name')}? Visitors will reach {r.get('content')} directly "
                                    "and see its real address." if proxied else
                                    f"Proxy {r.get('name')} through Cloudflare? Visitors go through Cloudflare first, "
                                    "so the server must answer on 80/443.")})
    if r.get("type") != "NS":
        actions.append({"id": "delete", "label": "delete", "danger": True,
                        "confirm": f"Delete {_short(r)}? Anything using this name stops working once caches expire."})
    return {"id": r["id"], "name": f"{r.get('type')}  {r.get('name')}",
            "state": "up" if proxied else ("warn" if proxyable else "off"),
            "facts": [str(r.get("content"))[:120] + (f"  (priority {r['priority']})" if r.get("priority") is not None else ""),
                      "proxied through Cloudflare" if proxied else
                      ("not proxied: visitors reach the server directly" if proxyable else ""),
                      f"TTL {'auto' if r.get('ttl') == 1 else r.get('ttl')}" + (f" · {r['comment']}" if r.get("comment") else "")],
            "actions": actions}


def details(entries: dict[str, dict[str, Any]], ctx: Any) -> list[dict[str, Any]]:
    out = []
    for name, entry in entries.items():
        try:
            zs = zones(entry, ctx)
        except CloudflareError as exc:
            out.append({"title": name, "entry": name, "state": "down", "facts": [str(exc)], "items": []})
            continue
        seen, sections = [], []
        for z in zs:
            recs = records(entry, ctx, z["id"])
            certs = certificates(entry, ctx, z["id"])
            ssl = ssl_mode(entry, ctx, z["id"])
            seen.append((z, recs, ssl))
            items = [{"id": f"add-{z['id']}", "name": "+ add a record", "state": "off",
                      "facts": [f"Adds a DNS record to {z.get('name')}."],
                      "actions": [{"id": "add", "label": "add",
                                   "ask": f"New record in {z.get('name')}: TYPE NAME VALUE, e.g. "
                                          "'A www 203.0.113.5 proxied', 'TXT @ google-site-verification=…', "
                                          f"'MX @ 10 mail.example.com'. @ means {z.get('name')} itself."}]}]
            items += [_record_item(r) for r in sorted(recs, key=lambda r: (r.get("type"), r.get("name")))]
            sections.append({"title": z.get("name"), "entry": name,
                             "state": "down" if z.get("status") != "active" else ("warn" if certs else "ok"),
                             "facts": [f"{z.get('status')} · plan {((z.get('plan') or {}).get('name') or '?')} · SSL {ssl}",
                                       f"{len(recs)} records, {sum(1 for r in recs if r.get('proxied'))} proxied"]
                                      + certs + ([entry["note"]] if entry.get("note") else []),
                             "items": items})
        out += [review(name, entry, ctx, seen)] + sections
    return out


# ── keys and exposure ────────────────────────────────────────────────────

#: a token not used for this many days is worth revoking (if nothing needs it)
STALE_DAYS = 90
#: Security Center finding types, in plain words
INSIGHTS = {"security_txt_not_enabled": ("security.txt isn't set up",
                                         "Lets people who find a hole tell you about it. Cloudflare > Security > Settings > security.txt."),
            "no_turnstile_enabled": ("No Turnstile on any form",
                                     "Turnstile stops bots on sign-up and contact forms. Only matters if your sites have forms.")}


def _days_ago(stamp: str | None, now: Any) -> int | None:
    import datetime as dt
    if not stamp:
        return None
    try:
        return (now - dt.datetime.fromisoformat(stamp.replace("Z", "+00:00"))).days
    except ValueError:
        return None


def _public_ip(value: str) -> bool:
    import ipaddress
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global and ip not in ipaddress.ip_network("100.64.0.0/10")


def _wide(resources: dict[str, Any]) -> bool:
    """A token policy on all zones or a whole account (rather than on named zones)."""
    for key, value in resources.items():
        if key.endswith("zone.*") or (key.startswith("com.cloudflare.api.account.") and ".zone." not in key and value == "*"):
            return True
        if isinstance(value, dict) and _wide(value):
            return True
    return False


def _exposed_ok(entry: dict[str, Any]) -> set[str]:
    return {x.strip() for x in str(entry.get("exposed_ok") or "").split(",") if x.strip()}


def token_items(entry: dict[str, Any], ctx: Any, now: Any = None) -> list[dict[str, Any]]:
    """One item per API token on the user: what it can do, when it was last used, what to do about it."""
    import datetime as dt
    now = now or dt.datetime.now(dt.timezone.utc)
    try:
        toks = list(call(entry, ctx, "/user/tokens?per_page=50") or [])
    except CloudflareError:
        return [{"id": "tokens", "name": "API tokens", "state": "unknown",
                 "facts": ["Hisho's token can't list your tokens (give it User > API Tokens > Read)."], "actions": []}]
    try:
        mine = (call(entry, ctx, "/user/tokens/verify") or {}).get("id")
    except CloudflareError:
        mine = None
    names = [t.get("name") for t in toks]
    items = []
    for t in sorted(toks, key=lambda t: str(t.get("name")).lower()):
        perms = sorted({g.get("name", "") for p in t.get("policies") or [] if p.get("effect") == "allow"
                        for g in p.get("permission_groups") or []})
        writes = [g for g in perms if g.endswith((" Write", " Edit", " Run", " Bind"))]
        every = any(_wide(p.get("resources") or {}) for p in t.get("policies") or [])
        idle = _days_ago(t.get("last_used_on"), now)
        notes = []
        if t.get("id") == mine:
            notes.append("this is Hisho's own token")
        elif t.get("status") != "active":
            notes.append(f"{t.get('status')}: delete it if you don't need it back")
        elif idle is None:
            notes.append("never used: revoke it if nothing needs it")
        elif idle > STALE_DAYS:
            notes.append(f"not used for {idle} days: revoke it if nothing needs it")
        if t.get("id") != mine and len(writes) >= 5:
            notes.append(f"broad: it can change {len(writes)} kinds of things; a token per job is safer")
        if names.count(t.get("name")) > 1:
            notes.append("another token has the same name: rename them so you can tell them apart")
        if not t.get("expires_on"):
            notes.append("never expires")
        if not (t.get("condition") or {}).get("request_ip"):
            notes.append("works from any IP address")
        worry = [n for n in notes if not n.startswith(("this is", "never expires", "works from"))]
        items.append({"id": f"token-{str(t.get('id'))[:20]}", "name": f"token  {t.get('name')}",
                      "state": "warn" if worry else ("up" if t.get("status") == "active" else "off"),
                      "facts": [(f"last used {idle} days ago" if idle else "used today" if idle == 0 else "never used")
                                + f" · {'all zones/account' if every else 'some zones'} · "
                                + (", ".join(writes) + " (change)" if writes else "read only"),
                                *[n[0].upper() + n[1:] + "." for n in notes],
                                "Can: " + ", ".join(perms)],
                      "actions": []})
    return items


def review(name: str, entry: dict[str, Any], ctx: Any, seen: list[tuple[dict[str, Any], list[dict[str, Any]], str]]) -> dict[str, Any]:
    """The "Keys and exposure" section: tokens, servers anyone can find in DNS, weak SSL, Security Center."""
    items = token_items(entry, ctx)
    exposed: dict[str, list[str]] = {}
    for z, recs, ssl in seen:
        for r in recs:
            if r.get("type") in ("A", "AAAA") and not r.get("proxied") and _public_ip(str(r.get("content"))):
                exposed.setdefault(str(r["content"]), []).append(str(r.get("name")))
        if ssl in ("off", "flexible"):
            items.append({"id": f"ssl-{z['id']}", "name": f"SSL {ssl}  {z.get('name')}", "state": "warn",
                          "facts": ["Cloudflare talks to your server without encryption. "
                                    "Set SSL/TLS to Full (strict) once the server has a certificate."], "actions": []})
    ok = _exposed_ok(entry)
    for ip, hosts in sorted(exposed.items(), key=lambda kv: -len(kv[1])):
        known = ip in ok
        items.append({"id": f"ip-{ip.replace(':', '-')}"[:60], "name": f"server {ip}", "state": "off" if known else "warn",
                      "facts": [(f"{len(hosts)} names point" if len(hosts) != 1 else "1 name points") + " straight at it"
                                + (". You said that's on purpose." if known else
                                   ", so anyone can find and attack it without going through Cloudflare. Turn proxy on "
                                   "for web names (not for mail, SSH or game ports)."), ", ".join(sorted(hosts))],
                      "actions": [{"id": "expected", "label": "not on purpose"} if known else
                                  {"id": "expected", "label": "on purpose",
                                   "confirm": f"Stop warning about {ip}? It stays listed here, marked on purpose."}]})
    try:
        aid = (list(call(entry, ctx, "/accounts?per_page=5") or [{}])[0] or {}).get("id")
        found = (call(entry, ctx, f"/accounts/{aid}/security-center/insights?per_page=100") or {}).get("issues") or [] if aid else []
    except CloudflareError:
        found = []
    groups: dict[str, list[dict[str, Any]]] = {}
    for i in found:
        if not i.get("dismissed") and i.get("status", "active") == "active":
            groups.setdefault(str(i.get("issue_class")), []).append(i)
    for cls, issues in sorted(groups.items()):
        title, why = INSIGHTS.get(cls, (cls.replace("_", " "), str(issues[0].get("issue_type", "")).replace("_", " ")))
        items.append({"id": f"insight-{cls}"[:60], "name": f"Security Center  {title}",
                      "state": "warn" if any(i.get("severity") in ("Moderate", "Critical", "High") for i in issues) else "off",
                      "facts": [f"{issues[0].get('severity')} · {why}", ", ".join(sorted(str(i.get("subject")) for i in issues))],
                      "actions": []})
    worry = sum(1 for i in items if i["state"] == "warn")
    return {"title": "Keys and exposure", "entry": name, "state": "warn" if worry else "ok",
            "facts": [f"{worry} thing{'s' * (worry != 1)} to look at" if worry else "nothing to look at",
                      "Read only: Hisho never makes, changes or revokes tokens."],
            "items": items}


def test(entry: dict[str, Any], ctx: Any) -> dict[str, Any]:
    try:
        zs = zones(entry, ctx)
    except CloudflareError as exc:
        return {"ok": False, "error": str(exc)}
    if not zs:
        return {"ok": False, "error": "the token works but sees no domains (give it Zone:Read on your zones)"}
    return {"ok": True, "message": f"Connected: {len(zs)} domain(s): " + ", ".join(z.get('name', '') for z in zs[:6])}


def describe_secret(entry: dict[str, Any], ctx: Any) -> str:
    """The 'What:' line of the token's Infisical comment: its name in Cloudflare, scope and permissions
    (the permissions only when the token may read API Tokens)."""
    names = ", ".join(z.get("name", "") for z in zones(entry, ctx)) or "no zones"
    try:
        tid = (call(entry, ctx, "/user/tokens/verify") or {}).get("id")
        tok = call(entry, ctx, f"/user/tokens/{tid}") or {}
    except CloudflareError:
        return f"Cloudflare API token, zones {names}."
    perms = sorted({g.get("name", "") for p in tok.get("policies") or [] if p.get("effect") == "allow"
                    for g in p.get("permission_groups") or []})
    every = any("zone.*" in json.dumps(p.get("resources") or {}) for p in tok.get("policies") or [])
    return (f'Cloudflare API token "{tok.get("name", "?")}", {"all zones" if every else "zones"} ({names}). '
            + ", ".join(perms) + "." + (f" Expires {tok['expires_on'][:10]}." if tok.get("expires_on") else ""))


# ── changing ───────────────────────────────────────────────────────────────

def _journal(meta: dict[str, Any]) -> None:
    try:
        from hisho.jobs import append_event
        append_event(Path(os.environ.get("HISHO_ROOT") or "~/Hisho").expanduser(), "dns-change", meta)
    except Exception:  # noqa: BLE001 -- the journal never blocks a change
        pass


def _fqdn(name: str, zone: str) -> str:
    name = name.strip().rstrip(".").lower()
    if name in ("@", "", zone):
        return zone
    return name if name.endswith("." + zone) else f"{name}.{zone}"


def _body(rtype: str, name: str, value: str, proxied: bool | None, ttl: int | None) -> dict[str, Any]:
    rtype = rtype.upper()
    if rtype not in TYPES:
        raise CloudflareError(f"record type {rtype} isn't one Hisho changes ({', '.join(TYPES)})")
    if not value.strip():
        raise CloudflareError("the record needs a value")
    body: dict[str, Any] = {"type": rtype, "name": name, "content": value.strip(), "ttl": int(ttl or 1)}
    if rtype == "MX":
        prio, _, host = value.strip().partition(" ")
        if not prio.isdigit() or not host.strip():
            raise CloudflareError("an MX value is a priority then a host, e.g. 10 mail.example.com")
        body.update(content=host.strip(), priority=int(prio))
    if rtype in PROXYABLE:
        body["proxied"] = bool(proxied)
    elif proxied:
        raise CloudflareError(f"{rtype} records can't be proxied")
    return body


def _zone_for(entries: dict[str, dict[str, Any]], ctx: Any, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """(entry, zone) whose domain holds ``name`` (the longest match wins)."""
    name = name.rstrip(".").lower()
    best = None
    for entry in entries.values():
        for z in zones(entry, ctx):
            zn = str(z.get("name", "")).lower()
            if (name == zn or name.endswith("." + zn)) and (best is None or len(zn) > len(best[1]["name"])):
                best = (entry, z)
    if best is None:
        raise CloudflareError(f"none of your Cloudflare domains holds {name}")
    return best


def _find(entry: dict[str, Any], ctx: Any, record_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    for z in zones(entry, ctx):
        for r in records(entry, ctx, z["id"]):
            if r.get("id") == record_id:
                return z, r
    raise CloudflareError("that record isn't there any more (refresh the page)")


def _done(verb: str, zone: dict[str, Any], before: dict[str, Any] | None, after: dict[str, Any] | None) -> dict[str, Any]:
    _journal({"addon": "cloudflare", "zone": zone.get("name"), "action": verb,
              "before": {k: before.get(k) for k in KEEP if k in before} if before else None,
              "after": {k: after.get(k) for k in KEEP if k in after} if after else None})
    was = (f" (was {before.get('content')}{', proxied' if before.get('proxied') else ''})"
           if before and after else "")
    return {"ok": True, "message": f"{verb.capitalize()} {_short(after or before or {})}"
                                   + (" (proxied)" if (after or {}).get("proxied") else "") + was,
            "record": {k: (after or before).get(k) for k in KEEP}}


def add(entry: dict[str, Any], ctx: Any, zone: dict[str, Any], rtype: str, name: str, value: str,
        proxied: bool | None = None, ttl: int | None = None) -> dict[str, Any]:
    body = _body(rtype, _fqdn(name, zone["name"]), value, proxied, ttl)
    return _done("added", zone, None, call(entry, ctx, f"/zones/{zone['id']}/dns_records", "POST", body))


def change(entry: dict[str, Any], ctx: Any, zone: dict[str, Any], rec: dict[str, Any], value: str | None = None,
           proxied: bool | None = None) -> dict[str, Any]:
    if value is None:
        value = f"{rec.get('priority')} {rec['content']}" if rec["type"] == "MX" else rec["content"]
    body = _body(rec["type"], rec["name"], value, rec.get("proxied") if proxied is None else proxied, rec.get("ttl"))
    if rec.get("comment"):
        body["comment"] = rec["comment"]
    return _done("changed", zone, rec, call(entry, ctx, f"/zones/{zone['id']}/dns_records/{rec['id']}", "PUT", body))


def delete(entry: dict[str, Any], ctx: Any, zone: dict[str, Any], rec: dict[str, Any]) -> dict[str, Any]:
    call(entry, ctx, f"/zones/{zone['id']}/dns_records/{rec['id']}", "DELETE")
    return _done("deleted", zone, rec, None)


def parse_new(text: str) -> tuple[str, str, str, bool]:
    """'A www 203.0.113.5 proxied' -> (A, www, 203.0.113.5, True). The value may hold spaces (TXT)."""
    words = text.split()
    if len(words) < 3:
        raise CloudflareError("type the record as TYPE NAME VALUE, e.g. A www 203.0.113.5")
    rtype, name, rest = words[0].upper(), words[1], words[2:]
    proxied = rtype in PROXYABLE and len(rest) > 1 and rest[-1].lower() in ("proxied", "proxy")
    if proxied:
        rest = rest[:-1]
    value = " ".join(rest).strip()
    if rtype == "TXT" and len(value) > 1 and value[0] == value[-1] == '"':
        value = value[1:-1]
    return rtype, name, value, proxied


def act(entries: dict[str, dict[str, Any]], ctx: Any, entry: str, item: str, action: str) -> dict[str, Any]:
    ent = entries.get(entry)
    if ent is None:
        return {"ok": False, "error": f"no Cloudflare entry {entry}"}
    typed = (getattr(ctx, "input", "") or "").strip()
    try:
        if action == "add":
            zone = next((z for z in zones(ent, ctx) if z["id"] == item.removeprefix("add-")), None)
            if zone is None:
                return {"ok": False, "error": "that domain isn't in this Cloudflare account"}
            rtype, name, value, proxied = parse_new(typed)
            return add(ent, ctx, zone, rtype, name, value, proxied)
        if action == "expected" and item.startswith("ip-"):
            from hisho import addons
            ip = item.removeprefix("ip-")
            ip = ip if "." in ip else ip.replace("-", ":")
            ok = _exposed_ok(ent)
            ok = ok - {ip} if ip in ok else ok | {ip}
            addons.set_entry(ctx.addon, entry, {"exposed_ok": ", ".join(sorted(ok))}, merge=True)
            return {"ok": True, "message": f"{ip}: " + ("on purpose, no more warning" if ip in ok else "warning again")}
        if action not in ("change", "proxy", "unproxy", "delete"):
            return {"ok": False, "error": f"unknown action {action}"}
        zone, rec = _find(ent, ctx, item)
        if action == "change":
            return change(ent, ctx, zone, rec, value=typed) if typed else {"ok": False, "error": "type the new value"}
        if action == "delete":
            return delete(ent, ctx, zone, rec)
        if rec["type"] not in PROXYABLE:
            return {"ok": False, "error": f"{rec['type']} records can't be proxied"}
        return change(ent, ctx, zone, rec, proxied=action == "proxy")
    except CloudflareError as exc:
        return {"ok": False, "error": str(exc)}


# ── the dns_records capability ────────────────────────────────────────────

def list_records(entries: dict[str, dict[str, Any]], ctx: Any, name: str) -> list[dict[str, Any]]:
    """The records named ``name``, or every record of the domain when ``name`` is the domain."""
    ent, zone = _zone_for(entries, ctx, name)
    fq = name.rstrip(".").lower()
    return [{k: r.get(k) for k in KEEP} for r in records(ent, ctx, zone["id"])
            if fq == zone["name"] or r.get("name") == fq]


def set_record(entries: dict[str, dict[str, Any]], ctx: Any, name: str, rtype: str, value: str,
               proxied: bool | None = None, ttl: int | None = None) -> dict[str, Any]:
    """Make ``name`` hold this record. A/AAAA/CNAME: the one record of that name and type is changed
    (or made). TXT/MX/...: added unless the same value is already there."""
    try:
        ent, zone = _zone_for(entries, ctx, name)
        fq, rtype = _fqdn(name, zone["name"]), rtype.upper()
        want = _body(rtype, fq, value, proxied, ttl)
        same = [r for r in records(ent, ctx, zone["id"]) if r.get("name") == fq and r.get("type") == rtype]
        if rtype in MULTI:
            if any(r.get("content") == want["content"] for r in same):
                return {"ok": True, "changed": False, "message": f"{rtype} {fq} already has that value"}
            return {**add(ent, ctx, zone, rtype, fq, value, proxied, ttl), "changed": True}
        if len(same) > 1:
            return {"ok": False, "error": f"{fq} has {len(same)} {rtype} records; change them on the add-on page"}
        if not same:  # (Cloudflare itself refuses a CNAME next to other records, with a clear error)
            return {**add(ent, ctx, zone, rtype, fq, value, proxied, ttl), "changed": True}
        r = same[0]
        if r.get("content") == want["content"] and bool(r.get("proxied")) == bool(want.get("proxied")):
            return {"ok": True, "changed": False, "message": f"{rtype} {fq} is already {want['content']}"}
        return {**change(ent, ctx, zone, r, value=value, proxied=bool(want.get("proxied"))), "changed": True}
    except CloudflareError as exc:
        return {"ok": False, "error": str(exc)}


def delete_record(entries: dict[str, dict[str, Any]], ctx: Any, name: str, rtype: str,
                  value: str | None = None) -> dict[str, Any]:
    """Delete ``name``'s records of this type (only the one holding ``value`` when given)."""
    try:
        ent, zone = _zone_for(entries, ctx, name)
        fq, rtype = _fqdn(name, zone["name"]), rtype.upper()
        gone = [r for r in records(ent, ctx, zone["id"]) if r.get("name") == fq and r.get("type") == rtype
                and (value is None or r.get("content") == value.strip())]
        if not gone:
            return {"ok": True, "changed": False, "message": f"{fq} has no such {rtype} record"}
        return {"ok": True, "changed": True, "message": "; ".join(delete(ent, ctx, zone, r)["message"] for r in gone)}
    except CloudflareError as exc:
        return {"ok": False, "error": str(exc)}
