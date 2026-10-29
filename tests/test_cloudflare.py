"""Cloudflare add-on tests. Run with Hisho's venv at the repository's top:
~/code/hisho/.venv/bin/python -m pytest -q"""
import json
import subprocess
from pathlib import Path

import pytest
import yaml

from hisho import addon_store, addons
from hisho.addon_testing import AUTH, TOKEN, Recorder

HERE = Path(__file__).resolve().parents[1]


def ctx_for(addon):
    return addons.Context(addon, resolve=lambda name: f"value-of-{name}")


def test_manifest_is_valid_and_readme_matches(addon):
    assert addons.validate_manifest(addon.manifest) == []
    assert addon_store.readme_problems(HERE) == []



def test_the_token_link_opens_cloudflare_with_exactly_the_permissions_ticked(addon):
    """Cloudflare's documented template URL: permissionGroupKeys is a URL-encoded JSON list of {key, type}."""
    from urllib.parse import parse_qs, urlparse
    url = addon.manifest["help"]["token"]["get"]
    u = urlparse(url)
    assert (u.scheme, u.netloc, u.path) == ("https", "dash.cloudflare.com", "/profile/api-tokens")
    q = parse_qs(u.query)
    keys = json.loads(q["permissionGroupKeys"][0])
    assert keys == [{"key": "zone", "type": "read"}, {"key": "dns", "type": "edit"},
                    {"key": "zone_settings", "type": "read"}, {"key": "ssl_and_certificates", "type": "read"},
                    {"key": "account_settings", "type": "read"}]
    assert q["accountId"] == ["*"] and q["zoneId"] == ["all"] and q["name"] == ["Hisho"]
    assert "{" not in url and " " not in url          # nothing the page would try to fill in
    required = [k for k, t in addon.manifest["entry_schema"].items() if not str(t).endswith("?")]
    assert required == ["token"]                       # the token is all the form needs; zones are found

def test_the_cloudflare_integration_lists_zones_and_records(fleet, monkeypatch):
    import io, json as _json
    cf = addons.get("cloudflare")
    addons.set_entry(cf, "main", {"token": "HISHO_CF"})

    class Resp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def urlopen(req, timeout=0):
        assert req.headers["Authorization"] == "Bearer t"
        path = req.full_url.split("/v4", 1)[1]
        res = {"/zones?per_page=50": [{"id": "z1", "name": "example.app", "status": "active", "plan": {"name": "Free"}}],
               "/zones/z1/dns_records?per_page=500": [
                   {"id": "r1", "type": "A", "name": "example.app", "content": "93.184.216.34", "proxied": False},
                   {"id": "r2", "type": "CNAME", "name": "www.example.app", "content": "example.app", "proxied": True},
                   {"id": "r3", "type": "TXT", "name": "example.app", "content": "v=spf1 -all", "proxied": False}],
               "/zones/z1/settings/ssl": {"value": "full"},
               "/zones/z1/ssl/certificate_packs?status=all": [{"hosts": ["example.app"], "status": "pending_validation"}],
               "/user/tokens?per_page=50": [], "/user/tokens/verify": {}, "/accounts?per_page=5": []}[path]
        return Resp(_json.dumps({"success": True, "result": res}).encode())
    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    ctx = addons.Context(cf, resolve=lambda n: "t")
    assert addons.summarize(cf, ctx)["headline"] == "1 domain · 3 DNS records"
    review, sec = addons.details(cf, ctx)
    assert review["title"] == "Keys and exposure"
    assert [i["name"] for i in review["items"]] == ["server 93.184.216.34"]   # the A record not proxied
    assert sec["facts"][0] == "active · plan Free · SSL full"
    assert sec["state"] == "warn" and "certificate for example.app is pending_validation" in sec["facts"]
    states = {i["name"]: i["state"] for i in sec["items"][1:]}
    assert states == {"A  example.app": "warn", "CNAME  www.example.app": "up", "TXT  example.app": "off"}


class FakeCloudflare:
    """Cloudflare's v4 API for one zone, in memory: GET/POST/PUT/DELETE on dns_records."""

    def __init__(self):
        import itertools
        self.ids = (f"r{i}" for i in itertools.count(10))
        self.records = {"r1": {"id": "r1", "type": "A", "name": "example.app", "content": "93.184.216.34", "proxied": False, "ttl": 1},
                        "r2": {"id": "r2", "type": "CNAME", "name": "www.example.app", "content": "example.app", "proxied": True, "ttl": 1},
                        "r3": {"id": "r3", "type": "TXT", "name": "example.app", "content": "v=spf1 -all", "proxied": False, "ttl": 1}}
        self.writes = []
        self.extra = {"/user/tokens?per_page=50": [], "/user/tokens/verify": {"id": "tok1"}, "/accounts?per_page=5": []}

    def __call__(self, req, timeout=0):
        import io, json as _json

        class Resp(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False
        assert req.headers["Authorization"] == "Bearer t"
        path, method = req.full_url.split("/v4", 1)[1], req.get_method()
        body = _json.loads(req.data) if req.data else None
        if path == "/zones?per_page=50":
            res = [{"id": "z1", "name": "example.app", "status": "active", "plan": {"name": "Free"}}]
        elif path == "/zones/z1/settings/ssl":
            res = {"value": "full"}
        elif path.startswith("/zones/z1/ssl/certificate_packs"):
            res = [{"hosts": ["example.app", "*.example.app"], "status": "active"},
                   {"hosts": ["example.app", "*.example.app"], "status": "backup_issued"}]
        elif path == "/zones/z1/dns_records?per_page=500":
            res = list(self.records.values())
        elif path in self.extra:
            res = self.extra[path]
        elif path == "/zones/z1/dns_records" and method == "POST":
            res = {**body, "id": next(self.ids)}
            self.records[res["id"]] = res
        elif path.startswith("/zones/z1/dns_records/"):
            rid = path.rsplit("/", 1)[1]
            self.writes.append((method, rid, body))
            res = self.records.pop(rid) if method == "DELETE" else {**body, "id": rid}
            if method == "PUT":
                self.records[rid] = res
        else:
            raise AssertionError(path)
        return Resp(_json.dumps({"success": True, "result": res}).encode())


def cloudflare_on(monkeypatch):
    cf = addons.get("cloudflare")
    addons.set_entry(cf, "main", {"token": "HISHO_CF"})
    fake = FakeCloudflare()
    monkeypatch.setattr("urllib.request.urlopen", fake)
    return cf, addons.Context(cf, resolve=lambda n: "t"), fake


def test_cloudflare_record_buttons_add_change_proxy_and_delete_and_journal_each(fleet, monkeypatch):
    from hisho import jobs
    cf, ctx, fake = cloudflare_on(monkeypatch)
    _review, sec = addons.details(cf, ctx)
    assert sec["state"] == "ok" and addons.summarize(cf, ctx)["problems"] == []   # backup certificates are normal
    add_item, *recs = sec["items"]
    assert add_item["id"] == "add-z1" and add_item["actions"][0]["ask"]
    a = {i["name"]: {x["id"]: x for x in i["actions"]} for i in recs}
    assert set(a["A  example.app"]) == {"change", "proxy", "delete"}
    assert a["A  example.app"]["delete"]["danger"] and "Delete A example.app" in a["A  example.app"]["delete"]["confirm"]
    assert "unproxy" in a["CNAME  www.example.app"] and "proxy" not in a["TXT  example.app"]

    def press(item, action, typed=""):
        return addons.act(cf, "main", item, action, ctx=ctx, input=typed)

    res = press("add-z1", "add", "A blog 198.51.100.7 proxied")
    assert res["ok"], res
    new = next(r for r in fake.records.values() if r["name"] == "blog.example.app")
    assert new == {"type": "A", "name": "blog.example.app", "content": "198.51.100.7", "ttl": 1, "proxied": True, "id": new["id"]}
    assert press("add-z1", "add", 'TXT @ "google-site-verification=abc 123"')["ok"]
    assert any(r["content"] == "google-site-verification=abc 123" and r["name"] == "example.app" for r in fake.records.values())
    assert press("add-z1", "add", "MX @ 10 mail.example.app")["ok"]
    assert any(r.get("priority") == 10 and r["content"] == "mail.example.app" for r in fake.records.values())
    assert "MX value" in press("add-z1", "add", "MX @ mail.example.app")["error"]

    res = press("r1", "change", "203.0.113.9")
    assert res["ok"] and "was 93.184.216.34" in res["message"] and fake.records["r1"]["content"] == "203.0.113.9"
    assert press("r1", "proxy")["ok"] and fake.records["r1"]["proxied"] is True
    assert press("r3", "proxy")["error"] == "TXT records can't be proxied"
    assert press("r2", "delete")["ok"] and "r2" not in fake.records
    assert "isn't there any more" in press("r2", "delete")["error"]
    assert press("r1", "change")["error"] == "type the new value"

    changes = [e["meta"] for e in jobs.read_events(fleet) if e["event"] == "dns-change"]
    assert [c["action"] for c in changes] == ["added", "added", "added", "changed", "changed", "deleted"]
    assert changes[3]["before"]["content"] == "93.184.216.34" and changes[3]["after"]["content"] == "203.0.113.9"
    assert changes[5]["before"]["name"] == "www.example.app" and changes[5]["after"] is None


def test_dns_records_is_a_capability_cloudflare_provides(fleet, monkeypatch):
    cf, ctx, fake = cloudflare_on(monkeypatch)
    with pytest.raises(addons.AddonError, match="provides dns records"):
        addons.capability("dns_records")
    addons.enable("cloudflare")
    addon, mod, ents = addons.capability("dns_records")
    assert addon.name == "cloudflare"
    assert [r["type"] for r in mod.list_records(ents, ctx, "example.app")] == ["A", "CNAME", "TXT"]
    assert mod.list_records(ents, ctx, "www.example.app")[0]["content"] == "example.app"
    # A: the one record is changed in place; the same value again changes nothing
    res = mod.set_record(ents, ctx, "example.app", "A", "203.0.113.9")
    assert res["ok"] and res["changed"] and fake.records["r1"]["content"] == "203.0.113.9"
    assert mod.set_record(ents, ctx, "example.app", "A", "203.0.113.9")["changed"] is False
    res = mod.set_record(ents, ctx, "new", "A", "198.51.100.1")   # short names belong to... nothing
    assert "none of your Cloudflare domains holds new" in res["error"]
    assert mod.set_record(ents, ctx, "api.example.app", "AAAA", "2001:db8::1", proxied=True)["changed"]
    # TXT: added next to the existing one, not replacing it
    assert mod.set_record(ents, ctx, "example.app", "TXT", "google-site-verification=x")["changed"]
    assert sorted(r["content"] for r in fake.records.values() if r["type"] == "TXT") == ["google-site-verification=x", "v=spf1 -all"]
    assert mod.set_record(ents, ctx, "example.app", "TXT", "v=spf1 -all")["changed"] is False
    # delete: by value, or all of that type
    assert mod.delete_record(ents, ctx, "example.app", "TXT", "v=spf1 -all")["changed"]
    assert [r["content"] for r in fake.records.values() if r["type"] == "TXT"] == ["google-site-verification=x"]
    assert mod.delete_record(ents, ctx, "nope.example.app", "A")["changed"] is False
    assert mod.delete_record(ents, ctx, "www.example.app", "CNAME")["changed"] and "r2" not in fake.records


def test_hisho_dns_shows_what_is_there_and_asks_before_changing(fleet, monkeypatch, capsys):
    from hisho import cli
    cf, ctx, fake = cloudflare_on(monkeypatch)
    addons.enable("cloudflare")
    monkeypatch.setattr(addons.Context, "secret", lambda self, n: "t")
    assert cli.run(["dns", "list", "example.app"]) == 0
    out = capsys.readouterr().out
    assert "CNAME  www.example.app" in out and "(proxied)" in out
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    assert cli.run(["dns", "set", "example.app", "A", "203.0.113.9"]) == 2
    assert "--yes" in capsys.readouterr().err and fake.records["r1"]["content"] == "93.184.216.34"
    assert cli.run(["dns", "set", "example.app", "A", "203.0.113.9", "--yes"]) == 0
    assert fake.records["r1"]["content"] == "203.0.113.9"
    assert cli.run(["dns", "delete", "www.example.app", "CNAME", "--yes"]) == 0 and "r2" not in fake.records


def test_hisho_writes_the_secret_comment_the_sop_asks_for(fleet, monkeypatch, stand_in):
    from hisho import secret_notes
    cf, ctx, fake = cloudflare_on(monkeypatch)
    addons.set_entry(cf, "main", {"token": "CLOUDFLARE_X_API_TOKEN"})
    pg = stand_in("pangolin", kind="integration", title="Pangolin",
                  entry_schema={"url": "url", "api_url": "url?", "api_key": "password", "org": "str?"})
    addons.set_entry(pg, "offsite", {"url": "https://p.example.com", "api_url": "https://api.example.com/v1",
                                   "api_key": "CLOUDFLARE_X_API_TOKEN", "org": "acme"})
    monkeypatch.setattr(addons.Context, "secret", lambda self, n: "t")
    real = fake.__call__

    def with_tokens(req, timeout=0):
        import io, json as _json

        class Resp(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False
        path = req.full_url.split("/v4", 1)[1]
        if path == "/user/tokens/verify":
            return Resp(_json.dumps({"success": True, "result": {"id": "tok1", "status": "active"}}).encode())
        if path == "/user/tokens/tok1":
            return Resp(_json.dumps({"success": True, "result": {"name": "hisho-kihon", "policies": [
                {"effect": "allow", "resources": {"com.cloudflare.api.account.abc": {"com.cloudflare.api.account.zone.*": "*"}},
                 "permission_groups": [{"name": "Zone Read"}, {"name": "DNS Write"}]}]}}).encode())
        return real(req, timeout)
    monkeypatch.setattr("urllib.request.urlopen", with_tokens)
    text = secret_notes.draft("CLOUDFLARE_X_API_TOKEN", added="2026-10-18")
    assert text.splitlines() == [
        'What: Cloudflare API token "hisho-kihon", all zones (example.app). DNS Write, Zone Read.',
        "Used by: Hisho Cloudflare add-on, entry main; Hisho Pangolin add-on, entry offsite.",
        "Rotate: dash.cloudflare.com > My Profile > API Tokens > the token > Roll, then update this value.",
        "Added: 2026-10-18"]
    # a secret nothing uses still gets the shape to fill in
    assert secret_notes.draft("NOPE_TOKEN").splitlines()[1] == "Used by: <nothing in Hisho names it yet>."
    # fill writes only when Infisical has no comment yet
    store = {"CLOUDFLARE_X_API_TOKEN": ""}
    monkeypatch.setattr(secret_notes, "current", lambda n: store[n])
    monkeypatch.setattr(secret_notes, "write", lambda n, c: store.__setitem__(n, c))
    assert secret_notes.fill("CLOUDFLARE_X_API_TOKEN")["written"] and store["CLOUDFLARE_X_API_TOKEN"].startswith("What: Cloudflare")
    store["CLOUDFLARE_X_API_TOKEN"] = "mine"
    assert secret_notes.fill("CLOUDFLARE_X_API_TOKEN")["written"] is False and store["CLOUDFLARE_X_API_TOKEN"] == "mine"


def test_cloudflare_keys_and_exposure_review(fleet, monkeypatch):
    import datetime as dt
    cf, ctx, fake = cloudflare_on(monkeypatch)
    allow = lambda *names, res=None: [{"effect": "allow", "resources": res or {"com.cloudflare.api.account.zone.z1": "*"},
                                       "permission_groups": [{"name": n} for n in names]}]
    fake.extra.update({
        "/user/tokens?per_page=50": [
            {"id": "tok1", "name": "Hisho-Kihon", "status": "active", "last_used_on": "2026-10-19T02:00:00Z",
             "policies": allow("DNS Write", "Zone Read", res={"com.cloudflare.api.account.a1": {"com.cloudflare.api.account.zone.*": "*"}})},
            {"id": "tok2", "name": "Edit zone DNS", "status": "active", "last_used_on": "2024-12-09T09:10:12Z",
             "policies": allow("DNS Write", "Zone Read")},
            {"id": "tok3", "name": "Edit zone DNS", "status": "active", "last_used_on": "2026-10-10T00:00:00Z",
             "expires_on": "2027-01-01T00:00:00Z", "condition": {"request_ip": {"in": ["198.51.100.0/24"]}},
             "policies": allow("Zone Read")},
            {"id": "tok4", "name": "site build", "status": "active", "last_used_on": None,
             "policies": allow("D1 Write", "Workers Scripts Write", "Workers KV Storage Write", "Queues Write",
                               "Workers R2 Storage Write", res={"com.cloudflare.api.account.a1": "*"})}],
        "/accounts?per_page=5": [{"id": "a1"}],
        "/accounts/a1/security-center/insights?per_page=100": {"issues": [
            {"issue_class": "security_txt_not_enabled", "severity": "Low", "subject": "example.app", "status": "active", "dismissed": False},
            {"issue_class": "exposed_infrastructure", "issue_type": "exposed_infrastructure", "severity": "Moderate",
             "subject": "ssh.example.app", "status": "active", "dismissed": False},
            {"issue_class": "old_thing", "severity": "Low", "subject": "x", "status": "active", "dismissed": True}]}})
    mod = addons.provider(cf)
    now = dt.datetime(2026, 10, 19, 3, tzinfo=dt.timezone.utc)
    items = mod.token_items(addons.entries(cf)["main"], ctx, now=now)
    toks = {i["name"]: i for i in items}
    assert toks["token  Hisho-Kihon"]["state"] == "up" and "This is Hisho's own token." in toks["token  Hisho-Kihon"]["facts"]
    assert "all zones/account" in toks["token  Hisho-Kihon"]["facts"][0]
    stale = next(i for i in items if "Not used for 678 days" in " ".join(i["facts"]))
    assert stale["state"] == "warn" and "some zones" in stale["facts"][0]
    assert any("same name" in f for f in stale["facts"])
    build = toks["token  site build"]
    assert build["state"] == "warn" and any("Never used" in f for f in build["facts"]) and any("Broad" in f for f in build["facts"])
    assert "all zones/account" in build["facts"][0]
    review = addons.details(cf, ctx)[0]
    names = [i["name"] for i in review["items"]]
    assert "server 93.184.216.34" in names
    assert "Security Center  security.txt isn't set up" in names
    exposed = next(i for i in review["items"] if "exposed infrastructure" in i["name"])
    assert exposed["state"] == "warn" and "ssh.example.app" in exposed["facts"][1]
    assert not any("old thing" in n for n in names)          # dismissed findings stay hidden
    assert review["state"] == "warn" and "Hisho never makes, changes or revokes tokens" in review["facts"][1]


def test_a_server_left_unproxied_on_purpose_stops_warning(fleet, monkeypatch):
    cf, ctx, fake = cloudflare_on(monkeypatch)
    server = lambda: next(i for i in addons.details(cf, ctx)[0]["items"] if i["name"] == "server 93.184.216.34")
    assert server()["state"] == "warn" and server()["actions"][0]["label"] == "on purpose"
    assert addons.act(cf, "main", "ip-93.184.216.34", "expected", ctx=ctx)["ok"]
    assert addons.entries(cf)["main"] == {"token": "HISHO_CF", "exposed_ok": "93.184.216.34"}
    ctx = addons.Context(cf, resolve=lambda n: "t")
    assert server()["state"] == "off" and "on purpose" in server()["facts"][0]
    assert addons.details(cf, ctx)[0]["state"] == "ok"
    addons.act(cf, "main", "ip-93.184.216.34", "expected", ctx=ctx)
    assert addons.entries(cf)["main"]["exposed_ok"] == ""
