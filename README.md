# Cloudflare (Hisho add-on)

## What it does

Shows your Cloudflare domains (zones): their DNS records, which are proxied through Cloudflare and
which point straight at a server, the SSL mode and certificate problems, and whether a server's
address is left exposed. Records can be added, changed, proxied or deleted on its page (each asks
first, and every change goes to the journal with the old value), with `hisho dns`, or by other
add-ons through the `dns_records` capability it provides.

## What it needs

- You need:
  - A Cloudflare account with your domains on it
  - A Cloudflare API token (Zone:Read, DNS:Edit, Zone Settings:Read, SSL and Certificates:Read)
- Runs on: the Core machine, inside Hisho Core
- One entry per Cloudflare token, each with:
  - `token` (password, kept as a local secret, required)
  - `note` (str, optional)
  - `exposed_ok` (str, optional)
- Provides: `dns_records`

## How to install

On the dashboard: **Add-ons > Store > Cloudflare > Install**. Or from a terminal:

```bash
hisho addon install cloudflare
```

Hisho takes the newest version from this repository and turns it on inside Hisho Core. Updates show as **Update
available** on its Store card; **Roll back** returns to the version before.

## How to use

Its card names any domain with an exposed server or an SSL problem. Its page (**Add-ons > Cloudflare**) lists every domain and its records; **add**, **edit**, **proxy** and **delete** ask first and keep the old value in the journal. From a terminal: `hisho dns`.

## Settings

One entry per Cloudflare API token. Make the token at dash.cloudflare.com > My Profile > API
Tokens > Custom token with Zone:Read, DNS:Edit, Zone Settings:Read and SSL and Certificates:Read
on all zones (DNS:Read instead of Edit keeps it read-only). Paste it on the page, or give its
secret's name. Entries are kept in `~/Hisho/System/Config/Addons/cloudflare.yaml`. To rotate:
dash.cloudflare.com > My Profile > API Tokens > the token > Roll.

## How to remove

**Add-ons > Store > Cloudflare > Remove**, or `hisho addon remove cloudflare`. Its card and page go away; your settings stay in `~/Hisho/System/Config/Addons/cloudflare.yaml`, so installing it again picks up where you left off.

## License

Source-available under the [PolyForm Shield License 1.0.0](LICENSE.md): free to use, change and share,
for any purpose except offering a product that competes with Hisho (reselling it, for example).
