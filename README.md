# CF0T-Manager

A small web page, running in Docker on your NAS, that manages your Cloudflare
Zero Trust setup. One form adds a hostname: tunnel route, Access application and
policy in a single submit. Nothing that already exists is overwritten without
asking first.

## Why

Adding one service to Cloudflare Zero Trust means three screens in the dashboard:
a published application route on the tunnel, an Access application for the
hostname, and a policy attached to it. Miss one and you either get a 502, a 1016,
or a hostname anyone on the internet can reach. This puts the three together.

## What adding an application does

For each hostname the tool:

1. adds the **tunnel route**, hostname to origin, keeping the `http_status:404`
   catch-all last where cloudflared expects it,
2. creates the **Access application** and attaches the policies you picked, in
   the order you picked them,
3. creates the **DNS CNAME** to `<tunnel>.cfargotunnel.com`, proxied.

Step 3 is a checkbox: switch it off if you already have a wildcard CNAME. If a
record is there already and points somewhere else, you get a screen with the old
and the new value and decide yourself.

## The page

Open `http://<your-nas-ip>:8099`. Four tabs:

- **Applications** — every hostname on the tunnel, with its origin, Access app,
  policies and DNS status. Search filters as you type. A record still pointing at
  the tunnel without a route or application behind it is flagged *unused DNS*, so
  leftovers from a rename do not go unnoticed. Exports to Excel or CSV.
- **New application** — the form above. Subdomain plus a domain dropdown, origin
  as protocol/host/port, and the advanced origin options cloudflared supports:
  `noTLSVerify` for a self-signed origin like Proxmox, HTTP/2, host header,
  connect timeout.
- **Backup** — download the whole configuration, or keep copies in `/data`.
  Restoring always shows the difference first.
- **Settings** — API token, which tunnel to manage, your password, session
  length, and the backup schedule.

Deleting is its own screen: tick what should go — route, application, DNS record
— and nothing else is touched.

## Getting it working

### 1. A Cloudflare API token

Dashboard → *My Profile* → *API Tokens* → *Create Token* → *Create Custom Token*:

| Scope | Permission | Level |
|---|---|---|
| Account | Cloudflare Tunnel | Edit |
| Account | Access: Apps and Policies | Edit |
| Zone | DNS | Edit *(optional, for DNS records)* |
| Zone | Zone | Read *(optional, for the domain dropdown)* |

Copy it straight away, it is shown once. You also need your **Account ID**, in
the right-hand column of the Cloudflare dashboard.

A passkey on your account changes nothing here: a passkey protects dashboard
login, an API token is a separate key. Cloudflare may ask for the passkey once
while you create the token.

### 2. One folder on your NAS

For the configuration and the backups, for example:

```
/share/CACHEDEV1_DATA/Docker/cf0t-manager/data
```

You do not have to prepare it: the container starts as root, hands the folder to
`PUID`/`PGID` and only then drops to that user. If your share refuses that, the
page says so when you try to save instead of quietly forgetting your settings.

### 3. Start the container

In Portainer: *Stacks* → *Add stack* → *Web editor*, paste `docker-compose.yml`
from this repo. The short version, with everything you need to change:

```yaml
version: "3"

services:
  cf0t-manager:
    container_name: cf0t-manager
    image: ghcr.io/terrorsource/cf0t-manager:latest
    init: true
    restart: unless-stopped
    network_mode: bridge
    environment:
      - TZ=Europe/Amsterdam               # otherwise times are shown in UTC
      - PUID=1000                         # run as this user, so the files are yours
      - PGID=1000
    ports:
      - 8099:8080
    volumes:
      - /share/CACHEDEV1_DATA/Docker/cf0t-manager/data:/data
```

- No token, no password, no account ID here: the page asks for all three the
  first time you open it and keeps them in `/data`. Put them in the stack as
  `CF_API_TOKEN`, `CF_ACCOUNT_ID` and `CF0T_PASSWORD` if you would rather keep
  secrets in Portainer; set that way they become read-only in the page.
- `PUID` / `PGID` — the user the container runs as, so the files it writes on
  the NAS belong to you. The mounted folder is handed to this user at startup.
  Set `PUID=0` to stay root.
- The folder path — the one from step 2.
- `TZ` only affects displayed times, for instance in the backup list.

The image is published to GitHub Container Registry, and packages there are
**private** by default. Either set the package to public under *Package
settings* → *Change visibility*, or run `docker login ghcr.io` on the NAS with a
token that has `read:packages`.

### 4. Finish setup in the browser

Open `http://<your-nas-ip>:8099`. The first-run wizard asks for a password, your
API token and your account ID, checks them against Cloudflare before storing
anything, and logs you in. One tunnel on the account is selected for you.

## Backups

A backup holds every ingress rule on the tunnel, all Access applications and the
reusable policies. Three kinds are kept in `/data/backups`:

- **automatic** — every 24 hours. The schedule looks at how old the newest one
  is rather than sleeping a full day, so a restart never skips or doubles a run.
- **before a delete** — written before an application is removed. If that backup
  fails, the delete stops and asks whether to go ahead without one.
- **by hand** — the button on the Backup page.

Both automatic kinds are on by default; interval, retention and the switches are
under Settings. Restoring puts routes back and recreates missing applications
with everything the backup holds, after showing you what would change. DNS is
never part of a restore.

## When something goes wrong

- **Error 1016** — the hostname has no DNS record pointing at the tunnel. Open
  *Edit* for it, tick the CNAME checkbox and save.
- **A hostname that worked is suddenly NXDOMAIN** — the record is back but your
  resolver cached the old answer. Cloudflare keeps negative answers for 30
  minutes; on a Pi-hole, *Settings* → *System* → *Restart DNS resolver*.
- **502 on a self-signed origin** — tick *Don't verify the origin's TLS
  certificate* under the advanced origin options.
- **No tunnels, or no domain dropdown** — the token is missing
  *Cloudflare Tunnel: Edit* or *Zone: Read*.
- **Settings do not survive a restart** — the container could not take ownership
  of the mounted folder. The log says so at startup; `chown -R 1000:1000` on the
  folder from the NAS side fixes it.

## Safety

The page can delete routes, applications and DNS records, so give it a real
password and **do not open port 8099 to the internet**. Better: add it to
Cloudflare Zero Trust as an application of its own, behind your usual policy,
and switch on *Only send the session cookie over https* under Settings.

Your API token sits in `config.json` in the mounted folder, readable only by the
container user, the same as it would be in a `.env`. Treat that folder as a
secret. Your password is stored as an scrypt hash and never in a recoverable
form; changing it signs out every other session. Nothing is in the image or in
this repository.

## For developers

Python + FastAPI with server-rendered Jinja templates, talking to the Cloudflare
`client/v4` API over httpx. Three things that each cost an evening:

- Updating an Access application is a **PUT that replaces the whole object**, and
  there is no PATCH. Send only the fields you care about and `allowed_idps`,
  `auto_redirect_to_identity` and the custom pages silently fall back to their
  defaults, which turns a Google-only application into one that accepts every
  identity provider. Always read the application first and change only your own
  fields.
- The same goes for the tunnel configuration: the PUT replaces the entire ingress
  list, and the catch-all entry has to stay last or cloudflared matches nothing.
- Applications take **reusable policies** by `{id, precedence}`; reusable and
  inline policies are mutually exclusive in one request.

The overview costs four or five calls, so they run in parallel and the result is
cached for a minute, dropped on every write. Filtering is done in the browser.

## Disclaimer

The tool changes live Cloudflare configuration, including deleting routes,
applications and DNS records. It asks before anything destructive and backs up
first, but using it is your own risk. Provided as-is, no warranty.

## License

[MIT](LICENSE).
