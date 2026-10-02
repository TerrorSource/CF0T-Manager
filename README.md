# CFZeroTrustControl

A small web UI to manage Cloudflare Zero Trust. Adding an app normally means three separate
screens in the Cloudflare dashboard — tunnel route, Access application, policy. Here it's one form.

- **Overview** — every tunnel hostname with its origin, Access app, policies and DNS status
- **Add** — creates the tunnel route, the Access application and attaches your policies in one go
- **Edit / delete** — change the origin or policies; delete route, app and DNS record selectively
- **Backup** — export everything as JSON, restore with a diff screen first
- **Login** — one password, signed session cookie

---

## Setup

### Step 1 — Create a Cloudflare API token

Dashboard → **My Profile → API Tokens → Create Token → Create Custom Token**

| Scope | Permission | Level |
|---|---|---|
| Account | Cloudflare Tunnel | Edit |
| Account | Access: Apps and Policies | Edit |
| Zone | DNS | Edit *(optional, for DNS records)* |
| Zone | Zone | Read *(optional, for the domain dropdown)* |

Copy the token immediately — it is shown only once.

You also need your **Account ID**: it's in the right-hand column of the Cloudflare dashboard.

> **Using a passkey on your account?** No problem. A passkey protects dashboard login; an API
> token is a separate key and is not subject to 2FA. Cloudflare may ask for your passkey once
> while creating the token.

### Step 2 — Configure

```bash
cp .env.example .env
```

Fill in `CF_API_TOKEN`, `CF_ACCOUNT_ID` and `CFZT_PASSWORD`. Everything else has sane defaults.

### Step 3 — Start

```bash
docker compose up -d --build
```

### Step 4 — Open it

Go to **http://localhost:8099** and log in. If you have more than one tunnel, pick the one you
want to manage under **Instellingen** (Settings); with a single tunnel it's selected automatically.

That's it. **Nieuwe applicatie** (New application) now creates a route, an Access app and its policies in one submit.

---

## Running it on a NAS with Portainer

First push this repo to GitHub. The included workflow builds a multi-arch image (amd64 + arm64)
and publishes it to `ghcr.io/<you>/<repo>` on every push to `main`.

```bash
git remote add origin git@github.com:<you>/<repo>.git
git push -u origin main
```

Then in Portainer, **Stacks → Add stack → Web editor**, paste
[`docker-compose.ghcr.yml`](docker-compose.ghcr.yml), and set these under *Environment variables*:

| Variable | Value |
|---|---|
| `CFZT_IMAGE` | `ghcr.io/<you>/<repo>:latest` |
| `CF_API_TOKEN` | your Cloudflare API token |
| `CF_ACCOUNT_ID` | your Cloudflare account ID |
| `CFZT_PASSWORD` | password for the web UI |

Deploy. Nothing is built on the NAS — the image is just pulled.

> GHCR packages are **private** by default. Either make the package public under
> *Package settings → Change visibility*, or run `docker login ghcr.io` on the NAS with a
> personal access token that has the `read:packages` scope.

**Prefer to build on the NAS instead?** Use **Add stack → Repository** with your repo URL and
`docker-compose.yml` as the compose path, and set the same variables.

---

## Configuration

| Variable | Required | Description |
|---|---|---|
| `CF_API_TOKEN` | yes | Cloudflare API token |
| `CF_ACCOUNT_ID` | yes | Cloudflare account ID |
| `CFZT_PASSWORD` | recommended | Web UI password; empty means no login |
| `CF_TUNNEL_ID` | no | Pin to one tunnel; empty means choose in the UI |
| `CFZT_SECRET_KEY` | no | Session cookie key; generated in `/data/secret.key` if empty |
| `CFZT_SESSION_HOURS` | no | How long you stay logged in (default 12) |
| `CFZT_SECURE_COOKIE` | no | Set to `1` when reaching the tool over https only |
| `CFZT_DEFAULT_ORIGIN_HOST` | no | Prefills the Host/IP field in the form |
| `CFZT_PORT` | no | Host port (default 8099) |
| `CFZT_IMAGE` | GHCR only | Which image to pull |

---

## Good to know

**Put the tool behind its own Zero Trust policy.** Add an application pointing at
`http://<nas-ip>:8099`, attach your usual policy, and set `CFZT_SECURE_COOKIE=1`.

**Tunnel routes are replaced as a whole** by the Cloudflare API. The tool always reads the
current config first, changes one rule, and keeps the `http_status:404` catch-all last — it adds
one if it's missing.

**If a step fails halfway**, the error names the steps that did succeed, so you know what to
clean up.

**JSON endpoints:** `GET /api/services` (needs login) and `GET /healthz` (doesn't).

**Data** lives in the `/data` volume: the selected tunnel and the generated cookie key. Backups
are downloaded to your machine, never stored on the server.

---

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
.venv/bin/python -m pytest tests/ -q
```

The tests run against a mocked Cloudflare API and cover creating, editing, deleting, the backup
roundtrip and login.
