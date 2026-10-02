# CFZeroTrustControl

A small web UI to manage Cloudflare Zero Trust. Adding an app normally means three separate
screens in the Cloudflare dashboard — tunnel route, Access application, policy. Here it's one form.

- **Overview** — every tunnel hostname with its origin, Access app, policies and DNS status
- **Add** — creates the tunnel route, the Access application and attaches your policies in one go
- **Edit / delete** — change the origin or policies; delete route, app and DNS record selectively
- **Backup** — export everything as JSON, restore with a diff screen first
- **Self-configuring** — token, account, password and preferences are all set in the UI

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

Copy the token immediately — it is shown only once. You also need your **Account ID**, in the
right-hand column of the Cloudflare dashboard.

> **Using a passkey on your account?** No problem. A passkey protects dashboard login; an API
> token is a separate key and is not subject to 2FA. Cloudflare may ask for your passkey once
> while creating the token.

### Step 2 — Start the container

```bash
docker compose up -d --build
```

No configuration file needed.

### Step 3 — Finish setup in the browser

Open **http://localhost:8099**. The first-run wizard asks for a password, your API token and your
account ID, verifies them against Cloudflare, and logs you in. If you have a single tunnel it's
selected for you.

That's it. **New application** now creates a route, an Access app and its policies in one submit.

Everything stays changeable under **Settings**: replace the token, switch tunnels, change your
password, adjust session length and the default origin host.

---

## Running it on a NAS with Portainer

First push this repo to GitHub. The included workflow builds a multi-arch image (amd64 + arm64)
and publishes it to `ghcr.io/<you>/<repo>` on every push to `main`.

```bash
git remote add origin git@github.com:<you>/<repo>.git
git push -u origin main
```

Then in Portainer, **Stacks → Add stack → Web editor**, paste
[`docker-compose.ghcr.yml`](docker-compose.ghcr.yml), and set one variable:

| Variable | Value |
|---|---|
| `CFZT_IMAGE` | `ghcr.io/<you>/<repo>:latest` |

Deploy, open the UI on port 8099, and run through the wizard. Nothing is built on the NAS and no
secrets live in the stack definition.

> GHCR packages are **private** by default. Either make the package public under
> *Package settings → Change visibility*, or run `docker login ghcr.io` on the NAS with a
> personal access token that has the `read:packages` scope.

**Prefer to build on the NAS instead?** Use **Add stack → Repository** with your repo URL and
`docker-compose.yml` as the compose path.

---

## Optional environment variables

Everything can be set in the UI, so none of these are required. Anything you do set wins over the
stored config and shows up as read-only on the Settings page — handy if you'd rather keep secrets
in your orchestrator.

| Variable | Description |
|---|---|
| `CF_API_TOKEN` | Cloudflare API token |
| `CF_ACCOUNT_ID` | Cloudflare account ID |
| `CF_TUNNEL_ID` | Pin to one tunnel instead of choosing in the UI |
| `CFZT_PASSWORD` | Fixed login password instead of the one managed in the UI |
| `CFZT_SECRET_KEY` | Session cookie key; generated in `/data/secret.key` if unset |
| `CFZT_DISABLE_LOGIN` | `1` runs without any login — only on a trusted network |
| `CFZT_PORT` | Host port (default 8099) |
| `CFZT_IMAGE` | Which image to pull (GHCR compose file only) |

---

## Good to know

**Put the tool behind its own Zero Trust policy.** Add an application pointing at
`http://<nas-ip>:8099`, attach your usual policy, and turn on *Only send the session cookie over
https* under Settings.

**Where your data lives.** The `/data` volume holds `config.json` (API token, account ID, selected
tunnel, preferences and the scrypt hash of your password) and `secret.key`. The token is stored in
plain text with `0600` permissions, the same as it would be in a `.env` — treat the volume as a
secret. Your password is never stored in a recoverable form, and changing it signs out every other
session.

**Tunnel routes are replaced as a whole** by the Cloudflare API. The tool always reads the current
config first, changes one rule, and keeps the `http_status:404` catch-all last — it adds one if
it's missing.

**If a step fails halfway**, the error names the steps that did succeed, so you know what to clean
up.

**JSON endpoints:** `GET /api/services` (needs login) and `GET /healthz` (doesn't).

---

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
.venv/bin/python -m pytest tests/ -q
```

The tests run against a mocked Cloudflare API and cover the first-run wizard, login and password
changes, creating, editing and deleting applications, and the backup roundtrip.
