# CFZeroTrustControl

Kleine Docker-container met een web-UI om je Cloudflare Zero Trust omgeving te beheren.
Eén formulier zet in één keer de **tunnel-route**, de **Access-applicatie** en de **policy** goed —
in plaats van drie losse schermen in het Cloudflare-dashboard.

## Wat kun je ermee

| | |
|---|---|
| **Overzicht** | Alle hostnames van de tunnel naast hun Access-app, policies en DNS-status. Eén tabel, zoekbaar. |
| **Toevoegen** | Hostname + origin (bv. `http://192.168.1.9:8096`) → tunnel-route, Access-app en gekozen policy(s) in één flow. Optioneel meteen het DNS CNAME. |
| **Bewerken** | Origin, pad, origin-opties, app-naam, sessieduur en policies aanpassen. Access-app aan/uit zetten. |
| **Verwijderen** | Per onderdeel aanvinken: route, Access-app en/of DNS-record. |
| **Backup** | Alles als JSON exporteren; terugzetten gaat via een vergelijkingsscherm, dus je ziet eerst wat er verandert. |
| **Login** | Eén wachtwoord, ondertekende sessiecookie. |

## 1. API-token maken

Cloudflare dashboard → **My Profile → API Tokens → Create Token → Create Custom Token**:

| Scope | Permissie | Niveau |
|---|---|---|
| Account | Cloudflare Tunnel | Edit |
| Account | Access: Apps and Policies | Edit |
| Zone | DNS | Edit *(optioneel — voor DNS-records)* |
| Zone | Zone | Read *(optioneel — voor de domein-dropdown)* |

Zonder de twee Zone-permissies werkt alles behalve de DNS-kolom en de DNS-checkbox.
Je **Account ID** staat in het Cloudflare-dashboard in de rechterkolom (of in de URL van Zero Trust).

### Passkey op je account?

Dat is geen probleem. Een passkey beveiligt het **inloggen op het dashboard**; een API-token is
een losse sleutel met z'n eigen permissies. De token-header `Authorization: Bearer …` gaat niet
door 2FA of passkey-verificatie heen — dat zou API's ook onbruikbaar maken. In de praktijk:

- Je logt met je passkey in op het dashboard en maakt daar het token aan. Cloudflare kan je
  tijdens dat aanmaken nog één keer om je passkey vragen; daarna krijg je het token te zien.
- **Kopieer het token meteen** — het wordt daarna nooit meer getoond.
- Gebruik een **API-token**, niet de Global API Key. Een token is beperkt tot de permissies
  hierboven en kun je los intrekken zonder je accountwachtwoord te wijzigen.

## 2. Lokaal draaien

```bash
cp .env.example .env
```

Vul minimaal `CF_API_TOKEN`, `CF_ACCOUNT_ID` en `CFZT_PASSWORD` in. Een sessie-sleutel genereer je met
`openssl rand -hex 32` (laat je `CFZT_SECRET_KEY` leeg, dan maakt de container er zelf één aan).

```bash
docker compose up -d --build
```

Open daarna http://localhost:8099. Heb je meerdere tunnels, dan kies je bij **Instellingen**
welke je wilt beheren (of zet `CF_TUNNEL_ID` vast in `.env`).

## 3. Op GitHub zetten

```bash
git remote add origin git@github.com:<jouw-naam>/<repo-naam>.git
git push -u origin main
```

`.env` staat in `.gitignore`, dus je token gaat niet mee. In de repo zitten twee workflows:

- **Tests** — draait de pytest-suite bij elke push en pull request.
- **Build and publish image** — bouwt bij elke push naar `main` een multi-arch image
  (amd64 + arm64) en publiceert die naar `ghcr.io/<jouw-naam>/<repo-naam>:latest`.

Na de eerste build staat de image onder **Packages** bij je repo. Standaard is die privé;
wil je hem publiek, zet dat dan om via Package settings → Change visibility. Je NAS moet
anders eerst `docker login ghcr.io` doen met een personal access token (scope `read:packages`).

## 4. Draaien in Portainer op je NAS

Twee smaken — kies er één.

### A. Stack vanuit de Git-repo (bouwt op de NAS)

**Stacks → Add stack → Repository**

| Veld | Waarde |
|---|---|
| Repository URL | `https://github.com/<jouw-naam>/<repo-naam>` |
| Compose path | `docker-compose.yml` |

Vul onder **Environment variables** in: `CF_API_TOKEN`, `CF_ACCOUNT_ID`, `CFZT_PASSWORD`,
`CFZT_SECRET_KEY` en eventueel `CF_TUNNEL_ID` en `CFZT_PORT`. Daarna **Deploy the stack**.

Zet je "Automatic updates" aan, dan haalt Portainer nieuwe commits automatisch op.

### B. Kant-en-klare image van GHCR (bouwt niets)

Sneller, en prettiger voor een NAS met weinig CPU. **Stacks → Add stack → Web editor**,
plak de inhoud van [`docker-compose.ghcr.yml`](docker-compose.ghcr.yml), en zet onder
**Environment variables** in elk geval:

| Variabele | Waarde |
|---|---|
| `CFZT_IMAGE` | `ghcr.io/<jouw-naam>/<repo-naam>:latest` |
| `CF_API_TOKEN` | je Cloudflare API-token |
| `CF_ACCOUNT_ID` | je Cloudflare account-ID |
| `CFZT_PASSWORD` | wachtwoord voor de web-UI |
| `CFZT_SECRET_KEY` | uitvoer van `openssl rand -hex 32` |

De stack gebruikt een named volume `cfzt-data` voor `/data`, zodat je geen gedoe hebt met
rechten op een bind-mount. Portainer toont de health-status van de container zodra hij draait.

### De tool zelf achter Zero Trust zetten

Leuke eerste test: voeg de tool met zichzelf toe.

1. **Nieuwe applicatie** → hostname `cfzt`, domein `makooy.nl`
2. Origin: `http` · host = IP van je NAS · poort `8099`
3. Access-applicatie aan, policy `GoogleIDP-Marc-Policy`
4. Opslaan

Daarna is `https://cfzt.makooy.nl` bereikbaar achter je eigen IdP. Zet in dat geval
`CFZT_SECURE_COOKIE=1`.

## Environment variables

| Variabele | Verplicht | Uitleg |
|---|---|---|
| `CF_API_TOKEN` | ja | Cloudflare API-token (zie hierboven) |
| `CF_ACCOUNT_ID` | ja | Cloudflare account-ID |
| `CF_TUNNEL_ID` | nee | Vastzetten op één tunnel; leeg = kiezen in de UI |
| `CFZT_PASSWORD` | aanbevolen | Wachtwoord voor de web-UI; leeg = geen login |
| `CFZT_SECRET_KEY` | nee | Sleutel voor sessiecookies; leeg = automatisch gegenereerd in `/data/secret.key` |
| `CFZT_SESSION_HOURS` | nee | Hoe lang je ingelogd blijft (standaard 12) |
| `CFZT_SECURE_COOKIE` | nee | `1` als de tool alleen via https bereikbaar is |
| `CFZT_DEFAULT_ORIGIN_HOST` | nee | Voorinvulling van het Host/IP-veld |
| `CFZT_PORT` | nee | Poort op de host (standaard 8099) |
| `CFZT_IMAGE` | alleen bij GHCR | Welke image gepulld wordt |

## Hoe het onder water werkt

- **Tunnel-routes**: de Cloudflare API vervangt bij een wijziging de *hele* ingress-lijst.
  De tool leest daarom altijd eerst de actuele config, past één regel aan en houdt de
  catch-all (`http_status:404`) gegarandeerd als laatste regel. Bestaat die niet, dan wordt
  hij toegevoegd.
- **Access-apps** worden gekoppeld via *reusable policies*: dezelfde policies die je in
  Zero Trust → Access controls → Policies hebt staan, met precedence in de volgorde waarin
  je ze selecteert.
- **Mislukt er een stap halverwege?** Dan vertelt de foutmelding precies welke stappen wél
  gelukt zijn, zodat je weet wat je nog moet opruimen.

## API

Voor scripting is er één JSON-endpoint (zelfde sessiecookie-login):

```
GET /api/services   # alle hostnames met service, access-app, policies en dns-status
GET /healthz        # health check, geen login nodig
```

## Data

In het volume `/data` staan:

- `state.json` — de gekozen tunnel
- `secret.key` — automatisch gegenereerde cookie-sleutel als je er geen opgeeft

Backups download je zelf; die worden niet op de server bewaard.

## Tests

De testsuite draait tegen een nagebootste Cloudflare-API (geen echte calls), en dekt
aanmaken, bewerken, verwijderen, de backup-roundtrip en de login:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
.venv/bin/python -m pytest tests/ -q
```
