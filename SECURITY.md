# Security

## Reporting a problem

Open a [security advisory](https://github.com/TerrorSource/CF0T-Manager/security/advisories/new)
rather than a public issue, and give it a few days before saying anything in public.

## What this tool holds

The `/data` volume holds your Cloudflare API token in `config.json`, readable only by the
container user. Anyone who can read that folder can change your Zero Trust configuration and your
DNS. Treat it the way you treat the token itself.

Your login password is stored as an scrypt hash and cannot be read back. Changing it signs out
every other session.

## Running it safely

- Give it a real password, and do not expose the port to the internet. Put it behind Cloudflare
  Access, like any other application you publish.
- Switch on *Only send the session cookie over https* once you reach it over https.
- Set `CF0T_TRUSTED_PROXIES` to the address of whatever sits in front of it. Left at `*`, any
  caller that can reach the port directly may set `X-Forwarded-For` itself, which hides their
  address from the per-address login throttle. A global throttle still applies.
- Give the API token only the four permissions in the README. It does not need anything else.
