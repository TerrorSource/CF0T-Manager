# Contributing

## Running it locally

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
.venv/bin/python -m pytest tests/ -q
```

The tests run against a fake Cloudflare API, so they never touch a real account and need no
token. Please add one for anything you change: every bug fixed so far has a test that fails
without the fix.

## Two things worth knowing before you change anything

- Updating an Access application, or a tunnel configuration, **replaces the whole object**. Read
  the current one first and change only your own fields, or settings nobody here manages quietly
  fall back to their defaults.
- Nothing destructive happens without asking: removing protection, overwriting a DNS record and
  deleting without a backup all go through a confirmation screen first. Keep it that way.
