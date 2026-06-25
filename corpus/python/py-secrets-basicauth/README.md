# py-secrets-basicauth

Planted vulnerabilities: **hardcoded secrets** (CWE-798) — RC03.

- `config.py` line 4: PostgreSQL connection URL with basic-auth credentials
  (`admin:S3cr3tP@ssw0rd`) embedded in plaintext — illustrative non-functional
  placeholder.
- `config.py` line 7: Stripe live API key (`sk_live_...`) hardcoded as a string
  literal — illustrative non-functional placeholder.

Both secrets are fake/illustrative and will never authenticate against a real service.

**RC exercised:** RC03 — secret detection for embedded credentials and API keys.
