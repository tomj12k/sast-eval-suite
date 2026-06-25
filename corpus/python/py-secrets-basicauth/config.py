"""Config module with planted secrets, including basic-auth-in-URL."""

# VULN: basic-auth credentials embedded in a URL (RC03).
DATABASE_URL = "postgres://admin:S3cr3tP@ssw0rd@db.internal:5432/app"

# VULN: hardcoded API key.
STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
