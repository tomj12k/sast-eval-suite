"""Application configuration."""

# [VULN] CWE-798: Hardcoded secret key used to sign Flask session cookies.
# Any attacker who knows this value can forge session tokens.
SECRET_KEY = "hardcoded-flask-secret-do-not-use"

DATABASE = "users.db"
DEBUG = False
