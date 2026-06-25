# py-rest-api

A realistic multi-file Flask REST API used as a SAST/SCA evaluation corpus target.

## Purpose

Exercises interacting taint flows, missing access-control checks, and secrets
detection across several source files.  Includes one mitigated-by-design finding
and one false-positive decoy so evaluation harnesses can measure both precision
and recall.

## Planted findings

| ID | File | Line | CWE | Class | Exploitability |
|----|------|------|-----|-------|----------------|
| F1 | db.py | 19 | CWE-89 | sql-injection | true-positive |
| F2 | db.py | 32 | CWE-89 | sql-injection | mitigated-by-design |
| F3 | fetch.py | 13 | CWE-918 | ssrf | true-positive |
| F4 | app.py | 31 | CWE-639 | broken-access-control | true-positive |
| F5 | config.py | 5 | CWE-798 | hardcoded-secret | true-positive |
| F6 | app.py | 55 | CWE-601 | open-redirect | false-positive |

## Architecture

```
config.py   — hardcoded SECRET_KEY (F5)
db.py       — get_user() SQLi (F1), get_user_safe() parameterised (F2)
fetch.py    — fetch_avatar() SSRF (F3)
auth.py     — can_access_profile() defined but never called in the profile route
app.py      — /users/<id>/profile IDOR (F4), /logout static-redirect FP (F6)
```

The IDOR in `app.py` (F4) interacts with `auth.py`: `can_access_profile()` exists
but the route never calls it, demonstrating a cross-file missing-check pattern.
