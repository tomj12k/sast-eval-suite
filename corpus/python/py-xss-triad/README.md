# py-xss-triad

Planted vulnerabilities: **XSS triad** (CWE-79) — RC05.

Three routes in `app.py` represent the full XSS detection spectrum:

| Line | Route | Exploitability | Description |
|------|-------|---------------|-------------|
| 113 | `/reflect` | true-positive | User input rendered directly in HTML — real reflected XSS |
| 118 | `/safe` | mitigated-by-design | `flask.escape()` applied — correctly mitigated |
| 128 | `/static` | false-positive | Static string literal only — no user data flows in |

The file is padded with filler comments (lines 7-105) so sinks land on the exact
line numbers referenced in `groundtruth.yaml`. The `flask.escape` import is only
valid in Flask < 3.0 and is kept for static-analysis purposes only — this file is
never executed.

**RC exercised:** RC05 — XSS detection accuracy including TP/mitigated/FP discrimination.
