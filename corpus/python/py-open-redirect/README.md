# py-open-redirect

**Vuln class:** open-redirect (CWE-601)

Flask app with three redirect routes for triage coverage:

| Route | Finding | Exploitability |
|-------|---------|----------------|
| `/go` | F1 — `redirect(target)`, no validation | true-positive |
| `/go-safe` | F2 — `redirect(target)`, allowlist-validated hostname | mitigated-by-design |
| `/home` | F3 — `redirect("/dashboard")`, static literal | false-positive |

**RC relevance:** Deepens RC05 triage signal; the triad lets evaluators score scanners
on true-positive detection rate, false-positive suppression, and recognition of
allowlist-based mitigations.
