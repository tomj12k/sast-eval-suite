# SAST/SCA Evaluation Suite — Design (SCA-426)

- **Linear:** [SCA-426](https://linear.app/scantonamous/issue/SCA-426/build-a-sastsca-evaluation-suite-self-gap-detection-competitor)
- **Related:** [SCA-425](https://linear.app/scantonamous/issue/SCA-425) (RC01–RC05 root causes)
- **Date:** 2026-06-23
- **Status:** Approved (brainstorming) — pending implementation plan

## 1. Purpose

A standalone repo that does two things:

1. **Self gap-detection / regression** — catch failures like "joern silently
   returns 0" or "ODC misses non-Maven deps" before customers do, and prevent
   regressions over time (CI-runnable, trend-tracked).
2. **Competitor benchmarking** — run the same corpus through competitors and
   quantify what they catch that we don't (and the reverse).

**Acceptance:** run today, the suite must independently reproduce RC01–RC05 —
i.e. it would have caught all five gaps without a design partner.

## 2. What this is (and is not)

- It is a **target corpus + scoring harness**. Nothing in this repo drives or
  invokes the Scantonomous pipeline.
- Scantonomous's own results come from running the corpus **in the Scantonomous
  account** (standard scan + AI scan), exporting findings JSON, and ingesting
  that export via the `scntnms_import` adapter. The harness then scores that
  file alongside the competitors.
- Competitor/baseline scanners ARE run by the harness (CLI).

## 3. Scope (v1)

- **Languages/ecosystems:** Python (PyPI) + Java (Maven/Gradle). Java doubles as
  the ODC-covered SCA control; Python exposes the gaps. Go/Rust/Ruby/.NET are
  later waves.
- **Corpus sourcing:** author our own, ground-truth-first (clean licensing,
  exact labels). No vendored third-party repos in v1.
- **Baseline/competitor tools:** Semgrep OSS, Trivy, OSV-Scanner (free CLIs);
  GitHub code scanning (CodeQL / Advanced Security); Snyk (token); Claude
  `/security-review`.

## 4. Repo shape

Python-tooled to match org conventions (uv, ruff, pyright, pytest).

```
sast-eval-suite/
  corpus/
    python/  pkg-*/  (app/lib code + groundtruth.yaml + README)
    java/    pkg-*/
  schema/         groundtruth.schema.json, finding.schema.json
  harness/src/eval_suite/
    runners/      semgrep, trivy, osv, codeql(github), snyk, claude_review, scntnms_import
    normalize/    sarif + per-tool -> common finding
    score/        match->ground-truth, recall/precision, triage, diff
    report/       markdown + json, trend.json
    cli.py        eval run | score | report
  results/runs/<ts>/...   trend.json
  .github/workflows/eval.yml
```

## 5. Corpus (v1 package set)

Each package is small and focused — one or a few planted vulns, exact labels.
Chosen so the suite independently reproduces RC01–RC05.

| Package | Lang | Class / purpose | Reproduces |
|---|---|---|---|
| `py-webapp-cmdi` | Python | Flask app, OS command injection (RCE) | SAST taint baseline |
| `py-noentry-lib` | Python | Library/CLI, no web entry point, SSRF + path traversal | **RC01** (joern silent-zero) |
| `py-sca-pypi-old` | Python | Old pinned vulnerable PyPI deps | **RC02** (non-Maven SCA miss) |
| `py-secrets-basicauth` | Python | basic-auth-in-URL + other secrets | **RC03** |
| `py-xss-triad` | Python | XSS: real / mitigated-by-design / static-literal FP | **RC05** (triage) |
| `py-medsev-bug` | Python | Real MEDIUM-severity bug | **RC04** (remediation gate) |
| `java-sca-maven-old` | Java | Old vulnerable Maven deps | RC02 **control** (ODC should catch) |
| `java-cmdi-sqli` | Java | Command injection + SQLi | SAST cross-language |

## 6. Ground-truth schema

Lives next to the code as `groundtruth.yaml`, validated against
`schema/groundtruth.schema.json`.

```yaml
package: py-xss-triad
language: python
ecosystem: pypi
findings:
  - id: F1
    file: app.py
    line: 113
    cwe: CWE-79
    class: xss-reflected
    severity: HIGH
    exploitability: true-positive          # true-positive | mitigated-by-design | false-positive
    notes: user input rendered without escaping
  - id: F2
    file: app.py
    line: 118
    cwe: CWE-79
    exploitability: mitigated-by-design     # escaping/guard present
  - id: F3
    file: app.py
    line: 128
    cwe: CWE-79
    exploitability: false-positive          # static literal, not user-controlled
sca: []                                       # for SCA pkgs: {name, version, cve, ecosystem}
```

The XSS triad mirrors the codelion case exactly (L113 real / L118 mitigated /
L128 static-literal FP).

## 7. Normalization

Every tool normalizes to one `finding.schema.json` record:

```
{ tool, kind (sast|sca|secret), file, line, cwe, severity, category,
  package, version, cve, raw_id, message }
```

- **SARIF adapter** handles Semgrep, CodeQL, Snyk, Trivy (all emit SARIF).
- **Bespoke adapters** for OSV-Scanner JSON, Claude `/security-review` output,
  and the Scantonomous findings export.
- Each runner writes raw tool output **and** normalized findings under the run
  directory.

## 8. Scoring

**Match finding → ground truth:**

- SAST/secrets: same file + line within ±N lines (default 3, configurable) +
  compatible CWE/class. Normalized finding with no matching ground-truth item =
  false positive. Unmatched ground-truth `true-positive` = false negative.
- SCA: match on `{package, version, cve}` (CVE optional), line-independent —
  RC02 is about ecosystem coverage, not location.

**Scores per tool:**

- **Recall & precision** per vuln class and per ecosystem.
- **Exploitability-triage accuracy** — flagged the `true-positive`, did NOT
  report the `false-positive`, and (if it emits severity) downgraded the
  `mitigated-by-design`. Scores RC05.
- **Remediation coverage** — % of matched findings carrying actionable
  remediation (meaningful only for tools whose export includes it, i.e.
  Scantonomous). Scores RC04.
- **Competitor diff matrix** — "found by X, missed by us" and the reverse, per
  class/ecosystem.

**Report:** markdown summary + machine-readable JSON per run under
`results/runs/<ts>/`.

## 9. Acceptance (RC01–RC05)

A single acceptance test asserts the suite, run today, independently reproduces
all five.

| RC | Concrete scored signal |
|---|---|
| **RC01** | `py-noentry-lib`: Scantonomous AI-scan recall = 0 while ≥1 competitor catches the SSRF/path-traversal → silent-zero gap. The canary masks this; this package does not. |
| **RC02** | `py-sca-pypi-old` missed by ODC but caught by Trivy/OSV, **while** `java-sca-maven-old` is caught → proves the miss is ecosystem-scoped. |
| **RC03** | `py-secrets-basicauth`: basic-auth-in-URL in ground truth, absent from Scantonomous findings, present in a competitor → secrets-rule gap. |
| **RC04** | `py-medsev-bug`: real MEDIUM finding present but no remediation in the export → remediation-coverage drops on MEDIUM/LOW. |
| **RC05** | `py-xss-triad`: triage accuracy < 1.0 when the FP is reported or the real one missed. |

## 10. Trend / CI

- Each run appends a summary to `results/trend.json` (committed).
- `.github/workflows/eval.yml` runs the free CLIs (Semgrep/Trivy/OSV) + scoring
  on every push and **fails CI if any tool's recall on a class regresses below
  its stored baseline** — so "joern silently drops to 0" trips automatically.
- Paid/GitHub/Claude + Scantonomous-import runs are token/account-gated and run
  manually; their results fold into the report when present.

## 11. Out of scope (v1 / later waves)

- Go / Rust / Ruby / .NET ecosystems (RC02 breadth).
- Vendored public vulnerable repos (Juice Shop, WebGoat, vulhub, DVWA).
- IaC / container / DAST control surfaces.
- Automated invocation of the Scantonomous pipeline (stays manual export-based).
