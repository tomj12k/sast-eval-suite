# SAST/SCA Evaluation Suite

A reproducible harness for evaluating SAST/SCA scanner quality — measuring detection
rate, false-positive rate, and ranking consistency across tools and rule sets on an
authored, ground-truth-labeled corpus.

---

## WARNING: intentionally vulnerable test corpus

**This repository contains intentionally vulnerable code and fabricated/illustrative
secrets as deliberate scan targets.**

- The `corpus/` tree is a test fixture, NOT production code. Do not deploy it.
- Planted vulnerabilities (command injection, XSS, SQL injection, path traversal, …)
  are real, working vulnerable patterns — they exist so scanners have something to find.
- Fake secrets scattered through the corpus (`sk_live_…`, basic-auth DB URLs such as
  `postgresql://admin:password@db/prod`, etc.) are synthetic fixtures. They are not
  real credentials and rotating them would be meaningless.
- Do **not** point Dependabot auto-remediation or an automated secret-scanner alert
  pipeline at this repo expecting actionable issues. Every finding in `corpus/` is
  intentional by design.
- The corpus is intentionally excluded from the repo's own `ruff`/`pyright` checks
  (those tools run only over `harness/src` and `harness/tests`).

---

## Layout

```
.
├── corpus/                 # Authored vulnerable packages (the "test fixtures")
│   ├── python/             # Python packages
│   │   ├── py-webapp-cmdi/ # Example: command-injection web app
│   │   │   ├── groundtruth.yaml
│   │   │   └── src/
│   │   └── …
│   └── java/               # Java packages
│       └── …
├── harness/                # Scoring engine (the "test harness")
│   ├── src/eval_suite/     # Python package
│   │   ├── cli.py          # eval-suite entry point
│   │   ├── models.py       # Finding, GroundTruth* dataclasses
│   │   ├── groundtruth.py  # Corpus discovery + ground-truth loader
│   │   ├── normalize/      # SARIF, OSV, Claude, Scantonomous importers
│   │   ├── runners/        # Per-tool scan wrappers (semgrep, trivy, osv, …)
│   │   ├── score/          # match.py + metrics.py (recall/precision/ToolScore)
│   │   └── report/         # render.py (Markdown + JSON) + trend.py
│   └── tests/              # pytest suite (42+ tests)
├── schema/                 # groundtruth.yaml JSON Schema
├── results/                # Generated outputs (gitignored)
│   ├── report.md           # Human-readable per-tool scoring table
│   ├── report.json         # Machine-readable scores
│   └── trend.json          # Historical run series (regression baseline)
└── .github/workflows/
    └── eval.yml            # CI: lint/type/test + free-CLI baseline scan
```

Each corpus package contains a `groundtruth.yaml` that declares every true-positive
finding with its CWE class, ecosystem, severity, exploitability triad
(network-reachable / user-controlled / no-auth-bypass), and remediation advice.
The schema lives in `schema/groundtruth-schema.json`.

---

## Quick start

Requires Python 3.13. Uses [uv](https://github.com/astral-sh/uv) for dependency
management.

```bash
# 1. Install deps
uv sync

# 2. Run the unit/integration test suite
cd harness && uv run pytest -v

# 3. Lint and type-check the harness (corpus is excluded)
uv run ruff check .
uv run pyright

# 4. Run a live scan with the free CLIs and score the corpus
#    Requires: semgrep, trivy, osv-scanner on $PATH
uv run eval-suite --corpus corpus
```

Results are written to `results/report.md`, `results/report.json`, and
`results/trend.json`.

---

## Running `eval-suite`

```
uv run eval-suite [OPTIONS]

Options:
  --corpus PATH          Path to the corpus root (default: corpus)
  --out PATH             Output path stem for report files (default: results/report)
  --trend PATH           Path to the trend JSON file (default: results/trend.json)
  --stamp TEXT           Label for this run in the trend file (default: manual)
  --scntnms-export PATH  Path to a Scantonomous findings export JSON (optional)
  --fail-on-regression   Exit with code 1 if recall regresses vs. the trend baseline
```

### Free CLIs (semgrep / trivy / osv-scanner)

The `semgrep`, `trivy`, and `osv-scanner` runners invoke the system binaries. Install
them before running:

```bash
# semgrep
pipx install semgrep

# trivy (macOS)
brew install aquasecurity/trivy/trivy

# osv-scanner
curl -sSfL https://raw.githubusercontent.com/google/osv-scanner/main/scripts/install.sh \
  | sh -s -- -b "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"
```

### Gated tools (CodeQL / Snyk / Claude)

These tools require licenses or API keys. Supply their outputs out-of-band and drop
them into the repo root before running `eval-suite`:

| Tool | How to produce | Drop-in file |
|------|---------------|--------------|
| **CodeQL** | Run the CodeQL CLI or GitHub Advanced Security scan over the corpus; export SARIF | `.codeql.sarif` |
| **Claude** | Run the `claude_review` runner or produce a compatible JSON review | `.claude-review.json` |
| **Snyk** | Set `SNYK_TOKEN` in your environment; the `snyk` runner will pick it up automatically | env var only |

```bash
# Example: run with Snyk token
SNYK_TOKEN=snyk_… uv run eval-suite --corpus corpus

# Example: run after dropping in CodeQL SARIF
cp /path/to/codeql-results.sarif .codeql.sarif
uv run eval-suite --corpus corpus
```

The runners silently skip tools whose prerequisites are absent — you always get a
partial score for whatever is available.

### Scantonomous findings export

Export findings from the Scantonomous API for a repository and save as JSON, then pass
the file path with `--scntnms-export`:

```bash
# Export findings (example using the Scantonomous CLI / API client)
scntnms export --repo my-org/my-repo --format json > my-repo-findings.json

# Score with Scantonomous findings alongside the free CLIs
uv run eval-suite \
  --corpus corpus \
  --scntnms-export my-repo-findings.json \
  --stamp "scntnms-$(date +%Y%m%d)"
```

The export JSON must be a mapping of `package_name -> findings_export_object` matching
the format produced by `scntnms_to_findings` in `harness/src/eval_suite/normalize/scntnms.py`.

---

## Reading the results

### `results/report.md`

A Markdown table with one row per tool showing:
- **recall** — fraction of ground-truth true positives detected
- **precision** — fraction of reported findings that are true positives
- **by_class** — per-CWE recall breakdown
- **by_ecosystem** — per-ecosystem (python/java) recall breakdown
- **triage_score** — how well severity rankings match ground-truth exploitability
- **remediation_score** — quality of fix advice where provided

### `results/trend.json`

A JSON array of run-summary objects, one per `eval-suite` run, each keyed by `--stamp`.
Used by `--fail-on-regression` to detect recall drops vs. the previous baseline.

```python
# Show the last 5 runs
import json, pathlib
runs = json.loads(pathlib.Path('results/trend.json').read_text())
for run in runs[-5:]:
    print(run['stamp'], {tool: round(score['recall'], 3) for tool, score in run['tools'].items()})
```

---

## CI

The `.github/workflows/eval.yml` workflow runs on every push and pull request:

- **`test` job** — installs deps with `uv`, runs `pytest -v`, then `ruff check` and
  `pyright`. Fails fast on any test, lint, or type error.
- **`baseline` job** — installs the free CLIs (semgrep via pipx, trivy via the
  `aquasecurity/trivy-action`, osv-scanner via the install script), runs
  `eval-suite --corpus corpus --fail-on-regression`, and uploads `results/` as a
  build artifact named `eval-report`.

The `baseline` job will fail if any tool's recall drops below its previous run stored
in `results/trend.json`. Gated tools (CodeQL, Snyk, Claude) are skipped in CI unless
the relevant secrets/files are present in the repository.

---

## Development

```bash
# Full verification pass (mirrors CI)
cd harness && uv run pytest -v
cd ..
uv run ruff check .
uv run pyright
```

Conventional Commits are used: `feature:`, `fix:`, `chore:`, `refactor:`, `test:`,
`docs:`. Include the Linear issue ID, e.g. `fix: correct recall formula (SCA-42)`.
