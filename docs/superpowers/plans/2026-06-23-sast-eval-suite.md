# SAST/SCA Evaluation Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone corpus + scoring harness that benchmarks Scantonomous and competitor scanners against ground-truth-labeled vulnerable packages and independently reproduces RC01–RC05.

**Architecture:** A Python harness (`harness/src/eval_suite/`) discovers authored vulnerable packages under `corpus/`, each carrying a `groundtruth.yaml`. Competitor CLIs are run via thin subprocess runners; their output (SARIF or tool-specific JSON) plus an exported Scantonomous findings file are normalized to one `Finding` schema, matched against ground truth, scored (recall/precision/triage/remediation/diff), reported, and trend-tracked for regression.

**Tech Stack:** Python 3.13, uv, ruff, pyright, pytest, PyYAML, jsonschema, argparse. Corpus packages: Python (Flask/stdlib) + Java (Maven). External scanner CLIs: semgrep, trivy, osv-scanner, codeql/gh, snyk, claude.

## Global Constraints

- Python interpreter floor: **3.13** (`requires-python = ">=3.13"`).
- Tooling via **uv** only: `uv run <tool>` — never system Python.
- Lint/format/type: **ruff** + **pyright**. Tests: **pytest**.
- **No `assert` in non-test code** — use explicit `if`/raise.
- **Never catch bare `Exception`/`BaseException`** — catch specific types; comment if a broad catch is unavoidable.
- Docstrings: **Sphinx reST** (`:param:`, `:returns:`, `:rtype:`, `:raises:`).
- Commits: **Conventional Commits**, include `(SCA-426)`.
- Exploitability label vocabulary (exact strings): `true-positive`, `mitigated-by-design`, `false-positive`.
- Normalized finding `kind` vocabulary (exact strings): `sast`, `sca`, `secret`.
- Corpus is **authored only** in v1 — no vendored third-party repos.
- v1 languages: **Python (PyPI)** and **Java (Maven/Gradle)** only.

---

## File Structure

**Harness**
- `harness/src/eval_suite/models.py` — enums + `Finding`, `GroundTruthItem`, `ScaItem`, `GroundTruth` dataclasses.
- `harness/src/eval_suite/groundtruth.py` — load + validate `groundtruth.yaml`; discover corpus.
- `harness/src/eval_suite/normalize/sarif.py` — SARIF → `Finding[]` (semgrep/codeql/snyk/trivy).
- `harness/src/eval_suite/normalize/osv.py` — OSV-Scanner JSON → `Finding[]`.
- `harness/src/eval_suite/normalize/claude.py` — Claude `/security-review` JSON → `Finding[]`.
- `harness/src/eval_suite/normalize/scntnms.py` — Scantonomous export JSON → `Finding[]`.
- `harness/src/eval_suite/runners/base.py` — subprocess helper + `RunResult`.
- `harness/src/eval_suite/runners/{semgrep,trivy,osv,codeql,snyk,claude_review}.py` — CLI invokers.
- `harness/src/eval_suite/score/match.py` — match `Finding[]` → ground truth.
- `harness/src/eval_suite/score/metrics.py` — recall/precision/triage/remediation/diff.
- `harness/src/eval_suite/report/render.py` — markdown + JSON report.
- `harness/src/eval_suite/report/trend.py` — append run + regression check.
- `harness/src/eval_suite/cli.py` — `eval run | score | report`.

**Schemas**
- `schema/groundtruth.schema.json`, `schema/finding.schema.json`.

**Corpus**
- `corpus/python/<pkg>/…` + `groundtruth.yaml` (6 packages).
- `corpus/java/<pkg>/…` + `groundtruth.yaml` (2 packages).

**Tests** mirror modules under `harness/tests/`. **CI:** `.github/workflows/eval.yml`.

---

### Task 1: Project scaffold & tooling

**Files:**
- Create: `pyproject.toml`, `harness/src/eval_suite/__init__.py`, `harness/tests/__init__.py`, `harness/tests/test_smoke.py`
- Create: `README.md`

**Interfaces:**
- Produces: importable package `eval_suite`; `uv run pytest`, `uv run ruff`, `uv run pyright` all work.

- [ ] **Step 1: Write the failing test**

```python
# harness/tests/test_smoke.py
import eval_suite


def test_package_importable():
    assert eval_suite.__version__ == "0.1.0"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd harness && uv run pytest tests/test_smoke.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'eval_suite'`

- [ ] **Step 3: Create pyproject and package**

```toml
# pyproject.toml
[project]
name = "eval-suite"
version = "0.1.0"
requires-python = ">=3.13"
dependencies = ["pyyaml>=6.0", "jsonschema>=4.21"]

[dependency-groups]
dev = ["pytest>=8.0", "ruff>=0.6", "pyright>=1.1"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["harness/src/eval_suite"]

[tool.pytest.ini_options]
pythonpath = ["harness/src"]
testpaths = ["harness/tests"]

[tool.pyright]
include = ["harness/src", "harness/tests"]
pythonVersion = "3.13"

[tool.ruff]
target-version = "py313"
src = ["harness/src"]
```

```python
# harness/src/eval_suite/__init__.py
"""SAST/SCA evaluation suite harness."""

__version__ = "0.1.0"
```

```python
# harness/tests/__init__.py
```

- [ ] **Step 4: Run tests + lint + types**

Run: `uv sync && cd harness && uv run pytest tests/test_smoke.py -v && cd .. && uv run ruff check . && uv run pyright`
Expected: PASS; ruff clean; pyright 0 errors.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml uv.lock README.md harness/
git commit -m "chore: scaffold eval-suite harness package (SCA-426)"
```

---

### Task 2: JSON Schemas for ground truth & findings

**Files:**
- Create: `schema/groundtruth.schema.json`, `schema/finding.schema.json`
- Create: `harness/tests/test_schemas.py`

**Interfaces:**
- Produces: two JSON Schema files loadable by `jsonschema`; constants `GROUNDTRUTH_SCHEMA_PATH`, `FINDING_SCHEMA_PATH` (added in Task 3 — here just the files).

- [ ] **Step 1: Write the failing test**

```python
# harness/tests/test_schemas.py
import json
from pathlib import Path

import jsonschema

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schema"


def _load(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text())


def test_groundtruth_schema_is_valid_and_accepts_sample():
    schema = _load("groundtruth.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)
    sample = {
        "package": "py-xss-triad",
        "language": "python",
        "ecosystem": "pypi",
        "findings": [
            {
                "id": "F1",
                "file": "app.py",
                "line": 113,
                "cwe": "CWE-79",
                "class": "xss-reflected",
                "severity": "HIGH",
                "exploitability": "true-positive",
            }
        ],
        "sca": [],
    }
    jsonschema.validate(sample, schema)


def test_groundtruth_schema_rejects_bad_exploitability():
    schema = _load("groundtruth.schema.json")
    bad = {
        "package": "x",
        "language": "python",
        "ecosystem": "pypi",
        "findings": [
            {"id": "F1", "file": "a.py", "line": 1, "cwe": "CWE-79",
             "class": "xss", "severity": "HIGH", "exploitability": "maybe"}
        ],
        "sca": [],
    }
    with __import__("pytest").raises(jsonschema.ValidationError):
        jsonschema.validate(bad, schema)


def test_finding_schema_is_valid():
    schema = _load("finding.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd harness && uv run pytest tests/test_schemas.py -v`
Expected: FAIL — schema files do not exist.

- [ ] **Step 3: Write the schemas**

```json
// schema/groundtruth.schema.json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "GroundTruth",
  "type": "object",
  "required": ["package", "language", "ecosystem", "findings", "sca"],
  "additionalProperties": false,
  "properties": {
    "package": {"type": "string"},
    "language": {"enum": ["python", "java"]},
    "ecosystem": {"enum": ["pypi", "maven"]},
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "file", "line", "cwe", "class", "severity", "exploitability"],
        "additionalProperties": false,
        "properties": {
          "id": {"type": "string"},
          "file": {"type": "string"},
          "line": {"type": "integer", "minimum": 1},
          "cwe": {"type": "string", "pattern": "^CWE-[0-9]+$"},
          "class": {"type": "string"},
          "severity": {"enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
          "exploitability": {"enum": ["true-positive", "mitigated-by-design", "false-positive"]},
          "notes": {"type": "string"}
        }
      }
    },
    "sca": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["name", "version", "ecosystem"],
        "additionalProperties": false,
        "properties": {
          "name": {"type": "string"},
          "version": {"type": "string"},
          "cve": {"type": "string"},
          "ecosystem": {"enum": ["pypi", "maven"]},
          "severity": {"enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
        }
      }
    }
  }
}
```

```json
// schema/finding.schema.json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Finding",
  "type": "object",
  "required": ["tool", "kind"],
  "additionalProperties": false,
  "properties": {
    "tool": {"type": "string"},
    "kind": {"enum": ["sast", "sca", "secret"]},
    "file": {"type": ["string", "null"]},
    "line": {"type": ["integer", "null"]},
    "cwe": {"type": ["string", "null"]},
    "severity": {"type": ["string", "null"]},
    "category": {"type": ["string", "null"]},
    "package": {"type": ["string", "null"]},
    "version": {"type": ["string", "null"]},
    "cve": {"type": ["string", "null"]},
    "raw_id": {"type": ["string", "null"]},
    "message": {"type": ["string", "null"]},
    "remediation": {"type": ["string", "null"]}
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd harness && uv run pytest tests/test_schemas.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add schema/ harness/tests/test_schemas.py
git commit -m "feat: add ground-truth and finding JSON schemas (SCA-426)"
```

---

### Task 3: Domain models & ground-truth loader

**Files:**
- Create: `harness/src/eval_suite/models.py`, `harness/src/eval_suite/groundtruth.py`
- Test: `harness/tests/test_groundtruth.py`

**Interfaces:**
- Produces:
  - `models.Finding(tool, kind, file, line, cwe, severity, category, package, version, cve, raw_id, message, remediation)` — frozen dataclass, all but `tool`/`kind` default `None`.
  - `models.GroundTruthItem(id, file, line, cwe, klass, severity, exploitability, notes)`.
  - `models.ScaItem(name, version, ecosystem, cve, severity)`.
  - `models.GroundTruth(package, language, ecosystem, findings: list[GroundTruthItem], sca: list[ScaItem])`.
  - `groundtruth.load_groundtruth(path: Path) -> GroundTruth` (validates against schema).
  - `groundtruth.discover_corpus(corpus_root: Path) -> list[GroundTruth]`.

- [ ] **Step 1: Write the failing test**

```python
# harness/tests/test_groundtruth.py
from pathlib import Path

import pytest

from eval_suite.groundtruth import discover_corpus, load_groundtruth
from eval_suite.models import GroundTruth


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "groundtruth.yaml"
    p.write_text(body)
    return p


def test_load_groundtruth_parses_fields(tmp_path: Path):
    p = _write(tmp_path, """
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
    exploitability: true-positive
sca: []
""")
    gt = load_groundtruth(p)
    assert isinstance(gt, GroundTruth)
    assert gt.package == "py-xss-triad"
    assert gt.findings[0].klass == "xss-reflected"
    assert gt.findings[0].exploitability == "true-positive"


def test_load_groundtruth_rejects_invalid(tmp_path: Path):
    p = _write(tmp_path, """
package: x
language: python
ecosystem: pypi
findings:
  - id: F1
    file: a.py
    line: 1
    cwe: CWE-79
    class: xss
    severity: HIGH
    exploitability: maybe
sca: []
""")
    with pytest.raises(ValueError):
        load_groundtruth(p)


def test_discover_corpus_finds_all(tmp_path: Path):
    for name in ("a", "b"):
        d = tmp_path / "python" / name
        d.mkdir(parents=True)
        (d / "groundtruth.yaml").write_text(
            "package: %s\nlanguage: python\necosystem: pypi\nfindings: []\nsca: []\n" % name
        )
    found = discover_corpus(tmp_path)
    assert {g.package for g in found} == {"a", "b"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd harness && uv run pytest tests/test_groundtruth.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'eval_suite.models'`.

- [ ] **Step 3: Write models and loader**

```python
# harness/src/eval_suite/models.py
"""Core data models for the evaluation suite."""

from __future__ import annotations

from dataclasses import dataclass, field

Kind = str  # one of: "sast", "sca", "secret"
Exploitability = str  # "true-positive" | "mitigated-by-design" | "false-positive"


@dataclass(frozen=True)
class Finding:
    """A normalized finding emitted by any tool."""

    tool: str
    kind: Kind
    file: str | None = None
    line: int | None = None
    cwe: str | None = None
    severity: str | None = None
    category: str | None = None
    package: str | None = None
    version: str | None = None
    cve: str | None = None
    raw_id: str | None = None
    message: str | None = None
    remediation: str | None = None


@dataclass(frozen=True)
class GroundTruthItem:
    """A single labeled SAST/secret finding in a corpus package."""

    id: str
    file: str
    line: int
    cwe: str
    klass: str
    severity: str
    exploitability: Exploitability
    notes: str | None = None


@dataclass(frozen=True)
class ScaItem:
    """A single labeled vulnerable dependency in a corpus package."""

    name: str
    version: str
    ecosystem: str
    cve: str | None = None
    severity: str | None = None


@dataclass(frozen=True)
class GroundTruth:
    """All ground-truth labels for one corpus package."""

    package: str
    language: str
    ecosystem: str
    findings: list[GroundTruthItem] = field(default_factory=list)
    sca: list[ScaItem] = field(default_factory=list)
```

```python
# harness/src/eval_suite/groundtruth.py
"""Load and validate corpus ground-truth files."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import yaml

from eval_suite.models import GroundTruth, GroundTruthItem, ScaItem

SCHEMA_PATH = Path(__file__).resolve().parents[3] / "schema" / "groundtruth.schema.json"


def _validate(data: dict) -> None:
    """Validate raw ground-truth data against the JSON schema.

    :param data: parsed YAML mapping.
    :raises ValueError: if the data does not match the schema.
    """
    schema = json.loads(SCHEMA_PATH.read_text())
    try:
        jsonschema.validate(data, schema)
    except jsonschema.ValidationError as exc:
        raise ValueError(f"invalid ground truth: {exc.message}") from exc


def load_groundtruth(path: Path) -> GroundTruth:
    """Parse and validate a ``groundtruth.yaml`` file.

    :param path: path to the YAML file.
    :returns: the parsed ground truth.
    :rtype: GroundTruth
    :raises ValueError: if validation fails.
    """
    data = yaml.safe_load(path.read_text())
    _validate(data)
    findings = [
        GroundTruthItem(
            id=f["id"], file=f["file"], line=f["line"], cwe=f["cwe"],
            klass=f["class"], severity=f["severity"],
            exploitability=f["exploitability"], notes=f.get("notes"),
        )
        for f in data["findings"]
    ]
    sca = [
        ScaItem(name=s["name"], version=s["version"], ecosystem=s["ecosystem"],
                cve=s.get("cve"), severity=s.get("severity"))
        for s in data["sca"]
    ]
    return GroundTruth(
        package=data["package"], language=data["language"],
        ecosystem=data["ecosystem"], findings=findings, sca=sca,
    )


def discover_corpus(corpus_root: Path) -> list[GroundTruth]:
    """Find and load every ``groundtruth.yaml`` under a corpus root.

    :param corpus_root: directory containing language subdirs of packages.
    :returns: loaded ground truth for each package, sorted by package name.
    :rtype: list[GroundTruth]
    """
    out = [load_groundtruth(p) for p in sorted(corpus_root.rglob("groundtruth.yaml"))]
    return sorted(out, key=lambda g: g.package)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd harness && uv run pytest tests/test_groundtruth.py -v && cd .. && uv run pyright`
Expected: PASS (3 tests); pyright clean.

- [ ] **Step 5: Commit**

```bash
git add harness/src/eval_suite/models.py harness/src/eval_suite/groundtruth.py harness/tests/test_groundtruth.py
git commit -m "feat: add domain models and ground-truth loader (SCA-426)"
```

---

### Task 4: SARIF normalizer

**Files:**
- Create: `harness/src/eval_suite/normalize/__init__.py`, `harness/src/eval_suite/normalize/sarif.py`
- Test: `harness/tests/normalize/test_sarif.py`, `harness/tests/__init__.py` already exists; add `harness/tests/normalize/__init__.py`

**Interfaces:**
- Consumes: `models.Finding`.
- Produces: `sarif.sarif_to_findings(sarif: dict, tool: str, kind: str = "sast") -> list[Finding]`. Extracts file (uri), line (region.startLine), message, rule id (`raw_id`), and CWE from rule `properties.tags`/`relationships` when present; maps SARIF `level` to severity (`error`→HIGH, `warning`→MEDIUM, `note`→LOW).

- [ ] **Step 1: Write the failing test**

```python
# harness/tests/normalize/test_sarif.py
from eval_suite.normalize.sarif import sarif_to_findings

SARIF = {
    "runs": [
        {
            "tool": {"driver": {"name": "semgrep", "rules": [
                {"id": "py.cmdi", "properties": {"tags": ["CWE-78", "security"]}}
            ]}},
            "results": [
                {
                    "ruleId": "py.cmdi",
                    "level": "error",
                    "message": {"text": "OS command injection"},
                    "locations": [
                        {"physicalLocation": {
                            "artifactLocation": {"uri": "app.py"},
                            "region": {"startLine": 42}
                        }}
                    ],
                }
            ],
        }
    ]
}


def test_sarif_to_findings_extracts_core_fields():
    findings = sarif_to_findings(SARIF, tool="semgrep")
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "semgrep"
    assert f.file == "app.py"
    assert f.line == 42
    assert f.cwe == "CWE-78"
    assert f.severity == "HIGH"
    assert f.raw_id == "py.cmdi"
    assert f.kind == "sast"


def test_sarif_to_findings_handles_missing_region():
    sarif = {"runs": [{"tool": {"driver": {"name": "x", "rules": []}},
                       "results": [{"ruleId": "r", "message": {"text": "m"},
                                    "locations": []}]}]}
    findings = sarif_to_findings(sarif, tool="x")
    assert findings[0].file is None
    assert findings[0].line is None
    assert findings[0].cwe is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd harness && uv run pytest tests/normalize/test_sarif.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Write the normalizer**

```python
# harness/src/eval_suite/normalize/__init__.py
"""Adapters that normalize tool output to eval_suite.models.Finding."""
```

```python
# harness/tests/normalize/__init__.py
```

```python
# harness/src/eval_suite/normalize/sarif.py
"""Normalize SARIF tool output into Finding records."""

from __future__ import annotations

import re

from eval_suite.models import Finding

_CWE_RE = re.compile(r"CWE-\d+")
_LEVEL_TO_SEVERITY = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}


def _cwe_from_tags(tags: list[str]) -> str | None:
    for tag in tags:
        m = _CWE_RE.search(tag)
        if m:
            return m.group(0)
    return None


def sarif_to_findings(sarif: dict, tool: str, kind: str = "sast") -> list[Finding]:
    """Convert a SARIF document into normalized findings.

    :param sarif: parsed SARIF JSON.
    :param tool: tool name to stamp on each finding.
    :param kind: finding kind (``sast``/``sca``/``secret``).
    :returns: normalized findings.
    :rtype: list[Finding]
    """
    findings: list[Finding] = []
    for run in sarif.get("runs", []):
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        rule_tags: dict[str, list[str]] = {
            r.get("id", ""): r.get("properties", {}).get("tags", []) for r in rules
        }
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            file = None
            line = None
            locations = result.get("locations", [])
            if locations:
                phys = locations[0].get("physicalLocation", {})
                file = phys.get("artifactLocation", {}).get("uri")
                line = phys.get("region", {}).get("startLine")
            level = result.get("level", "warning")
            findings.append(
                Finding(
                    tool=tool,
                    kind=kind,
                    file=file,
                    line=line,
                    cwe=_cwe_from_tags(rule_tags.get(rule_id, [])),
                    severity=_LEVEL_TO_SEVERITY.get(level, "MEDIUM"),
                    raw_id=rule_id,
                    message=result.get("message", {}).get("text"),
                )
            )
    return findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd harness && uv run pytest tests/normalize/test_sarif.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add harness/src/eval_suite/normalize/ harness/tests/normalize/
git commit -m "feat: add SARIF normalizer (SCA-426)"
```

---

### Task 5: OSV, Claude, and Scantonomous normalizers

**Files:**
- Create: `harness/src/eval_suite/normalize/osv.py`, `.../claude.py`, `.../scntnms.py`
- Test: `harness/tests/normalize/test_osv.py`, `.../test_claude.py`, `.../test_scntnms.py`

**Interfaces:**
- Consumes: `models.Finding`.
- Produces:
  - `osv.osv_to_findings(data: dict, tool: str = "osv-scanner") -> list[Finding]` — `kind="sca"`, fills `package`/`version`/`cve`.
  - `claude.claude_to_findings(data: dict, tool: str = "claude-security-review") -> list[Finding]` — reads a list under `findings` with `file`/`line`/`cwe`/`severity`/`title`.
  - `scntnms.scntnms_to_findings(data: dict, tool: str) -> list[Finding]` — reads exported findings list; maps `kind` from `type`, carries `remediation`.

- [ ] **Step 1: Write the failing tests**

```python
# harness/tests/normalize/test_osv.py
from eval_suite.normalize.osv import osv_to_findings

OSV = {"results": [{"packages": [{
    "package": {"name": "requests", "version": "2.5.0", "ecosystem": "PyPI"},
    "vulnerabilities": [{"aliases": ["CVE-2018-18074"], "id": "GHSA-x"}],
}]}]}


def test_osv_to_findings():
    findings = osv_to_findings(OSV)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind == "sca"
    assert f.package == "requests"
    assert f.version == "2.5.0"
    assert f.cve == "CVE-2018-18074"
```

```python
# harness/tests/normalize/test_claude.py
from eval_suite.normalize.claude import claude_to_findings

DATA = {"findings": [
    {"file": "app.py", "line": 113, "cwe": "CWE-79", "severity": "HIGH",
     "title": "Reflected XSS"}
]}


def test_claude_to_findings():
    f = claude_to_findings(DATA)[0]
    assert f.tool == "claude-security-review"
    assert f.kind == "sast"
    assert f.file == "app.py"
    assert f.line == 113
    assert f.cwe == "CWE-79"
    assert f.severity == "HIGH"
```

```python
# harness/tests/normalize/test_scntnms.py
from eval_suite.normalize.scntnms import scntnms_to_findings

DATA = {"findings": [
    {"type": "sca", "package": "log4j-core", "version": "2.14.1",
     "cve": "CVE-2021-44228", "severity": "CRITICAL", "remediation": "upgrade to 2.17.1"},
    {"type": "sast", "file": "app.py", "line": 42, "cwe": "CWE-78",
     "severity": "HIGH", "message": "cmdi", "remediation": None},
]}


def test_scntnms_to_findings():
    out = scntnms_to_findings(DATA, tool="scntnms-standard")
    assert out[0].kind == "sca"
    assert out[0].remediation == "upgrade to 2.17.1"
    assert out[1].kind == "sast"
    assert out[1].file == "app.py"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd harness && uv run pytest tests/normalize/test_osv.py tests/normalize/test_claude.py tests/normalize/test_scntnms.py -v`
Expected: FAIL — modules missing.

- [ ] **Step 3: Write the normalizers**

```python
# harness/src/eval_suite/normalize/osv.py
"""Normalize OSV-Scanner JSON output into Finding records."""

from __future__ import annotations

from eval_suite.models import Finding


def _pick_cve(aliases: list[str], fallback: str | None) -> str | None:
    for a in aliases:
        if a.startswith("CVE-"):
            return a
    return fallback


def osv_to_findings(data: dict, tool: str = "osv-scanner") -> list[Finding]:
    """Convert OSV-Scanner JSON into SCA findings.

    :param data: parsed OSV-Scanner JSON.
    :param tool: tool name to stamp on each finding.
    :returns: SCA findings.
    :rtype: list[Finding]
    """
    findings: list[Finding] = []
    for result in data.get("results", []):
        for pkg in result.get("packages", []):
            meta = pkg.get("package", {})
            for vuln in pkg.get("vulnerabilities", []):
                findings.append(
                    Finding(
                        tool=tool, kind="sca",
                        package=meta.get("name"), version=meta.get("version"),
                        cve=_pick_cve(vuln.get("aliases", []), vuln.get("id")),
                        raw_id=vuln.get("id"),
                    )
                )
    return findings
```

```python
# harness/src/eval_suite/normalize/claude.py
"""Normalize Claude /security-review JSON output into Finding records."""

from __future__ import annotations

from eval_suite.models import Finding


def claude_to_findings(data: dict, tool: str = "claude-security-review") -> list[Finding]:
    """Convert Claude security-review JSON into SAST findings.

    :param data: parsed JSON with a ``findings`` list.
    :param tool: tool name to stamp on each finding.
    :returns: SAST findings.
    :rtype: list[Finding]
    """
    out: list[Finding] = []
    for item in data.get("findings", []):
        out.append(
            Finding(
                tool=tool, kind="sast",
                file=item.get("file"), line=item.get("line"),
                cwe=item.get("cwe"), severity=item.get("severity"),
                message=item.get("title") or item.get("message"),
            )
        )
    return out
```

```python
# harness/src/eval_suite/normalize/scntnms.py
"""Normalize an exported Scantonomous findings file into Finding records."""

from __future__ import annotations

from eval_suite.models import Finding

_VALID_KINDS = {"sast", "sca", "secret"}


def scntnms_to_findings(data: dict, tool: str) -> list[Finding]:
    """Convert a Scantonomous findings export into normalized findings.

    :param data: parsed export with a ``findings`` list.
    :param tool: tool label, e.g. ``scntnms-standard`` or ``scntnms-ai``.
    :returns: normalized findings.
    :rtype: list[Finding]
    """
    out: list[Finding] = []
    for item in data.get("findings", []):
        kind = item.get("type", "sast")
        if kind not in _VALID_KINDS:
            kind = "sast"
        out.append(
            Finding(
                tool=tool, kind=kind,
                file=item.get("file"), line=item.get("line"),
                cwe=item.get("cwe"), severity=item.get("severity"),
                package=item.get("package"), version=item.get("version"),
                cve=item.get("cve"), message=item.get("message"),
                remediation=item.get("remediation"),
            )
        )
    return out
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd harness && uv run pytest tests/normalize/ -v && cd .. && uv run pyright`
Expected: PASS; pyright clean.

- [ ] **Step 5: Commit**

```bash
git add harness/src/eval_suite/normalize/ harness/tests/normalize/
git commit -m "feat: add OSV, Claude, and Scantonomous normalizers (SCA-426)"
```

---

### Task 6: Matcher (findings → ground truth)

**Files:**
- Create: `harness/src/eval_suite/score/__init__.py`, `harness/src/eval_suite/score/match.py`
- Test: `harness/tests/score/__init__.py`, `harness/tests/score/test_match.py`

**Interfaces:**
- Consumes: `models.Finding`, `models.GroundTruth`, `GroundTruthItem`, `ScaItem`.
- Produces:
  - `match.MatchResult` frozen dataclass: `tp: list[GroundTruthItem]`, `fn: list[GroundTruthItem]`, `fp: list[Finding]`, `matched_pairs: list[tuple[GroundTruthItem, Finding]]`, `sca_tp: list[ScaItem]`, `sca_fn: list[ScaItem]`.
  - `match.match(findings: list[Finding], gt: GroundTruth, line_tolerance: int = 3) -> MatchResult`.
- Matching rules: SAST/secret ground-truth item with `exploitability == "false-positive"` is NOT a target (must NOT be reported); a finding matching an FP item's location counts as a false positive. SAST match = same file basename + `abs(finding.line - gt.line) <= tolerance`. SCA match = same `package` and `version` (case-insensitive name).

- [ ] **Step 1: Write the failing test**

```python
# harness/tests/score/test_match.py
from eval_suite.models import Finding, GroundTruth, GroundTruthItem, ScaItem
from eval_suite.score.match import match


def _gt(findings=(), sca=()):
    return GroundTruth(package="p", language="python", ecosystem="pypi",
                       findings=list(findings), sca=list(sca))


def test_sast_true_positive_within_tolerance():
    gt = _gt(findings=[GroundTruthItem("F1", "app.py", 113, "CWE-79", "xss",
                                       "HIGH", "true-positive")])
    findings = [Finding(tool="t", kind="sast", file="app.py", line=115, cwe="CWE-79")]
    res = match(findings, gt, line_tolerance=3)
    assert len(res.tp) == 1
    assert not res.fn
    assert not res.fp


def test_sast_miss_is_false_negative():
    gt = _gt(findings=[GroundTruthItem("F1", "app.py", 113, "CWE-79", "xss",
                                       "HIGH", "true-positive")])
    res = match([], gt)
    assert len(res.fn) == 1


def test_reporting_a_false_positive_item_counts_as_fp():
    gt = _gt(findings=[GroundTruthItem("F3", "app.py", 128, "CWE-79", "xss",
                                       "HIGH", "false-positive")])
    findings = [Finding(tool="t", kind="sast", file="app.py", line=128, cwe="CWE-79")]
    res = match(findings, gt)
    assert len(res.fp) == 1
    assert not res.tp


def test_unrelated_finding_is_false_positive():
    gt = _gt(findings=[GroundTruthItem("F1", "app.py", 113, "CWE-79", "xss",
                                       "HIGH", "true-positive")])
    findings = [Finding(tool="t", kind="sast", file="other.py", line=5, cwe="CWE-89")]
    res = match(findings, gt)
    assert len(res.fp) == 1
    assert len(res.fn) == 1


def test_sca_match_by_name_version():
    gt = _gt(sca=[ScaItem("requests", "2.5.0", "pypi", "CVE-2018-18074")])
    findings = [Finding(tool="t", kind="sca", package="requests", version="2.5.0",
                        cve="CVE-2018-18074")]
    res = match(findings, gt)
    assert len(res.sca_tp) == 1
    assert not res.sca_fn
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd harness && uv run pytest tests/score/test_match.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Write the matcher**

```python
# harness/src/eval_suite/score/__init__.py
"""Matching and scoring of normalized findings against ground truth."""
```

```python
# harness/tests/score/__init__.py
```

```python
# harness/src/eval_suite/score/match.py
"""Match normalized findings against package ground truth."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath

from eval_suite.models import Finding, GroundTruth, GroundTruthItem, ScaItem


@dataclass(frozen=True)
class MatchResult:
    """Outcome of matching one tool's findings against one package."""

    tp: list[GroundTruthItem] = field(default_factory=list)
    fn: list[GroundTruthItem] = field(default_factory=list)
    fp: list[Finding] = field(default_factory=list)
    matched_pairs: list[tuple[GroundTruthItem, Finding]] = field(default_factory=list)
    sca_tp: list[ScaItem] = field(default_factory=list)
    sca_fn: list[ScaItem] = field(default_factory=list)


def _basename(path: str | None) -> str | None:
    return PurePosixPath(path).name if path else None


def _sast_matches(finding: Finding, item: GroundTruthItem, tol: int) -> bool:
    if finding.kind not in ("sast", "secret"):
        return False
    if _basename(finding.file) != _basename(item.file):
        return False
    if finding.line is None:
        return False
    return abs(finding.line - item.line) <= tol


def _sca_matches(finding: Finding, item: ScaItem) -> bool:
    if finding.kind != "sca":
        return False
    if (finding.package or "").lower() != item.name.lower():
        return False
    return (finding.version or "") == item.version


def match(findings: list[Finding], gt: GroundTruth, line_tolerance: int = 3) -> MatchResult:
    """Match a tool's findings against a package's ground truth.

    :param findings: normalized findings from one tool for one package.
    :param gt: the package ground truth.
    :param line_tolerance: max line distance for a SAST/secret match.
    :returns: the match result.
    :rtype: MatchResult
    """
    res = MatchResult()
    consumed: set[int] = set()

    # SAST / secret matching against every labeled item (incl. FP decoys).
    for item in gt.findings:
        hit: Finding | None = None
        for idx, f in enumerate(findings):
            if idx in consumed:
                continue
            if _sast_matches(f, item, line_tolerance):
                hit = f
                consumed.add(idx)
                break
        if hit is not None:
            if item.exploitability == "false-positive":
                res.fp.append(hit)  # tool reported a known FP decoy
            else:
                res.tp.append(item)
                res.matched_pairs.append((item, hit))
        elif item.exploitability != "false-positive":
            res.fn.append(item)  # a real/mitigated item the tool missed

    # SCA matching.
    sca_consumed: set[int] = set()
    for item in gt.sca:
        hit_sca = False
        for idx, f in enumerate(findings):
            if idx in sca_consumed:
                continue
            if _sca_matches(f, item):
                sca_consumed.add(idx)
                hit_sca = True
                break
        if hit_sca:
            res.sca_tp.append(item)
        else:
            res.sca_fn.append(item)

    # Any SAST/secret finding not matched to a labeled item is a false positive.
    for idx, f in enumerate(findings):
        if f.kind in ("sast", "secret") and idx not in consumed:
            res.fp.append(f)

    return res
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd harness && uv run pytest tests/score/test_match.py -v && cd .. && uv run pyright`
Expected: PASS (5 tests); pyright clean.

- [ ] **Step 5: Commit**

```bash
git add harness/src/eval_suite/score/ harness/tests/score/
git commit -m "feat: add findings-to-ground-truth matcher (SCA-426)"
```

---

### Task 7: Metrics (recall/precision, triage, remediation, diff)

**Files:**
- Create: `harness/src/eval_suite/score/metrics.py`
- Test: `harness/tests/score/test_metrics.py`

**Interfaces:**
- Consumes: `match.MatchResult`, `models.GroundTruth`, `models.Finding`.
- Produces:
  - `metrics.ToolScore` frozen dataclass: `tool: str`, `recall: float`, `precision: float`, `by_class: dict[str, tuple[float, float]]` (recall, precision), `by_ecosystem: dict[str, tuple[float, float]]`, `triage_accuracy: float | None`, `remediation_coverage: float | None`.
  - `metrics.score_tool(tool: str, per_pkg: list[tuple[GroundTruth, MatchResult, list[Finding]]]) -> ToolScore`.
  - `metrics.competitor_diff(scores: dict[str, ToolScore], per_pkg_by_tool: dict[str, list[tuple[GroundTruth, MatchResult]]], us: str) -> dict` returning `{"missed_by_us": [...], "missed_by_them": [...]}` keyed by class.
- Triage accuracy: over packages that contain at least one labeled item, fraction of labeled items handled correctly — real/mitigated reported, FP decoy NOT reported. `None` if no labeled SAST items overall.
- Remediation coverage: among `matched_pairs`, fraction whose `Finding.remediation` is non-empty. `None` if the tool produced no matched pairs.

- [ ] **Step 1: Write the failing test**

```python
# harness/tests/score/test_metrics.py
from eval_suite.models import Finding, GroundTruth, GroundTruthItem, ScaItem
from eval_suite.score.match import match
from eval_suite.score.metrics import score_tool


def _pkg(findings=(), sca=(), eco="pypi"):
    return GroundTruth(package="p", language="python", ecosystem=eco,
                       findings=list(findings), sca=list(sca))


def test_perfect_recall_precision():
    gt = _pkg(findings=[GroundTruthItem("F1", "a.py", 10, "CWE-79", "xss",
                                        "HIGH", "true-positive")])
    fnd = [Finding(tool="t", kind="sast", file="a.py", line=10, cwe="CWE-79")]
    res = match(fnd, gt)
    score = score_tool("t", [(gt, res, fnd)])
    assert score.recall == 1.0
    assert score.precision == 1.0
    assert score.by_class["xss"] == (1.0, 1.0)


def test_triage_penalizes_reporting_fp_decoy():
    gt = _pkg(findings=[
        GroundTruthItem("F1", "a.py", 10, "CWE-79", "xss", "HIGH", "true-positive"),
        GroundTruthItem("F3", "a.py", 30, "CWE-79", "xss", "HIGH", "false-positive"),
    ])
    fnd = [
        Finding(tool="t", kind="sast", file="a.py", line=10, cwe="CWE-79"),
        Finding(tool="t", kind="sast", file="a.py", line=30, cwe="CWE-79"),
    ]
    res = match(fnd, gt)
    score = score_tool("t", [(gt, res, fnd)])
    assert score.triage_accuracy == 0.5  # real handled right, FP wrongly reported


def test_remediation_coverage():
    gt = _pkg(sca=[ScaItem("log4j-core", "2.14.1", "maven", "CVE-2021-44228")])
    fnd = [Finding(tool="t", kind="sca", package="log4j-core", version="2.14.1",
                   cve="CVE-2021-44228", remediation="upgrade")]
    res = match(fnd, gt)
    score = score_tool("t", [(gt, res, fnd)])
    assert score.remediation_coverage == 1.0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd harness && uv run pytest tests/score/test_metrics.py -v`
Expected: FAIL — module missing.

- [ ] **Step 3: Write metrics**

```python
# harness/src/eval_suite/score/metrics.py
"""Compute recall/precision/triage/remediation scores from match results."""

from __future__ import annotations

from dataclasses import dataclass, field

from eval_suite.models import Finding, GroundTruth
from eval_suite.score.match import MatchResult


@dataclass(frozen=True)
class ToolScore:
    """Aggregate scores for one tool across the corpus."""

    tool: str
    recall: float
    precision: float
    by_class: dict[str, tuple[float, float]] = field(default_factory=dict)
    by_ecosystem: dict[str, tuple[float, float]] = field(default_factory=dict)
    triage_accuracy: float | None = None
    remediation_coverage: float | None = None


def _ratio(num: int, den: int) -> float:
    return num / den if den else 0.0


def score_tool(
    tool: str, per_pkg: list[tuple[GroundTruth, MatchResult, list[Finding]]]
) -> ToolScore:
    """Aggregate per-package match results into a tool score.

    :param tool: tool name.
    :param per_pkg: triples of (ground truth, match result, raw findings).
    :returns: aggregate score.
    :rtype: ToolScore
    """
    tp = fp = fn = 0
    class_tp: dict[str, int] = {}
    class_fn: dict[str, int] = {}
    class_fp: dict[str, int] = {}
    eco_tp: dict[str, int] = {}
    eco_fn: dict[str, int] = {}
    eco_fp: dict[str, int] = {}
    triage_total = triage_ok = 0
    remediable_total = remediable_ok = 0

    for gt, res, _findings in per_pkg:
        sast_tp = len(res.tp) + len(res.sca_tp)
        sast_fn = len(res.fn) + len(res.sca_fn)
        sast_fp = len(res.fp)
        tp += sast_tp
        fn += sast_fn
        fp += sast_fp

        eco_tp[gt.ecosystem] = eco_tp.get(gt.ecosystem, 0) + sast_tp
        eco_fn[gt.ecosystem] = eco_fn.get(gt.ecosystem, 0) + sast_fn
        eco_fp[gt.ecosystem] = eco_fp.get(gt.ecosystem, 0) + sast_fp

        for item, _f in res.matched_pairs:
            class_tp[item.klass] = class_tp.get(item.klass, 0) + 1
        for item in res.fn:
            class_fn[item.klass] = class_fn.get(item.klass, 0) + 1

        # Triage: each labeled SAST item is one decision.
        matched_ids = {item.id for item, _ in res.matched_pairs}
        for item in gt.findings:
            triage_total += 1
            if item.exploitability == "false-positive":
                # correct iff the tool did NOT report it (not in matched/fp by location)
                reported = any(
                    _f.file and item.file and _f.file.endswith(item.file.split("/")[-1])
                    and _f.line is not None and abs(_f.line - item.line) <= 3
                    for _f in res.fp
                )
                triage_ok += 0 if reported else 1
            else:
                triage_ok += 1 if item.id in matched_ids else 0

        # Remediation coverage over matched SAST pairs + matched SCA.
        for _item, f in res.matched_pairs:
            remediable_total += 1
            if f.remediation:
                remediable_ok += 1
        for item in res.sca_tp:
            remediable_total += 1
            # find the matching finding's remediation
            for f in _findings:
                if (f.package or "").lower() == item.name.lower() and (f.version or "") == item.version:
                    if f.remediation:
                        remediable_ok += 1
                    break

    by_class = {
        k: (
            _ratio(class_tp.get(k, 0), class_tp.get(k, 0) + class_fn.get(k, 0)),
            _ratio(class_tp.get(k, 0), class_tp.get(k, 0) + class_fp.get(k, 0)),
        )
        for k in set(class_tp) | set(class_fn)
    }
    by_eco = {
        k: (
            _ratio(eco_tp.get(k, 0), eco_tp.get(k, 0) + eco_fn.get(k, 0)),
            _ratio(eco_tp.get(k, 0), eco_tp.get(k, 0) + eco_fp.get(k, 0)),
        )
        for k in set(eco_tp) | set(eco_fn)
    }
    return ToolScore(
        tool=tool,
        recall=_ratio(tp, tp + fn),
        precision=_ratio(tp, tp + fp),
        by_class=by_class,
        by_ecosystem=by_eco,
        triage_accuracy=_ratio(triage_ok, triage_total) if triage_total else None,
        remediation_coverage=_ratio(remediable_ok, remediable_total) if remediable_total else None,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd harness && uv run pytest tests/score/test_metrics.py -v && cd .. && uv run pyright`
Expected: PASS (3 tests); pyright clean.

- [ ] **Step 5: Commit**

```bash
git add harness/src/eval_suite/score/metrics.py harness/tests/score/test_metrics.py
git commit -m "feat: add scoring metrics (recall/precision/triage/remediation) (SCA-426)"
```

---

### Task 8: Report renderer & trend/regression store

**Files:**
- Create: `harness/src/eval_suite/report/__init__.py`, `.../render.py`, `.../trend.py`
- Test: `harness/tests/report/__init__.py`, `.../test_render.py`, `.../test_trend.py`

**Interfaces:**
- Consumes: `metrics.ToolScore`.
- Produces:
  - `render.render_markdown(scores: list[ToolScore]) -> str`.
  - `render.render_json(scores: list[ToolScore]) -> dict`.
  - `trend.append_run(trend_path: Path, scores: list[ToolScore], stamp: str) -> None`.
  - `trend.check_regression(trend_path: Path, current: list[ToolScore], min_drop: float = 0.0) -> list[str]` — returns human-readable regression messages where a tool's per-class recall dropped vs. the previous run by more than `min_drop`.

- [ ] **Step 1: Write the failing tests**

```python
# harness/tests/report/test_render.py
from eval_suite.report.render import render_json, render_markdown
from eval_suite.score.metrics import ToolScore


def test_render_markdown_contains_tool_and_recall():
    s = ToolScore(tool="semgrep", recall=0.8, precision=0.9,
                  by_class={"xss": (1.0, 1.0)})
    md = render_markdown([s])
    assert "semgrep" in md
    assert "0.8" in md


def test_render_json_roundtrips_fields():
    s = ToolScore(tool="t", recall=0.5, precision=0.5)
    out = render_json([s])
    assert out["tools"][0]["tool"] == "t"
    assert out["tools"][0]["recall"] == 0.5
```

```python
# harness/tests/report/test_trend.py
from pathlib import Path

from eval_suite.report.trend import append_run, check_regression
from eval_suite.score.metrics import ToolScore


def test_regression_detected_when_recall_drops(tmp_path: Path):
    tp = tmp_path / "trend.json"
    append_run(tp, [ToolScore(tool="joern", recall=1.0, precision=1.0,
                              by_class={"ssrf": (1.0, 1.0)})], stamp="2026-06-23T00:00:00Z")
    msgs = check_regression(
        tp, [ToolScore(tool="joern", recall=0.0, precision=0.0,
                       by_class={"ssrf": (0.0, 0.0)})]
    )
    assert any("joern" in m and "ssrf" in m for m in msgs)


def test_no_regression_when_stable(tmp_path: Path):
    tp = tmp_path / "trend.json"
    append_run(tp, [ToolScore(tool="t", recall=1.0, precision=1.0,
                              by_class={"xss": (1.0, 1.0)})], stamp="2026-06-23T00:00:00Z")
    msgs = check_regression(
        tp, [ToolScore(tool="t", recall=1.0, precision=1.0,
                       by_class={"xss": (1.0, 1.0)})]
    )
    assert msgs == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd harness && uv run pytest tests/report/ -v`
Expected: FAIL — modules missing.

- [ ] **Step 3: Write renderer and trend store**

```python
# harness/src/eval_suite/report/__init__.py
"""Report rendering and trend tracking."""
```

```python
# harness/tests/report/__init__.py
```

```python
# harness/src/eval_suite/report/render.py
"""Render tool scores as markdown and JSON."""

from __future__ import annotations

from eval_suite.score.metrics import ToolScore


def render_json(scores: list[ToolScore]) -> dict:
    """Render scores as a JSON-serializable dict.

    :param scores: per-tool scores.
    :returns: serializable report.
    :rtype: dict
    """
    return {
        "tools": [
            {
                "tool": s.tool, "recall": s.recall, "precision": s.precision,
                "by_class": {k: list(v) for k, v in s.by_class.items()},
                "by_ecosystem": {k: list(v) for k, v in s.by_ecosystem.items()},
                "triage_accuracy": s.triage_accuracy,
                "remediation_coverage": s.remediation_coverage,
            }
            for s in scores
        ]
    }


def render_markdown(scores: list[ToolScore]) -> str:
    """Render scores as a markdown report.

    :param scores: per-tool scores.
    :returns: markdown text.
    :rtype: str
    """
    lines = ["# Eval Suite Report", "", "## Overall", "",
             "| Tool | Recall | Precision | Triage | Remediation |",
             "|---|---|---|---|---|"]
    for s in scores:
        triage = "n/a" if s.triage_accuracy is None else f"{s.triage_accuracy:.2f}"
        rem = "n/a" if s.remediation_coverage is None else f"{s.remediation_coverage:.2f}"
        lines.append(f"| {s.tool} | {s.recall} | {s.precision} | {triage} | {rem} |")
    lines.append("")
    lines.append("## Recall by class")
    lines.append("")
    for s in scores:
        for klass, (recall, _prec) in sorted(s.by_class.items()):
            lines.append(f"- {s.tool} / {klass}: recall={recall:.2f}")
    return "\n".join(lines)
```

```python
# harness/src/eval_suite/report/trend.py
"""Append run summaries to a trend file and detect recall regressions."""

from __future__ import annotations

import json
from pathlib import Path

from eval_suite.score.metrics import ToolScore


def _load(trend_path: Path) -> list[dict]:
    if not trend_path.exists():
        return []
    return json.loads(trend_path.read_text())


def append_run(trend_path: Path, scores: list[ToolScore], stamp: str) -> None:
    """Append a run summary to the trend file.

    :param trend_path: path to ``trend.json``.
    :param scores: per-tool scores for this run.
    :param stamp: ISO-8601 timestamp string for this run.
    :returns: ``None``.
    """
    history = _load(trend_path)
    history.append({
        "stamp": stamp,
        "tools": {
            s.tool: {
                "recall": s.recall,
                "by_class": {k: v[0] for k, v in s.by_class.items()},
            }
            for s in scores
        },
    })
    trend_path.write_text(json.dumps(history, indent=2))


def check_regression(
    trend_path: Path, current: list[ToolScore], min_drop: float = 0.0
) -> list[str]:
    """Compare current per-class recall to the most recent prior run.

    :param trend_path: path to ``trend.json`` holding prior runs.
    :param current: current per-tool scores.
    :param min_drop: only report drops strictly greater than this value.
    :returns: human-readable regression messages (empty if none).
    :rtype: list[str]
    """
    history = _load(trend_path)
    if not history:
        return []
    prev = history[-1]["tools"]
    msgs: list[str] = []
    for s in current:
        prev_classes = prev.get(s.tool, {}).get("by_class", {})
        for klass, (recall, _prec) in s.by_class.items():
            before = prev_classes.get(klass)
            if before is not None and (before - recall) > min_drop:
                msgs.append(
                    f"REGRESSION: {s.tool} / {klass} recall {before:.2f} -> {recall:.2f}"
                )
    return msgs
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd harness && uv run pytest tests/report/ -v && cd .. && uv run pyright`
Expected: PASS (4 tests); pyright clean.

- [ ] **Step 5: Commit**

```bash
git add harness/src/eval_suite/report/ harness/tests/report/
git commit -m "feat: add report renderer and trend/regression store (SCA-426)"
```

---

### Task 9: CLI runners for external tools

**Files:**
- Create: `harness/src/eval_suite/runners/__init__.py`, `.../base.py`, `.../semgrep.py`, `.../trivy.py`, `.../osv.py`, `.../codeql.py`, `.../snyk.py`, `.../claude_review.py`
- Test: `harness/tests/runners/__init__.py`, `.../test_base.py`, `.../test_semgrep.py`

**Interfaces:**
- Produces:
  - `base.RunResult(tool: str, returncode: int, stdout: str, stderr: str, raw: dict | None)` frozen dataclass.
  - `base.run_cmd(cmd: list[str], cwd: Path) -> RunResult` — subprocess wrapper, never raises on non-zero exit (records `returncode`), parses stdout JSON into `raw` when possible.
  - Each runner module exposes `run(target: Path) -> list[Finding]` and `NAME: str`, calling its CLI and the matching normalizer. Runners are tested via a fake `run_cmd` (monkeypatch) so no real CLI is required.

- [ ] **Step 1: Write the failing tests**

```python
# harness/tests/runners/test_base.py
from pathlib import Path

from eval_suite.runners.base import run_cmd


def test_run_cmd_captures_exit_and_json(tmp_path: Path):
    res = run_cmd(["python", "-c", "print('{\"ok\": 1}')"], cwd=tmp_path)
    assert res.returncode == 0
    assert res.raw == {"ok": 1}


def test_run_cmd_nonzero_does_not_raise(tmp_path: Path):
    res = run_cmd(["python", "-c", "import sys; sys.exit(3)"], cwd=tmp_path)
    assert res.returncode == 3
    assert res.raw is None
```

```python
# harness/tests/runners/test_semgrep.py
from pathlib import Path

import eval_suite.runners.semgrep as semgrep
from eval_suite.runners.base import RunResult

SARIF = {"runs": [{"tool": {"driver": {"name": "semgrep", "rules": [
    {"id": "r", "properties": {"tags": ["CWE-78"]}}]}},
    "results": [{"ruleId": "r", "level": "error", "message": {"text": "m"},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "app.py"},
                     "region": {"startLine": 42}}}]}]}]}


def test_semgrep_run_normalizes(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(
        semgrep, "run_cmd",
        lambda cmd, cwd: RunResult("semgrep", 0, "", "", SARIF),
    )
    findings = semgrep.run(tmp_path)
    assert findings[0].cwe == "CWE-78"
    assert findings[0].tool == "semgrep"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd harness && uv run pytest tests/runners/ -v`
Expected: FAIL — modules missing.

- [ ] **Step 3: Write base + runners**

```python
# harness/src/eval_suite/runners/__init__.py
"""External scanner CLI runners."""
```

```python
# harness/tests/runners/__init__.py
```

```python
# harness/src/eval_suite/runners/base.py
"""Subprocess helper for invoking external scanner CLIs."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RunResult:
    """Result of running an external CLI."""

    tool: str
    returncode: int
    stdout: str
    stderr: str
    raw: dict | None


def run_cmd(cmd: list[str], cwd: Path) -> RunResult:
    """Run a command, capturing output without raising on non-zero exit.

    :param cmd: argv list.
    :param cwd: working directory.
    :returns: the run result; ``raw`` is parsed JSON stdout when possible.
    :rtype: RunResult
    """
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    raw: dict | None = None
    try:
        raw = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        raw = None
    return RunResult(cmd[0], proc.returncode, proc.stdout, proc.stderr, raw)
```

```python
# harness/src/eval_suite/runners/semgrep.py
"""Run Semgrep OSS and normalize its SARIF output."""

from __future__ import annotations

from pathlib import Path

from eval_suite.models import Finding
from eval_suite.normalize.sarif import sarif_to_findings
from eval_suite.runners.base import RunResult, run_cmd

NAME = "semgrep"


def run(target: Path) -> list[Finding]:
    """Run Semgrep over a target and return normalized findings.

    :param target: package directory to scan.
    :returns: normalized findings.
    :rtype: list[Finding]
    """
    res: RunResult = run_cmd(
        ["semgrep", "--config", "auto", "--sarif", "--quiet", "."], cwd=target
    )
    if res.raw is None:
        return []
    return sarif_to_findings(res.raw, tool=NAME)
```

```python
# harness/src/eval_suite/runners/trivy.py
"""Run Trivy filesystem scan and normalize its SARIF output."""

from __future__ import annotations

from pathlib import Path

from eval_suite.models import Finding
from eval_suite.normalize.sarif import sarif_to_findings
from eval_suite.runners.base import run_cmd

NAME = "trivy"


def run(target: Path) -> list[Finding]:
    """Run Trivy over a target and return normalized SCA findings.

    :param target: package directory to scan.
    :returns: normalized findings.
    :rtype: list[Finding]
    """
    res = run_cmd(["trivy", "fs", "--format", "sarif", "."], cwd=target)
    if res.raw is None:
        return []
    return sarif_to_findings(res.raw, tool=NAME, kind="sca")
```

```python
# harness/src/eval_suite/runners/osv.py
"""Run OSV-Scanner and normalize its JSON output."""

from __future__ import annotations

from pathlib import Path

from eval_suite.models import Finding
from eval_suite.normalize.osv import osv_to_findings
from eval_suite.runners.base import run_cmd

NAME = "osv-scanner"


def run(target: Path) -> list[Finding]:
    """Run OSV-Scanner over a target and return normalized SCA findings.

    :param target: package directory to scan.
    :returns: normalized findings.
    :rtype: list[Finding]
    """
    res = run_cmd(["osv-scanner", "--format", "json", "-r", "."], cwd=target)
    if res.raw is None:
        return []
    return osv_to_findings(res.raw, tool=NAME)
```

```python
# harness/src/eval_suite/runners/codeql.py
"""Run CodeQL CLI (database create + analyze) and normalize SARIF.

CodeQL requires a per-language database build; this runner expects a prebuilt
SARIF at ``<target>/.codeql.sarif`` (produced by CI or a local script) to keep
the harness fast and CI-portable.
"""

from __future__ import annotations

import json
from pathlib import Path

from eval_suite.models import Finding
from eval_suite.normalize.sarif import sarif_to_findings

NAME = "codeql"


def run(target: Path) -> list[Finding]:
    """Load a prebuilt CodeQL SARIF for a target, if present.

    :param target: package directory.
    :returns: normalized findings (empty if no SARIF present).
    :rtype: list[Finding]
    """
    sarif_path = target / ".codeql.sarif"
    if not sarif_path.exists():
        return []
    return sarif_to_findings(json.loads(sarif_path.read_text()), tool=NAME)
```

```python
# harness/src/eval_suite/runners/snyk.py
"""Run Snyk (code + open-source) and normalize its SARIF output."""

from __future__ import annotations

from pathlib import Path

from eval_suite.models import Finding
from eval_suite.normalize.sarif import sarif_to_findings
from eval_suite.runners.base import run_cmd

NAME = "snyk"


def run(target: Path) -> list[Finding]:
    """Run Snyk Code over a target and return normalized findings.

    Requires ``SNYK_TOKEN`` in the environment; returns empty if unauthenticated.

    :param target: package directory to scan.
    :returns: normalized findings.
    :rtype: list[Finding]
    """
    res = run_cmd(["snyk", "code", "test", "--sarif", "."], cwd=target)
    if res.raw is None:
        return []
    return sarif_to_findings(res.raw, tool=NAME)
```

```python
# harness/src/eval_suite/runners/claude_review.py
"""Load Claude /security-review output for a target.

The /security-review command is run out-of-band; this runner reads its JSON
output from ``<target>/.claude-review.json`` when present.
"""

from __future__ import annotations

import json
from pathlib import Path

from eval_suite.models import Finding
from eval_suite.normalize.claude import claude_to_findings

NAME = "claude-security-review"


def run(target: Path) -> list[Finding]:
    """Load Claude security-review findings for a target, if present.

    :param target: package directory.
    :returns: normalized findings (empty if no output present).
    :rtype: list[Finding]
    """
    path = target / ".claude-review.json"
    if not path.exists():
        return []
    return claude_to_findings(json.loads(path.read_text()), tool=NAME)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd harness && uv run pytest tests/runners/ -v && cd .. && uv run pyright`
Expected: PASS; pyright clean.

- [ ] **Step 5: Commit**

```bash
git add harness/src/eval_suite/runners/ harness/tests/runners/
git commit -m "feat: add external scanner CLI runners (SCA-426)"
```

---

### Task 10: CLI orchestration (`eval run | score | report`)

**Files:**
- Create: `harness/src/eval_suite/cli.py`
- Modify: `pyproject.toml` (add `[project.scripts]` entry `eval-suite = "eval_suite.cli:main"`)
- Test: `harness/tests/test_cli.py`

**Interfaces:**
- Consumes: `groundtruth.discover_corpus`, all runners, `score.match.match`, `score.metrics.score_tool`, `report.render`, `report.trend`, `normalize.scntnms`.
- Produces:
  - `cli.score_corpus(corpus_root: Path, findings_by_tool: dict[str, list[Finding]], by_package: dict[str, dict[str, list[Finding]]]) -> list[ToolScore]` — pure scoring entry point (no subprocess), used by the acceptance test.
  - `cli.main(argv: list[str] | None = None) -> int`.
- `score_corpus` groups findings per package per tool, matches, and aggregates. Findings are bucketed to packages by the `file`/path prefix or supplied mapping; for SCA, by package directory.

- [ ] **Step 1: Write the failing test**

```python
# harness/tests/test_cli.py
from pathlib import Path

from eval_suite.cli import score_corpus
from eval_suite.models import Finding


def _make_corpus(tmp_path: Path) -> Path:
    d = tmp_path / "python" / "py-xss"
    d.mkdir(parents=True)
    (d / "groundtruth.yaml").write_text(
        "package: py-xss\nlanguage: python\necosystem: pypi\n"
        "findings:\n  - id: F1\n    file: app.py\n    line: 10\n"
        "    cwe: CWE-79\n    class: xss\n    severity: HIGH\n"
        "    exploitability: true-positive\nsca: []\n"
    )
    return tmp_path


def test_score_corpus_perfect_tool(tmp_path: Path):
    corpus = _make_corpus(tmp_path)
    by_package = {
        "py-xss": {"semgrep": [Finding(tool="semgrep", kind="sast",
                                       file="app.py", line=10, cwe="CWE-79")]}
    }
    scores = score_corpus(corpus, by_package)
    semgrep = next(s for s in scores if s.tool == "semgrep")
    assert semgrep.recall == 1.0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd harness && uv run pytest tests/test_cli.py -v`
Expected: FAIL — module/signature missing.

- [ ] **Step 3: Write the CLI**

```python
# harness/src/eval_suite/cli.py
"""Command-line entry point for the evaluation suite."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from eval_suite.groundtruth import discover_corpus, load_groundtruth
from eval_suite.models import Finding
from eval_suite.normalize.scntnms import scntnms_to_findings
from eval_suite.report.render import render_json, render_markdown
from eval_suite.report.trend import append_run, check_regression
from eval_suite.runners import claude_review, codeql, osv, semgrep, snyk, trivy
from eval_suite.score.match import match
from eval_suite.score.metrics import ToolScore, score_tool

_RUNNERS = [semgrep, trivy, osv, codeql, snyk, claude_review]


def score_corpus(
    corpus_root: Path, by_package: dict[str, dict[str, list[Finding]]]
) -> list[ToolScore]:
    """Score every tool against the corpus from pre-collected findings.

    :param corpus_root: directory of labeled packages.
    :param by_package: mapping package -> tool -> findings.
    :returns: per-tool aggregate scores.
    :rtype: list[ToolScore]
    """
    corpus = discover_corpus(corpus_root)
    tools = {t for pkg in by_package.values() for t in pkg}
    scores: list[ToolScore] = []
    for tool in sorted(tools):
        per_pkg = []
        for gt in corpus:
            findings = by_package.get(gt.package, {}).get(tool, [])
            per_pkg.append((gt, match(findings, gt), findings))
        scores.append(score_tool(tool, per_pkg))
    return scores


def _collect(corpus_root: Path) -> dict[str, dict[str, list[Finding]]]:
    """Run every available runner over every package (live scan)."""
    by_package: dict[str, dict[str, list[Finding]]] = {}
    for gt_path in sorted(corpus_root.rglob("groundtruth.yaml")):
        target = gt_path.parent
        gt = load_groundtruth(gt_path)
        by_package[gt.package] = {r.NAME: r.run(target) for r in _RUNNERS}
    return by_package


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    :param argv: argument vector (defaults to ``sys.argv``).
    :returns: process exit code.
    :rtype: int
    """
    parser = argparse.ArgumentParser(prog="eval-suite")
    parser.add_argument("--corpus", type=Path, default=Path("corpus"))
    parser.add_argument("--out", type=Path, default=Path("results/report"))
    parser.add_argument("--trend", type=Path, default=Path("results/trend.json"))
    parser.add_argument("--stamp", default="manual")
    parser.add_argument("--scntnms-export", type=Path, default=None)
    parser.add_argument("--fail-on-regression", action="store_true")
    args = parser.parse_args(argv)

    by_package = _collect(args.corpus)
    if args.scntnms_export and args.scntnms_export.exists():
        data = json.loads(args.scntnms_export.read_text())
        # export is a mapping package -> findings export dict
        for pkg, export in data.items():
            by_package.setdefault(pkg, {})["scntnms"] = scntnms_to_findings(
                export, tool="scntnms"
            )

    scores = score_corpus(args.corpus, by_package)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.with_suffix(".md").write_text(render_markdown(scores))
    args.out.with_suffix(".json").write_text(json.dumps(render_json(scores), indent=2))

    regressions = check_regression(args.trend, scores)
    args.trend.parent.mkdir(parents=True, exist_ok=True)
    append_run(args.trend, scores, stamp=args.stamp)
    for msg in regressions:
        print(msg)
    if regressions and args.fail_on_regression:
        return 1
    return 0
```

```toml
# append to pyproject.toml
[project.scripts]
eval-suite = "eval_suite.cli:main"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd harness && uv run pytest tests/test_cli.py -v && cd .. && uv run pyright && uv run ruff check .`
Expected: PASS; pyright + ruff clean.

- [ ] **Step 5: Commit**

```bash
git add harness/src/eval_suite/cli.py harness/tests/test_cli.py pyproject.toml
git commit -m "feat: add CLI orchestration for run/score/report (SCA-426)"
```

---

### Task 11: Python corpus packages (6)

**Files (create each package dir under `corpus/python/`):**
- `py-webapp-cmdi/` — `app.py`, `requirements.txt`, `groundtruth.yaml`, `README.md`
- `py-noentry-lib/` — `fetcher.py`, `pyproject.toml`, `groundtruth.yaml`, `README.md`
- `py-sca-pypi-old/` — `requirements.txt`, `groundtruth.yaml`, `README.md`
- `py-secrets-basicauth/` — `config.py`, `groundtruth.yaml`, `README.md`
- `py-xss-triad/` — `app.py`, `groundtruth.yaml`, `README.md`
- `py-medsev-bug/` — `crypto_util.py`, `groundtruth.yaml`, `README.md`
- Test: `harness/tests/test_corpus_integrity.py`

**Interfaces:**
- Produces: 6 valid corpus packages whose `groundtruth.yaml` line numbers point at the real planted lines.

- [ ] **Step 1: Write the failing integrity test**

```python
# harness/tests/test_corpus_integrity.py
from pathlib import Path

from eval_suite.groundtruth import discover_corpus

CORPUS = Path(__file__).resolve().parents[2] / "corpus"


def test_all_groundtruth_valid_and_lines_exist():
    packages = discover_corpus(CORPUS)
    assert packages, "no corpus packages found"
    for gt in packages:
        pkg_dir = next(CORPUS.rglob(f"{gt.package}/groundtruth.yaml")).parent
        for item in gt.findings:
            src = pkg_dir / item.file
            assert src.exists(), f"{gt.package}: missing {item.file}"
            n_lines = len(src.read_text().splitlines())
            assert 1 <= item.line <= n_lines, f"{gt.package}:{item.file}:{item.line} OOB"


def test_python_corpus_has_expected_packages():
    names = {g.package for g in discover_corpus(CORPUS)}
    assert {"py-webapp-cmdi", "py-noentry-lib", "py-sca-pypi-old",
            "py-secrets-basicauth", "py-xss-triad", "py-medsev-bug"} <= names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd harness && uv run pytest tests/test_corpus_integrity.py -v`
Expected: FAIL — corpus packages missing.

- [ ] **Step 3: Author the packages**

`corpus/python/py-webapp-cmdi/app.py`:

```python
"""Flask app with an OS command injection sink (planted vuln)."""

import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # VULN: user-controlled host concatenated into a shell command.
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)  # noqa: S602


if __name__ == "__main__":
    app.run()
```

`corpus/python/py-webapp-cmdi/requirements.txt`:

```
flask==3.0.0
```

`corpus/python/py-webapp-cmdi/groundtruth.yaml`:

```yaml
package: py-webapp-cmdi
language: python
ecosystem: pypi
findings:
  - id: F1
    file: app.py
    line: 13
    cwe: CWE-78
    class: command-injection
    severity: HIGH
    exploitability: true-positive
    notes: user-controlled host in shell=True command
sca: []
```

`corpus/python/py-noentry-lib/fetcher.py` (no web entry point — exposes RC01):

```python
"""A plain library with SSRF and path traversal sinks and no entry point."""

import urllib.request


def fetch(url: str) -> bytes:
    # VULN: SSRF — caller-supplied URL fetched with no allowlist.
    with urllib.request.urlopen(url) as resp:  # noqa: S310
        return resp.read()


def read_user_file(base: str, name: str) -> str:
    # VULN: path traversal — name joined without normalization checks.
    path = base + "/" + name
    with open(path, encoding="utf-8") as fh:
        return fh.read()
```

`corpus/python/py-noentry-lib/pyproject.toml`:

```toml
[project]
name = "noentry-lib"
version = "0.0.1"
requires-python = ">=3.13"
```

`corpus/python/py-noentry-lib/groundtruth.yaml`:

```yaml
package: py-noentry-lib
language: python
ecosystem: pypi
findings:
  - id: F1
    file: fetcher.py
    line: 8
    cwe: CWE-918
    class: ssrf
    severity: HIGH
    exploitability: true-positive
    notes: caller-supplied URL, no allowlist; no web entry point (RC01)
  - id: F2
    file: fetcher.py
    line: 15
    cwe: CWE-22
    class: path-traversal
    severity: HIGH
    exploitability: true-positive
    notes: unnormalized path join
sca: []
```

`corpus/python/py-sca-pypi-old/requirements.txt` (old, known-vulnerable — exposes RC02):

```
requests==2.5.0
pyyaml==5.3
jinja2==2.10
```

`corpus/python/py-sca-pypi-old/groundtruth.yaml`:

```yaml
package: py-sca-pypi-old
language: python
ecosystem: pypi
findings: []
sca:
  - name: requests
    version: 2.5.0
    ecosystem: pypi
    cve: CVE-2018-18074
    severity: HIGH
  - name: pyyaml
    version: "5.3"
    ecosystem: pypi
    cve: CVE-2020-14343
    severity: CRITICAL
  - name: jinja2
    version: "2.10"
    ecosystem: pypi
    cve: CVE-2019-10906
    severity: HIGH
```

`corpus/python/py-secrets-basicauth/config.py` (basic-auth-in-URL — exposes RC03):

```python
"""Config module with planted secrets, including basic-auth-in-URL."""

# VULN: basic-auth credentials embedded in a URL (RC03).
DATABASE_URL = "postgres://admin:S3cr3tP@ssw0rd@db.internal:5432/app"

# VULN: hardcoded API key.
STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
```

`corpus/python/py-secrets-basicauth/groundtruth.yaml`:

```yaml
package: py-secrets-basicauth
language: python
ecosystem: pypi
findings:
  - id: F1
    file: config.py
    line: 4
    cwe: CWE-798
    class: secret-basic-auth-url
    severity: HIGH
    exploitability: true-positive
    notes: basic-auth-in-URL (RC03)
  - id: F2
    file: config.py
    line: 7
    cwe: CWE-798
    class: secret-api-key
    severity: HIGH
    exploitability: true-positive
    notes: hardcoded live API key
sca: []
```

`corpus/python/py-xss-triad/app.py` (real / mitigated / FP — exposes RC05; mirror lines 113/118/128 by padding with a leading docstring so the planted lines land exactly):

```python
"""XSS triad fixture.

This leading block is intentionally padded so the three planted sinks land on
lines 113, 118, and 128 to mirror the codelion example exactly. Do not reflow.
"""

# ----------------------------------------------------------------------------
# Padding block (kept verbatim; lines 8-110 are filler comments).
# ... (the implementer fills lines 8-110 with the numbered filler comments
#     shown below so the sinks land on the exact lines) ...
```

> Implementer note: generate filler lines 8–110 as `# filler NNN` comments so
> the three functions below begin at the exact lines. Verify with
> `awk 'NR==113||NR==118||NR==128'` before committing. The functions:

```python
from flask import Flask, escape, request

app = Flask(__name__)


@app.route("/reflect")
def reflect():
    name = request.args.get("name", "")
    return f"<h1>Hello {name}</h1>"            # line 113: real reflected XSS


@app.route("/safe")
def safe():
    name = request.args.get("name", "")
    return f"<h1>Hello {escape(name)}</h1>"    # line 118: mitigated-by-design


@app.route("/static")
def static_banner():
    label = "welcome"
    return f"<h1>{label}</h1>"                 # line 128: static-literal FP
```

`corpus/python/py-xss-triad/groundtruth.yaml`:

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
    exploitability: true-positive
    notes: user input rendered without escaping
  - id: F2
    file: app.py
    line: 118
    cwe: CWE-79
    class: xss-reflected
    severity: HIGH
    exploitability: mitigated-by-design
    notes: flask.escape applied
  - id: F3
    file: app.py
    line: 128
    cwe: CWE-79
    class: xss-reflected
    severity: HIGH
    exploitability: false-positive
    notes: static literal, not user-controlled
sca: []
```

`corpus/python/py-medsev-bug/crypto_util.py` (real MEDIUM bug — exposes RC04):

```python
"""Utility with a MEDIUM-severity weak-hash bug (planted)."""

import hashlib


def fingerprint(data: bytes) -> str:
    # VULN (MEDIUM): MD5 used for a security-relevant fingerprint.
    return hashlib.md5(data).hexdigest()  # noqa: S324
```

`corpus/python/py-medsev-bug/groundtruth.yaml`:

```yaml
package: py-medsev-bug
language: python
ecosystem: pypi
findings:
  - id: F1
    file: crypto_util.py
    line: 7
    cwe: CWE-327
    class: weak-hash
    severity: MEDIUM
    exploitability: true-positive
    notes: MD5 for security fingerprint (RC04 remediation-gate target)
sca: []
```

Add a short `README.md` in each package describing the planted vuln(s) and the RC it exercises.

- [ ] **Step 4: Verify line numbers, then run the integrity test**

Run:
```bash
awk 'NR==113||NR==118||NR==128{print NR": "$0}' corpus/python/py-xss-triad/app.py
cd harness && uv run pytest tests/test_corpus_integrity.py -v
```
Expected: the three lines print the matching sinks; integrity test PASS.

- [ ] **Step 5: Commit**

```bash
git add corpus/python harness/tests/test_corpus_integrity.py
git commit -m "feat: add Python corpus packages reproducing RC01-RC05 (SCA-426)"
```

---

### Task 12: Java corpus packages (2)

**Files (under `corpus/java/`):**
- `java-sca-maven-old/` — `pom.xml`, `groundtruth.yaml`, `README.md` (RC02 control — ODC *should* catch)
- `java-cmdi-sqli/` — `pom.xml`, `src/main/java/com/example/App.java`, `groundtruth.yaml`, `README.md`
- Test: extend `harness/tests/test_corpus_integrity.py`

**Interfaces:**
- Produces: 2 valid Java packages; `java-sca-maven-old` is the Maven SCA control contrasted against `py-sca-pypi-old` for RC02.

- [ ] **Step 1: Extend the failing test**

```python
# append to harness/tests/test_corpus_integrity.py
def test_java_corpus_has_expected_packages():
    from eval_suite.groundtruth import discover_corpus
    names = {g.package for g in discover_corpus(CORPUS)}
    assert {"java-sca-maven-old", "java-cmdi-sqli"} <= names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd harness && uv run pytest tests/test_corpus_integrity.py::test_java_corpus_has_expected_packages -v`
Expected: FAIL — Java packages missing.

- [ ] **Step 3: Author the Java packages**

`corpus/java/java-sca-maven-old/pom.xml`:

```xml
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>sca-maven-old</artifactId>
  <version>0.0.1</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.9.8</version>
    </dependency>
  </dependencies>
</project>
```

`corpus/java/java-sca-maven-old/groundtruth.yaml`:

```yaml
package: java-sca-maven-old
language: java
ecosystem: maven
findings: []
sca:
  - name: log4j-core
    version: 2.14.1
    ecosystem: maven
    cve: CVE-2021-44228
    severity: CRITICAL
  - name: jackson-databind
    version: 2.9.8
    ecosystem: maven
    cve: CVE-2019-12384
    severity: HIGH
```

`corpus/java/java-cmdi-sqli/src/main/java/com/example/App.java`:

```java
package com.example;

import java.sql.Connection;
import java.sql.Statement;

public class App {
    public String run(String host) throws Exception {
        // VULN: OS command injection via user-controlled host.
        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
        return new String(p.getInputStream().readAllBytes());
    }

    public void lookup(Connection conn, String user) throws Exception {
        Statement st = conn.createStatement();
        // VULN: SQL injection via string concatenation.
        st.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
    }
}
```

`corpus/java/java-cmdi-sqli/pom.xml`:

```xml
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>cmdi-sqli</artifactId>
  <version>0.0.1</version>
</project>
```

`corpus/java/java-cmdi-sqli/groundtruth.yaml`:

```yaml
package: java-cmdi-sqli
language: java
ecosystem: maven
findings:
  - id: F1
    file: src/main/java/com/example/App.java
    line: 9
    cwe: CWE-78
    class: command-injection
    severity: HIGH
    exploitability: true-positive
    notes: user-controlled host in Runtime.exec
  - id: F2
    file: src/main/java/com/example/App.java
    line: 16
    cwe: CWE-89
    class: sql-injection
    severity: HIGH
    exploitability: true-positive
    notes: string-concatenated SQL
sca: []
```

Add `README.md` in each.

- [ ] **Step 4: Verify lines, run integrity test**

Run:
```bash
awk 'NR==9||NR==16{print NR": "$0}' corpus/java/java-cmdi-sqli/src/main/java/com/example/App.java
cd harness && uv run pytest tests/test_corpus_integrity.py -v
```
Expected: lines match the planted sinks; all integrity tests PASS.

- [ ] **Step 5: Commit**

```bash
git add corpus/java harness/tests/test_corpus_integrity.py
git commit -m "feat: add Java corpus packages incl. Maven SCA control (SCA-426)"
```

---

### Task 13: Acceptance test — reproduce RC01–RC05

**Files:**
- Create: `harness/tests/acceptance/__init__.py`, `harness/tests/acceptance/test_rc_reproduction.py`
- Create: `harness/tests/acceptance/fixtures/` — recorded per-tool findings JSON (so the test runs in CI without paid/live tools).

**Interfaces:**
- Consumes: `cli.score_corpus`, `score.metrics.competitor_diff` style logic (inline in test).
- Produces: a single acceptance test class asserting each of RC01–RC05 is independently detected from fixture findings.

The fixtures encode the *known* behavior: Scantonomous AI returns nothing on `py-noentry-lib` (RC01); ODC (scntnms) misses PyPI SCA but a competitor catches it while Maven is caught (RC02); scntnms misses the basic-auth secret a competitor finds (RC03); scntnms reports the MEDIUM bug with `remediation: null` (RC04); a tool reports the XSS FP decoy (RC05).

- [ ] **Step 1: Write the failing acceptance test**

```python
# harness/tests/acceptance/test_rc_reproduction.py
from pathlib import Path

from eval_suite.cli import score_corpus
from eval_suite.models import Finding

CORPUS = Path(__file__).resolve().parents[3] / "corpus"


def _scn(**kw):
    return Finding(tool="scntnms", **kw)


def _comp(tool, **kw):
    return Finding(tool=tool, **kw)


def _by_package():
    return {
        "py-noentry-lib": {
            "scntnms": [],  # RC01: AI scan silent-zero on no-entry-point repo
            "semgrep": [_comp("semgrep", kind="sast", file="fetcher.py", line=8, cwe="CWE-918")],
        },
        "py-sca-pypi-old": {
            "scntnms": [],  # RC02: ODC misses PyPI
            "osv-scanner": [_comp("osv-scanner", kind="sca", package="requests",
                                  version="2.5.0", cve="CVE-2018-18074")],
        },
        "java-sca-maven-old": {
            "scntnms": [_scn(kind="sca", package="log4j-core", version="2.14.1",
                             cve="CVE-2021-44228")],  # RC02 control: Maven IS caught
        },
        "py-secrets-basicauth": {
            "scntnms": [],  # RC03: no basic-auth-in-URL rule
            "trivy": [_comp("trivy", kind="secret", file="config.py", line=4, cwe="CWE-798")],
        },
        "py-medsev-bug": {
            "scntnms": [_scn(kind="sast", file="crypto_util.py", line=7, cwe="CWE-327",
                             severity="MEDIUM", remediation=None)],  # RC04
        },
        "py-xss-triad": {
            # RC05: tool reports the FP decoy at line 128 -> triage < 1.0
            "scntnms": [
                _scn(kind="sast", file="app.py", line=113, cwe="CWE-79"),
                _scn(kind="sast", file="app.py", line=128, cwe="CWE-79"),
            ],
        },
    }


def _score(tool):
    scores = score_corpus(CORPUS, _by_package())
    return next(s for s in scores if s.tool == tool)


def test_rc01_joern_silent_zero():
    scn = _score("scntnms")
    # Scantonomous catches nothing for ssrf; a competitor does.
    assert scn.by_class.get("ssrf", (0.0, 0.0))[0] == 0.0
    assert _score("semgrep").by_class["ssrf"][0] == 1.0


def test_rc02_non_maven_sca_gap():
    scn = _score("scntnms")
    osv = _score("osv-scanner")
    # PyPI ecosystem recall: scntnms 0, competitor 1; Maven recall for scntnms 1.
    assert scn.by_ecosystem.get("pypi", (0.0, 0.0))[0] == 0.0
    assert osv.by_ecosystem["pypi"][0] == 1.0
    assert scn.by_ecosystem["maven"][0] == 1.0


def test_rc03_basic_auth_secret_gap():
    scn = _score("scntnms")
    assert scn.by_class.get("secret-basic-auth-url", (0.0, 0.0))[0] == 0.0
    assert _score("trivy").by_class["secret-basic-auth-url"][0] == 1.0


def test_rc04_remediation_gate_on_medium():
    scn = _score("scntnms")
    # The MEDIUM finding matched but carried no remediation.
    assert scn.remediation_coverage is not None
    assert scn.remediation_coverage < 1.0


def test_rc05_triage_fails_on_fp_decoy():
    scn = _score("scntnms")
    assert scn.triage_accuracy is not None
    assert scn.triage_accuracy < 1.0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd harness && uv run pytest tests/acceptance/ -v`
Expected: FAIL initially if any class/ecosystem keys differ — adjust corpus `class`/`ecosystem` labels or metric keys until all five pass. (They should pass once Tasks 6–12 are correct.)

- [ ] **Step 3: Make it pass**

No new production code expected. If a test fails, the discrepancy is a real bug in matching/metrics or a label mismatch — fix the offending module or ground-truth label, not the test's intent.

- [ ] **Step 4: Run the full suite**

Run: `cd harness && uv run pytest -v && cd .. && uv run ruff check . && uv run pyright`
Expected: all tests PASS; lint + types clean.

- [ ] **Step 5: Commit**

```bash
git add harness/tests/acceptance/
git commit -m "test: acceptance suite reproduces RC01-RC05 (SCA-426)"
```

---

### Task 14: CI workflow & README

**Files:**
- Create: `.github/workflows/eval.yml`
- Create/expand: `README.md` (usage: how to run live scans, how to drop a Scantonomous export, how CI gates regressions)

**Interfaces:**
- Produces: CI that installs uv, runs lint/type/tests, runs the free CLIs (semgrep/trivy/osv) over the corpus, and fails on a recall regression.

- [ ] **Step 1: Write the workflow**

```yaml
# .github/workflows/eval.yml
name: eval
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
      - run: uv sync
      - run: cd harness && uv run pytest -v
      - run: uv run ruff check . && uv run pyright
  baseline:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
      - run: uv sync
      - run: pipx install semgrep
      - uses: aquasecurity/trivy-action@0.24.0
        with: { scan-type: fs, scan-ref: corpus, format: sarif, output: /dev/null }
      - run: |
          curl -sSfL https://raw.githubusercontent.com/google/osv-scanner/main/scripts/install.sh | sh -s -- -b "$HOME/.local/bin"
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - run: uv run eval-suite --corpus corpus --fail-on-regression
      - uses: actions/upload-artifact@v4
        with: { name: eval-report, path: results/ }
```

- [ ] **Step 2: Validate workflow YAML locally**

Run: `python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/eval.yml')); print('ok')"`
Expected: prints `ok`.

- [ ] **Step 3: Write README usage section**

Document: `uv sync`; `uv run eval-suite` to run the free CLIs + score; running CodeQL/Snyk/Claude out-of-band and dropping their outputs (`.codeql.sarif`, `.claude-review.json`, `SNYK_TOKEN`); exporting Scantonomous findings and passing `--scntnms-export`; reading `results/report.md` and `results/trend.json`.

- [ ] **Step 4: Final full verification**

Run: `cd harness && uv run pytest -v && cd .. && uv run ruff check . && uv run pyright`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/eval.yml README.md
git commit -m "ci: add eval workflow and usage docs (SCA-426)"
```

---

## Self-Review

**Spec coverage:**
- Standalone repo, two halves (corpus + harness) → Tasks 1, 11–12 (corpus), 3–10 (harness). ✓
- Authored-only, Python+Java, ground-truth-first → Tasks 11–12, schema Task 2. ✓
- Ground-truth schema incl. exploitability triad → Task 2 + `py-xss-triad` in Task 11. ✓
- Normalization (SARIF + OSV + Claude + Scantonomous import) → Tasks 4–5. ✓
- Scoring (recall/precision per class & ecosystem, triage, remediation, diff) → Tasks 6–7. ✓
- Baseline tools (semgrep/trivy/osv/codeql/snyk/claude) → Task 9; Scantonomous import → Tasks 5, 10. ✓
- Trend/regression + CI → Tasks 8, 14. ✓
- Acceptance reproduces RC01–RC05 → Task 13. ✓
- Competitor diff: covered by per-tool `by_class`/`by_ecosystem` comparison in the acceptance test; a dedicated `competitor_diff` helper is described in Task 7's interface but the acceptance test derives the diff directly from `ToolScore`. **Resolved:** the diff is computed in the report layer from per-tool scores; no separate module needed for v1 — Task 8 renderer shows per-tool recall side by side. (If a structured diff object is later wanted, add to `metrics.py`.)

**Placeholder scan:** The only deferred content is the `py-xss-triad` filler lines 8–110 (Task 11), which is mechanical and has an explicit verification command (`awk`) — acceptable and self-checking, not a logic placeholder.

**Type consistency:** `Finding`, `GroundTruth*`, `MatchResult`, `ToolScore` field names are used identically across Tasks 3–13. `run(target)`/`NAME` runner contract is consistent across Task 9 and consumed uniformly in Task 10 `_collect`. `score_corpus(corpus_root, by_package)` signature matches between Task 10 definition and Task 13 usage.
