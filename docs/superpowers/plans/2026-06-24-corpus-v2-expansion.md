# Corpus v2 Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand the authored corpus from 8 packages (Python+Java) to ~23 by adding four more ecosystems (Go/Rust/Ruby/.NET), more SAST vuln classes in Python/Java, and two larger multi-file realistic apps — without changing the scoring engine.

**Architecture:** The harness is complete and stable (42 tests passing). This expansion is almost entirely *data* (new `corpus/` packages + `groundtruth.yaml`). The only harness change is widening the ground-truth schema's `language`/`ecosystem` enums and updating the corpus-integrity test. The matcher keys SCA on package+version and `by_ecosystem` keys on the ground-truth package's ecosystem string, so new ecosystems work once the schema admits them.

**Tech Stack:** Existing Python 3.13 harness (uv/ruff/pyright/pytest). New corpus packages: Go (go.mod), Rust (Cargo.lock), Ruby (Gemfile.lock), .NET (.csproj), plus more Python/Java.

## Global Constraints

- Python floor 3.13; uv only (`uv run <tool>`); ruff + pyright + pytest for the harness.
- Corpus is **authored-only** (no vendored third-party repos); clean licensing.
- Corpus files are **intentionally vulnerable** — planted sinks (shell exec, pickle, XXE, SQLi, SSRF, hardcoded fake secrets) are correct scan targets, NOT defects to fix. Fake secrets are illustrative non-functional placeholders.
- Corpus is excluded from the repo's own ruff/pyright (already configured via `src`/`include`); if a new corpus file trips lint/type, add an exclude — do not sanitize the vuln.
- Every `groundtruth.yaml` validates against `schema/groundtruth.schema.json`; every finding's `line` MUST point at the actual planted sink (verify with `awk`/inspection — the integrity test only checks in-range).
- Exploitability vocab (exact): `true-positive`, `mitigated-by-design`, `false-positive`. Finding kind: `sast`, `sca`, `secret`.
- Ecosystem enum (v2 full set): `pypi`, `maven`, `go`, `cargo`, `rubygems`, `nuget`. Language enum: `python`, `java`, `go`, `rust`, `ruby`, `csharp`.
- Conventional Commits including `(SCA-426)`.

---

## File Structure

- `schema/groundtruth.schema.json` — widen `language`, `ecosystem`, and `sca[].ecosystem` enums.
- `harness/tests/test_corpus_integrity.py` — add per-ecosystem/per-package presence assertions; keep the existing in-range line check (it already iterates all packages).
- `corpus/go/…`, `corpus/rust/…`, `corpus/ruby/…`, `corpus/dotnet/…` — new ecosystem packages.
- `corpus/python/…`, `corpus/java/…` — new vuln-class packages + the two larger apps.

Each package: source + manifest + `groundtruth.yaml` + `README.md` (names planted vuln(s) + class/CWE).

---

### Task 1: Widen ground-truth schema enums + integrity test

**Files:**
- Modify: `schema/groundtruth.schema.json`
- Modify: `harness/tests/test_corpus_integrity.py`
- Test: same file (extend)

**Interfaces:**
- Produces: schema accepting languages {python,java,go,rust,ruby,csharp} and ecosystems {pypi,maven,go,cargo,rubygems,nuget} at top-level `language`/`ecosystem` and `sca[].ecosystem`.

- [ ] **Step 1: Write the failing test**

Add to `harness/tests/test_corpus_integrity.py`:

```python
def test_schema_accepts_new_ecosystems():
    import json
    from pathlib import Path

    import jsonschema

    schema = json.loads(
        (Path(__file__).resolve().parents[2] / "schema" / "groundtruth.schema.json").read_text()
    )
    sample = {
        "package": "go-sca-old",
        "language": "go",
        "ecosystem": "go",
        "findings": [],
        "sca": [{"name": "x", "version": "1.0.0", "ecosystem": "go"}],
    }
    jsonschema.validate(sample, schema)  # must not raise
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd harness && uv run pytest tests/test_corpus_integrity.py::test_schema_accepts_new_ecosystems -v`
Expected: FAIL — `"go"` not in the language/ecosystem enums.

- [ ] **Step 3: Widen the schema**

In `schema/groundtruth.schema.json`:
- `language` enum → `["python", "java", "go", "rust", "ruby", "csharp"]`
- top-level `ecosystem` enum → `["pypi", "maven", "go", "cargo", "rubygems", "nuget"]`
- `sca.items.properties.ecosystem` enum → `["pypi", "maven", "go", "cargo", "rubygems", "nuget"]`

- [ ] **Step 4: Run test to verify it passes**

Run: `cd harness && uv run pytest tests/test_corpus_integrity.py -v && cd .. && uv run pyright`
Expected: PASS (incl. existing integrity tests); pyright clean.

- [ ] **Step 5: Commit**

```bash
git add schema/groundtruth.schema.json harness/tests/test_corpus_integrity.py
git commit -m "feat: widen ground-truth schema for go/rust/ruby/nuget ecosystems (SCA-426)"
```

---

### Task 2: Go packages (go-sca-old, go-cmdi)

**Files (under `corpus/go/`):**
- `go-sca-old/` — `go.mod`, `go.sum`, `groundtruth.yaml`, `README.md`
- `go-cmdi/` — `go.mod`, `main.go`, `groundtruth.yaml`, `README.md`
- Test: extend `harness/tests/test_corpus_integrity.py`

**Interfaces:** 2 valid Go packages; `go-sca-old` exercises non-Maven SCA (RC02 breadth).

- [ ] **Step 1: Extend the failing test**

```python
def test_go_corpus_present():
    from eval_suite.groundtruth import discover_corpus
    names = {g.package for g in discover_corpus(CORPUS)}
    assert {"go-sca-old", "go-cmdi"} <= names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd harness && uv run pytest tests/test_corpus_integrity.py::test_go_corpus_present -v`
Expected: FAIL — packages missing.

- [ ] **Step 3: Author the packages**

`corpus/go/go-sca-old/go.mod` — module pinning a known-vulnerable dependency:

```
module example.com/scaold

go 1.21

require github.com/dgrijalva/jwt-go v3.2.0+incompatible
```

`corpus/go/go-sca-old/go.sum` — generate real checksums (`go mod download` offline may fail; if so, write the standard published `go.sum` lines for `jwt-go v3.2.0+incompatible`. OSV-Scanner reads `go.mod`, so `go.sum` correctness is secondary — include it but the SCA match keys on module+version).

`corpus/go/go-sca-old/groundtruth.yaml`:

```yaml
package: go-sca-old
language: go
ecosystem: go
findings: []
sca:
  - name: github.com/dgrijalva/jwt-go
    version: v3.2.0+incompatible
    ecosystem: go
    cve: CVE-2020-26160
    severity: HIGH
```

`corpus/go/go-cmdi/go.mod`:

```
module example.com/cmdi

go 1.21
```

`corpus/go/go-cmdi/main.go` — OS command injection (CWE-78):

```go
package main

import (
	"net/http"
	"os/exec"
)

// Run handles /ping?host=... with a planted command-injection sink.
func Run(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	// VULN: user-controlled host interpolated into a shell command.
	out, _ := exec.Command("bash", "-c", "ping -c 1 "+host).Output()
	w.Write(out)
}

func main() {}
```

`corpus/go/go-cmdi/groundtruth.yaml` — set `line` to the `exec.Command` line (verify with `awk`):

```yaml
package: go-cmdi
language: go
ecosystem: go
findings:
  - id: F1
    file: main.go
    line: 12
    cwe: CWE-78
    class: command-injection
    severity: HIGH
    exploitability: true-positive
    notes: user-controlled host in exec.Command bash -c
sca: []
```

Add `README.md` to each.

- [ ] **Step 4: Verify line + run integrity test**

Run:
```bash
awk 'NR==12{print NR": "$0}' corpus/go/go-cmdi/main.go
cd harness && uv run pytest tests/test_corpus_integrity.py -v
```
Adjust the groundtruth line if `exec.Command` isn't on line 12. Expect integrity tests PASS.

- [ ] **Step 5: Commit**

```bash
git add corpus/go harness/tests/test_corpus_integrity.py
git commit -m "feat: add Go corpus packages (SCA + command injection) (SCA-426)"
```

---

### Task 3: Rust + Ruby packages (rust-sca-old, ruby-sca-old, ruby-cmdi)

**Files:**
- `corpus/rust/rust-sca-old/` — `Cargo.toml`, `Cargo.lock`, `groundtruth.yaml`, `README.md`
- `corpus/ruby/ruby-sca-old/` — `Gemfile`, `Gemfile.lock`, `groundtruth.yaml`, `README.md`
- `corpus/ruby/ruby-cmdi/` — `app.rb`, `groundtruth.yaml`, `README.md`
- Test: extend integrity test.

**Interfaces:** 3 packages; the two SCA packages exercise crates.io + RubyGems coverage (RC02 breadth).

- [ ] **Step 1: Extend the failing test**

```python
def test_rust_ruby_corpus_present():
    from eval_suite.groundtruth import discover_corpus
    names = {g.package for g in discover_corpus(CORPUS)}
    assert {"rust-sca-old", "ruby-sca-old", "ruby-cmdi"} <= names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd harness && uv run pytest tests/test_corpus_integrity.py::test_rust_ruby_corpus_present -v`
Expected: FAIL.

- [ ] **Step 3: Author the packages**

`corpus/rust/rust-sca-old/Cargo.toml`:

```toml
[package]
name = "rust-sca-old"
version = "0.0.1"
edition = "2021"

[dependencies]
time = "=0.1.43"
```

`corpus/rust/rust-sca-old/Cargo.lock` — a minimal lock pinning `time 0.1.43` (OSV-Scanner reads Cargo.lock). Write a valid lock:

```toml
# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "rust-sca-old"
version = "0.0.1"
dependencies = ["time"]

[[package]]
name = "time"
version = "0.1.43"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ca8a50ef2360fbd1eeb0ecd46795a87a19024eb4b53c5dc916ca1fd95fe62438"
```

`corpus/rust/rust-sca-old/groundtruth.yaml`:

```yaml
package: rust-sca-old
language: rust
ecosystem: cargo
findings: []
sca:
  - name: time
    version: 0.1.43
    ecosystem: cargo
    cve: RUSTSEC-2020-0071
    severity: MEDIUM
```

`corpus/ruby/ruby-sca-old/Gemfile`:

```ruby
source "https://rubygems.org"
gem "rack", "2.0.5"
```

`corpus/ruby/ruby-sca-old/Gemfile.lock` (OSV-Scanner reads Gemfile.lock):

```
GEM
  remote: https://rubygems.org/
  specs:
    rack (2.0.5)

PLATFORMS
  ruby

DEPENDENCIES
  rack (= 2.0.5)

BUNDLED WITH
   2.3.0
```

`corpus/ruby/ruby-sca-old/groundtruth.yaml`:

```yaml
package: ruby-sca-old
language: ruby
ecosystem: rubygems
findings: []
sca:
  - name: rack
    version: 2.0.5
    ecosystem: rubygems
    cve: CVE-2019-16782
    severity: MEDIUM
```

`corpus/ruby/ruby-cmdi/app.rb` — command injection (CWE-78):

```ruby
require "sinatra"

# GET /ping?host=... with a planted command-injection sink.
get "/ping" do
  host = params["host"]
  # VULN: user-controlled host interpolated into a shell command.
  `ping -c 1 #{host}`
end
```

`corpus/ruby/ruby-cmdi/groundtruth.yaml` — point `line` at the backtick sink (verify):

```yaml
package: ruby-cmdi
language: ruby
ecosystem: rubygems
findings:
  - id: F1
    file: app.rb
    line: 7
    cwe: CWE-78
    class: command-injection
    severity: HIGH
    exploitability: true-positive
    notes: user-controlled host in backtick command
sca: []
```

Add `README.md` to each.

- [ ] **Step 4: Verify lines + run integrity test**

Run:
```bash
awk 'NR==7{print NR": "$0}' corpus/ruby/ruby-cmdi/app.rb
cd harness && uv run pytest tests/test_corpus_integrity.py -v
```
Adjust groundtruth lines if needed. Expect PASS.

- [ ] **Step 5: Commit**

```bash
git add corpus/rust corpus/ruby harness/tests/test_corpus_integrity.py
git commit -m "feat: add Rust and Ruby corpus packages (SCA-426)"
```

---

### Task 4: .NET packages (dotnet-sca-old, dotnet-sqli)

**Files:**
- `corpus/dotnet/dotnet-sca-old/` — `dotnet-sca-old.csproj`, `packages.lock.json`, `groundtruth.yaml`, `README.md`
- `corpus/dotnet/dotnet-sqli/` — `dotnet-sqli.csproj`, `Program.cs`, `groundtruth.yaml`, `README.md`
- Test: extend integrity test.

- [ ] **Step 1: Extend the failing test**

```python
def test_dotnet_corpus_present():
    from eval_suite.groundtruth import discover_corpus
    names = {g.package for g in discover_corpus(CORPUS)}
    assert {"dotnet-sca-old", "dotnet-sqli"} <= names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd harness && uv run pytest tests/test_corpus_integrity.py::test_dotnet_corpus_present -v`
Expected: FAIL.

- [ ] **Step 3: Author the packages**

`corpus/dotnet/dotnet-sca-old/dotnet-sca-old.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
  </ItemGroup>
</Project>
```

`corpus/dotnet/dotnet-sca-old/packages.lock.json` (Trivy/OSV read this when present):

```json
{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[12.0.1, )",
        "resolved": "12.0.1",
        "contentHash": ""
      }
    }
  }
}
```

`corpus/dotnet/dotnet-sca-old/groundtruth.yaml`:

```yaml
package: dotnet-sca-old
language: csharp
ecosystem: nuget
findings: []
sca:
  - name: Newtonsoft.Json
    version: 12.0.1
    ecosystem: nuget
    cve: CVE-2024-21907
    severity: HIGH
```

`corpus/dotnet/dotnet-sqli/dotnet-sqli.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
</Project>
```

`corpus/dotnet/dotnet-sqli/Program.cs` — SQL injection (CWE-89):

```csharp
using Microsoft.Data.SqlClient;

public class Lookup
{
    public void Find(SqlConnection conn, string user)
    {
        // VULN: SQL injection via string concatenation.
        var sql = "SELECT * FROM users WHERE name = '" + user + "'";
        var cmd = new SqlCommand(sql, conn);
        cmd.ExecuteReader();
    }
}
```

`corpus/dotnet/dotnet-sqli/groundtruth.yaml` — point `line` at the concatenated-SQL line (verify):

```yaml
package: dotnet-sqli
language: csharp
ecosystem: nuget
findings:
  - id: F1
    file: Program.cs
    line: 8
    cwe: CWE-89
    class: sql-injection
    severity: HIGH
    exploitability: true-positive
    notes: string-concatenated SQL passed to SqlCommand
sca: []
```

Add `README.md` to each.

- [ ] **Step 4: Verify line + run integrity test**

Run:
```bash
awk 'NR==8{print NR": "$0}' corpus/dotnet/dotnet-sqli/Program.cs
cd harness && uv run pytest tests/test_corpus_integrity.py -v
```
Adjust line if needed. Expect PASS.

- [ ] **Step 5: Commit**

```bash
git add corpus/dotnet harness/tests/test_corpus_integrity.py
git commit -m "feat: add .NET corpus packages (SCA + SQL injection) (SCA-426)"
```

---

### Task 5: New Python vuln classes (deserialization, SSTI, XXE, open-redirect triad)

**Files (under `corpus/python/`):**
- `py-deserialization/` — `worker.py`, `groundtruth.yaml`, `README.md`
- `py-ssti/` — `app.py`, `groundtruth.yaml`, `README.md`
- `py-xxe/` — `parser.py`, `groundtruth.yaml`, `README.md`
- `py-open-redirect/` — `app.py`, `groundtruth.yaml`, `README.md`
- Test: extend integrity test.

**Interfaces:** 4 packages adding CWE-502, CWE-1336/94, CWE-611, CWE-601. `py-open-redirect` includes a real + mitigated + FP triad for triage coverage.

- [ ] **Step 1: Extend the failing test**

```python
def test_python_v2_classes_present():
    from eval_suite.groundtruth import discover_corpus
    names = {g.package for g in discover_corpus(CORPUS)}
    assert {"py-deserialization", "py-ssti", "py-xxe", "py-open-redirect"} <= names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd harness && uv run pytest tests/test_corpus_integrity.py::test_python_v2_classes_present -v`
Expected: FAIL.

- [ ] **Step 3: Author the packages**

`corpus/python/py-deserialization/worker.py` (CWE-502):

```python
"""Background worker that deserializes untrusted task payloads (planted vuln)."""

import pickle


def handle(payload: bytes) -> object:
    # VULN: untrusted bytes passed to pickle.loads -> arbitrary code execution.
    return pickle.loads(payload)  # noqa: S301
```

`groundtruth.yaml`: F1 → the `pickle.loads` line, CWE-502, class `insecure-deserialization`, HIGH, true-positive.

`corpus/python/py-ssti/app.py` (CWE-1336 / server-side template injection):

```python
"""Flask app with a server-side template injection sink (planted vuln)."""

from flask import Flask, request
from flask import render_template_string

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    # VULN: user input concatenated into a template string -> SSTI.
    return render_template_string("<h1>Hello " + name + "</h1>")
```

`groundtruth.yaml`: F1 → the `render_template_string` line, CWE-1336, class `ssti`, HIGH, true-positive.

`corpus/python/py-xxe/parser.py` (CWE-611):

```python
"""XML parser that resolves external entities on untrusted input (planted vuln)."""

from lxml import etree


def parse(xml_bytes: bytes):
    # VULN: external entity resolution enabled on untrusted XML -> XXE.
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    return etree.fromstring(xml_bytes, parser=parser)
```

`groundtruth.yaml`: F1 → the `etree.XMLParser(...)` line (the sink that enables entity resolution), CWE-611, class `xxe`, HIGH, true-positive.

`corpus/python/py-open-redirect/app.py` (CWE-601 triad — real / mitigated / FP):

```python
"""Flask app with open-redirect sinks: real, mitigated, and a false positive."""

from urllib.parse import urlparse

from flask import Flask, redirect, request

app = Flask(__name__)

_ALLOWED = {"app.example.com"}


@app.route("/go")
def go():
    target = request.args.get("next", "")
    # VULN: user-controlled redirect target, no validation -> open redirect.
    return redirect(target)


@app.route("/go-safe")
def go_safe():
    target = request.args.get("next", "")
    # Mitigated: only redirect to an allowlisted host.
    if urlparse(target).hostname in _ALLOWED:
        return redirect(target)
    return redirect("/")


@app.route("/home")
def home():
    # Static literal target, not user-controlled -> false positive for scanners.
    return redirect("/dashboard")
```

`groundtruth.yaml`: F1 → the `return redirect(target)` in `go()` (true-positive, CWE-601, class `open-redirect`); F2 → the allowlisted `return redirect(target)` in `go_safe()` (mitigated-by-design); F3 → the `return redirect("/dashboard")` in `home()` (false-positive). VERIFY each line with `awk`.

Add `README.md` to each (name the class + RC relevance: these deepen the RC05 triage signal and SAST taint coverage).

- [ ] **Step 4: Verify lines + run integrity test**

Run:
```bash
awk 'NR>=1{c=NR} {print c": "$0}' corpus/python/py-open-redirect/app.py | grep -n "redirect("
cd harness && uv run pytest tests/test_corpus_integrity.py -v
```
Confirm each groundtruth line points at the intended `redirect(...)` sink; adjust lines to match the file as written. Expect PASS.

- [ ] **Step 5: Commit**

```bash
git add corpus/python/py-deserialization corpus/python/py-ssti corpus/python/py-xxe corpus/python/py-open-redirect harness/tests/test_corpus_integrity.py
git commit -m "feat: add Python deserialization/SSTI/XXE/open-redirect corpus packages (SCA-426)"
```

---

### Task 6: New Java vuln classes (deserialization, XXE)

**Files (under `corpus/java/`):**
- `java-deserialization/` — `pom.xml`, `src/main/java/com/example/Worker.java`, `groundtruth.yaml`, `README.md`
- `java-xxe/` — `pom.xml`, `src/main/java/com/example/XmlParser.java`, `groundtruth.yaml`, `README.md`
- Test: extend integrity test.

- [ ] **Step 1: Extend the failing test**

```python
def test_java_v2_classes_present():
    from eval_suite.groundtruth import discover_corpus
    names = {g.package for g in discover_corpus(CORPUS)}
    assert {"java-deserialization", "java-xxe"} <= names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd harness && uv run pytest tests/test_corpus_integrity.py::test_java_v2_classes_present -v`
Expected: FAIL.

- [ ] **Step 3: Author the packages**

`corpus/java/java-deserialization/src/main/java/com/example/Worker.java` (CWE-502):

```java
package com.example;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

public class Worker {
    public Object handle(byte[] payload) throws Exception {
        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(payload));
        // VULN: deserializing untrusted bytes -> remote code execution.
        return in.readObject();
    }
}
```

`groundtruth.yaml`: F1 → the `in.readObject()` line, CWE-502, class `insecure-deserialization`, HIGH, true-positive. `pom.xml` minimal (no deps).

`corpus/java/java-xxe/src/main/java/com/example/XmlParser.java` (CWE-611):

```java
package com.example;

import java.io.ByteArrayInputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class XmlParser {
    public Document parse(byte[] xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // VULN: DTD/external entities not disabled -> XXE on untrusted XML.
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(new ByteArrayInputStream(xml));
    }
}
```

`groundtruth.yaml`: F1 → the `db.parse(...)` line (the sink consuming untrusted XML with an unsafe factory), CWE-611, class `xxe`, HIGH, true-positive. `pom.xml` minimal.

Add `README.md` to each. VERIFY both sink lines with `awk`.

- [ ] **Step 4: Verify lines + run integrity test**

Run:
```bash
awk 'NR>=1' corpus/java/java-deserialization/src/main/java/com/example/Worker.java | grep -n "readObject"
cd harness && uv run pytest tests/test_corpus_integrity.py -v
```
Adjust groundtruth lines to match. Expect PASS.

- [ ] **Step 5: Commit**

```bash
git add corpus/java/java-deserialization corpus/java/java-xxe harness/tests/test_corpus_integrity.py
git commit -m "feat: add Java deserialization and XXE corpus packages (SCA-426)"
```

---

### Task 7: Larger Python app (py-rest-api, multi-file, interacting vulns)

**Files (under `corpus/python/py-rest-api/`):**
- `app.py` (routes), `db.py` (data access), `auth.py` (access control), `fetch.py` (outbound), `config.py` (settings), `requirements.txt`, `groundtruth.yaml`, `README.md`
- Test: extend integrity test.

**Interfaces:** one realistic multi-file Flask app whose ground truth spans files: ≥5 findings across the modules (one SQLi, one SSRF, one IDOR/broken access, one hardcoded secret, plus one mitigated case and one FP decoy).

- [ ] **Step 1: Extend the failing test**

```python
def test_py_rest_api_present_and_multifile():
    from eval_suite.groundtruth import discover_corpus
    gts = {g.package: g for g in discover_corpus(CORPUS)}
    assert "py-rest-api" in gts
    files = {f.file for f in gts["py-rest-api"].findings}
    assert len(files) >= 3  # ground truth spans multiple files
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd harness && uv run pytest tests/test_corpus_integrity.py::test_py_rest_api_present_and_multifile -v`
Expected: FAIL.

- [ ] **Step 3: Author the app**

Build a small Flask app with these planted, interacting sinks (write idiomatic code; keep each file short):
- `db.py`: `get_user(name)` builds `f"SELECT * FROM users WHERE name = '{name}'"` and executes it — **SQLi (CWE-89, true-positive)**. Also include `get_user_safe(name)` using a parameterized query — **mitigated-by-design** decoy.
- `fetch.py`: `fetch_avatar(url)` does `requests.get(url)` on a caller-supplied URL with no allowlist — **SSRF (CWE-918, true-positive)**.
- `auth.py` / `app.py`: a route `/users/<id>/profile` that returns any user's record without checking the requester owns `id` — **IDOR / broken access control (CWE-639, true-positive)**.
- `config.py`: a hardcoded `SECRET_KEY = "hardcoded-flask-secret-do-not-use"` — **hardcoded secret (CWE-798, true-positive)**.
- One **false-positive** decoy: e.g. in `app.py` a route that returns `redirect("/login")` (static literal) that a scanner might flag as open redirect — **false-positive (CWE-601)**.

`groundtruth.yaml` lists all of the above with their exact file + line + cwe + class + exploitability. VERIFY every line with `awk`/inspection after writing the files. `requirements.txt` pins flask + requests (versions need not be vulnerable here — this app is for SAST shape).

`README.md` explains it is a realistic multi-file app exercising interacting SAST taint flows + access control + secrets, with one mitigated and one FP case.

- [ ] **Step 4: Verify lines + run integrity test**

Run: `cd harness && uv run pytest tests/test_corpus_integrity.py -v`
The in-range integrity check plus the multifile assertion must pass. Manually confirm each cited line holds its sink.

- [ ] **Step 5: Commit**

```bash
git add corpus/python/py-rest-api harness/tests/test_corpus_integrity.py
git commit -m "feat: add larger multi-file Python REST API corpus app (SCA-426)"
```

---

### Task 8: Larger Java app (java-rest-api, multi-file) + full verification & README/CI refresh

**Files (under `corpus/java/java-rest-api/`):**
- `pom.xml`, `src/main/java/com/example/{Controller,UserRepository,FetchClient,AppConfig}.java`, `groundtruth.yaml`, `README.md`
- Modify: `README.md` (top-level) — refresh the corpus inventory/table to list the new ecosystems, classes, and the two larger apps.
- Test: extend integrity test.

**Interfaces:** one realistic multi-file Spring-style service whose ground truth spans files: ≥4 findings (SQLi via string-concat in the repository, SSRF in the fetch client, IDOR in the controller, hardcoded secret in config).

- [ ] **Step 1: Extend the failing test**

```python
def test_java_rest_api_present_and_multifile():
    from eval_suite.groundtruth import discover_corpus
    gts = {g.package: g for g in discover_corpus(CORPUS)}
    assert "java-rest-api" in gts
    files = {f.file for f in gts["java-rest-api"].findings}
    assert len(files) >= 3
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd harness && uv run pytest tests/test_corpus_integrity.py::test_java_rest_api_present_and_multifile -v`
Expected: FAIL.

- [ ] **Step 3: Author the app + refresh README**

Build a small Spring-style service (plain classes are fine; no need for a running Spring context — these are SAST scan targets):
- `UserRepository.java`: `findByName(String name)` builds `"SELECT * FROM users WHERE name = '" + name + "'"` and executes via `Statement` — **SQLi (CWE-89, true-positive)**.
- `FetchClient.java`: `fetch(String url)` opens `new URL(url).openStream()` on caller-supplied URL — **SSRF (CWE-918, true-positive)**.
- `Controller.java`: `getProfile(String id)` returns any user's profile with no ownership check — **IDOR (CWE-639, true-positive)**.
- `AppConfig.java`: `static final String API_KEY = "hardcoded-api-key-do-not-use";` — **hardcoded secret (CWE-798, true-positive)**.

`groundtruth.yaml` lists all four with exact file + line + cwe + class + exploitability. VERIFY each line. `pom.xml` minimal (no deps needed).

Refresh the top-level `README.md` corpus section to reflect the full v2 inventory (Python, Java, Go, Rust, Ruby, .NET; the new classes; the two larger apps).

- [ ] **Step 4: Full verification**

Run:
```bash
cd harness && uv run pytest -v
cd .. && uv run ruff check . && uv run pyright
python -c "import yaml; yaml.safe_load(open('.github/workflows/eval.yml')); print('ci ok')"
```
Expected: entire suite green (existing 42 + all new integrity assertions); ruff + pyright clean; CI YAML still valid.

- [ ] **Step 5: Commit**

```bash
git add corpus/java/java-rest-api harness/tests/test_corpus_integrity.py README.md
git commit -m "feat: add larger multi-file Java REST API app and refresh corpus README (SCA-426)"
```

---

## Self-Review

**Spec coverage:**
- More ecosystems (Go/Rust/Ruby/.NET) → Tasks 2,3,4 (+ schema enablement Task 1). ✓
- More vuln classes in Python/Java → Tasks 5,6 (deserialization, SSTI, XXE, open-redirect; Java deser + XXE). ✓
- A couple of larger realistic apps → Tasks 7,8 (Python + Java multi-file). ✓
- No scoring-engine change → confirmed: only the schema enums widen; matcher/metrics untouched. ✓
- RC01–RC05 acceptance stays green → the existing acceptance test is unchanged and references only v1 packages; new packages only add to the integrity gate. ✓

**Placeholder scan:** The larger-app tasks (7,8) describe each planted sink precisely (file, function, construct, CWE, exploitability) but let the implementer write idiomatic multi-file code and then pin exact line numbers via `awk` — consistent with how v1 corpus tasks worked. Not a logic placeholder.

**SCA ground-truth accuracy:** Each SCA package names a real, well-known vulnerable version + advisory (jwt-go v3.2.0/CVE-2020-26160, time 0.1.43/RUSTSEC-2020-0071, rack 2.0.5/CVE-2019-16782, Newtonsoft.Json 12.0.1/CVE-2024-21907). Implementers must confirm the advisory id/version against the manifest as written; if a competitor tool reports a different canonical CVE/GHSA, the SCA match still keys on package+version (CVE optional in the matcher), so ground truth remains valid.

**Type/label consistency:** All new `class` values (command-injection, sql-injection, insecure-deserialization, ssti, xxe, open-redirect, ssrf, idor/broken-access via CWE-639, secret-*) are free-form strings consumed only by `by_class` grouping — no enum constraint, no cross-task signature to break. Ecosystem/language strings match the widened schema enums exactly.
