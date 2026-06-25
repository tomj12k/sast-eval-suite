# Task 8 Report: Larger Multi-File Java REST API App + README Refresh

## Status: COMPLETE

---

## TDD Evidence

### Step 1: Failing test appended

Added `test_java_rest_api_present_and_multifile` to
`harness/tests/test_corpus_integrity.py` before authoring any corpus files.

### Step 2: Confirmed FAIL

```
FAILED harness/tests/test_corpus_integrity.py::test_java_rest_api_present_and_multifile
AssertionError: assert 'java-rest-api' in {...}
```

### Step 3: Corpus package authored, test now PASSES

---

## Files Created

```
corpus/java/java-rest-api/
├── pom.xml                                        minimal Maven descriptor, no deps
├── groundtruth.yaml                               4 findings across 4 files
├── README.md                                      per-package inventory table
└── src/main/java/com/example/
    ├── AppConfig.java                             hardcoded secret (F4)
    ├── UserRepository.java                        SQL injection (F1)
    ├── FetchClient.java                           SSRF (F2)
    └── Controller.java                            IDOR (F3)
```

---

## Per-Sink Line Verification

Each line was verified with `grep -n` against the authored file.

| ID | File | Line | CWE | Sink expression |
|----|------|------|-----|-----------------|
| F1 | `src/main/java/com/example/UserRepository.java` | 29 | CWE-89 | `"SELECT * FROM users WHERE name = '" + name + "'"` |
| F2 | `src/main/java/com/example/FetchClient.java` | 24 | CWE-918 | `new URL(url).openStream()` |
| F3 | `src/main/java/com/example/Controller.java` | 22 | CWE-639 | `public String getProfile(String id)` (no auth check) |
| F4 | `src/main/java/com/example/AppConfig.java` | 12 | CWE-798 | `static final String API_KEY = "hardcoded-api-key-do-not-use"` |

All four lines are within file bounds. Verified by
`test_all_groundtruth_valid_and_lines_exist` (passes in full suite).

---

## File-Span Confirmation

Findings span 4 distinct files:
- `src/main/java/com/example/UserRepository.java`
- `src/main/java/com/example/FetchClient.java`
- `src/main/java/com/example/Controller.java`
- `src/main/java/com/example/AppConfig.java`

`len(files) >= 3` assertion: PASSES (4 >= 3).

---

## README Changes

Top-level `README.md` corpus section replaced with:
- Full annotated directory tree listing all 23 corpus packages across 6 ecosystems.
- Corpus inventory summary table (ecosystem / package count / SAST classes / SCA).
- Note on the two larger multi-file apps (`py-rest-api`, `java-rest-api`).
- Existing intentionally-vulnerable-corpus WARNING block preserved unchanged.
- Test count in harness comment updated from "42+" to "50+".

---

## Full-Suite Verification

```
50 passed in 0.90s
```

- RC01–RC05 acceptance tests: ALL GREEN
- `test_java_rest_api_present_and_multifile`: PASS
- `test_all_groundtruth_valid_and_lines_exist`: PASS (line-in-range check)
- `uv run ruff check .`: All checks passed
- `uv run pyright`: 0 errors, 0 warnings, 0 informations
- CI YAML: ci ok

---

## Concerns

None. The pyright version-upgrade warning (`v1.1.410 -> v1.1.411`) is cosmetic
and does not affect the check result.

---

## Fix 2 Addendum (SCA-426 follow-up corrections)

### awk line check

```
28:         // SAST target: SQL injection — CWE-89
29:         String sql = "SELECT * FROM users WHERE name = '" + name + "'";
30:         try (Connection conn = getConnection();
```

The comment is on line 28; the string-concat assignment (the actual sink) is on line 29.
The groundtruth.yaml `F1 line: 29` was already correct — no change needed.

### Edits applied

1. **`README.md` (top-level) line 98-99**: Replaced inaccurate "exploitability triad
   (network-reachable / user-controlled / no-auth-bypass)" with accurate "`exploitability`
   label (`true-positive` / `mitigated-by-design` / `false-positive`)".

2. **`corpus/java/java-rest-api/groundtruth.yaml`**: No change — F1 `line: 29` was
   already pointing at the sink line.

3. **`corpus/java/java-rest-api/README.md`**: No change — table row already shows `29`.

### Full-suite verification

```
50 passed in 0.95s
```

- `uv run ruff check .`: All checks passed
- `uv run pyright`: 0 errors, 0 warnings, 0 informations
