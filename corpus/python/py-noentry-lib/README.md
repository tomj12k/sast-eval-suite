# py-noentry-lib

Planted vulnerabilities: **SSRF** (CWE-918) and **Path Traversal** (CWE-22) — RC01.

This is a pure library with no web entry point, exercising scanner ability to detect
sinks in non-web contexts.

- `fetcher.py` line 8: `urllib.request.urlopen(url)` called with a caller-supplied URL
  and no allowlist — SSRF sink.
- `fetcher.py` line 15: `open(path)` where `path = base + "/" + name` with no
  normalization — path traversal sink allowing `../` escape.

**RC exercised:** RC01 — taint detection in library code with no HTTP entry point.
