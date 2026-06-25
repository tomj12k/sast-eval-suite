# py-webapp-cmdi

Planted vulnerability: **OS Command Injection** (CWE-78) — RC01.

`app.py` line 14: user-supplied `host` parameter is concatenated directly into a
shell command via `subprocess.check_output(..., shell=True)`. An attacker can inject
arbitrary shell metacharacters (e.g. `; rm -rf /`).

**RC exercised:** RC01 — detects taint flowing from HTTP request parameter to a
shell-invoked subprocess sink.
