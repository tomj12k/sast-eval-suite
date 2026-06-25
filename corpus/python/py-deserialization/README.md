# py-deserialization

**Vuln class:** insecure-deserialization (CWE-502)

Background worker that deserializes untrusted task payloads via `pickle.loads`.
Pickle deserializes arbitrary Python object graphs — an attacker can craft a payload
that executes arbitrary code on load.

**RC relevance:** Deepens RC05 triage signal for SAST taint coverage; tests whether
scanners detect untrusted data flowing into `pickle.loads` without a prior signature
or type check.
