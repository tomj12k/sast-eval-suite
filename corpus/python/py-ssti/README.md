# py-ssti

**Vuln class:** ssti (CWE-1336)

Flask app with a server-side template injection sink: user input is concatenated
directly into a Jinja2 template string passed to `render_template_string`.
An attacker can inject `{{ 7*7 }}` or `{{ config }}` to enumerate secrets or
escalate to remote code execution.

**RC relevance:** Deepens RC05 triage signal and SAST taint coverage; tests whether
scanners track user-controlled data flowing into `render_template_string` without
prior sanitization.
