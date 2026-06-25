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
