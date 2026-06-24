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
