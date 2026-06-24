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
