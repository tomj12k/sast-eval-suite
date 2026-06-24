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
