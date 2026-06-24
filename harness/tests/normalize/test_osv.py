from eval_suite.normalize.osv import osv_to_findings

OSV = {"results": [{"packages": [{
    "package": {"name": "requests", "version": "2.5.0", "ecosystem": "PyPI"},
    "vulnerabilities": [{"aliases": ["CVE-2018-18074"], "id": "GHSA-x"}],
}]}]}


def test_osv_to_findings():
    findings = osv_to_findings(OSV)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind == "sca"
    assert f.package == "requests"
    assert f.version == "2.5.0"
    assert f.cve == "CVE-2018-18074"
