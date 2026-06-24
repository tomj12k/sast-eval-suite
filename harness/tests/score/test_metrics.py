from eval_suite.models import Finding, GroundTruth, GroundTruthItem, ScaItem
from eval_suite.score.match import match
from eval_suite.score.metrics import score_tool


def _pkg(findings=(), sca=(), eco="pypi"):
    return GroundTruth(package="p", language="python", ecosystem=eco,
                       findings=list(findings), sca=list(sca))


def test_perfect_recall_precision():
    gt = _pkg(findings=[GroundTruthItem("F1", "a.py", 10, "CWE-79", "xss",
                                        "HIGH", "true-positive")])
    fnd = [Finding(tool="t", kind="sast", file="a.py", line=10, cwe="CWE-79")]
    res = match(fnd, gt)
    score = score_tool("t", [(gt, res, fnd)])
    assert score.recall == 1.0
    assert score.precision == 1.0
    assert score.by_class["xss"] == (1.0, 1.0)


def test_triage_penalizes_reporting_fp_decoy():
    gt = _pkg(findings=[
        GroundTruthItem("F1", "a.py", 10, "CWE-79", "xss", "HIGH", "true-positive"),
        GroundTruthItem("F3", "a.py", 30, "CWE-79", "xss", "HIGH", "false-positive"),
    ])
    fnd = [
        Finding(tool="t", kind="sast", file="a.py", line=10, cwe="CWE-79"),
        Finding(tool="t", kind="sast", file="a.py", line=30, cwe="CWE-79"),
    ]
    res = match(fnd, gt)
    score = score_tool("t", [(gt, res, fnd)])
    assert score.triage_accuracy == 0.5  # real handled right, FP wrongly reported


def test_remediation_coverage():
    gt = _pkg(sca=[ScaItem("log4j-core", "2.14.1", "maven", "CVE-2021-44228")])
    fnd = [Finding(tool="t", kind="sca", package="log4j-core", version="2.14.1",
                   cve="CVE-2021-44228", remediation="upgrade")]
    res = match(fnd, gt)
    score = score_tool("t", [(gt, res, fnd)])
    assert score.remediation_coverage == 1.0
