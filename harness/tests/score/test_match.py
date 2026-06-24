from eval_suite.models import Finding, GroundTruth, GroundTruthItem, ScaItem
from eval_suite.score.match import match


def _gt(findings=(), sca=()):
    return GroundTruth(package="p", language="python", ecosystem="pypi",
                       findings=list(findings), sca=list(sca))


def test_sast_true_positive_within_tolerance():
    gt = _gt(findings=[GroundTruthItem("F1", "app.py", 113, "CWE-79", "xss",
                                       "HIGH", "true-positive")])
    findings = [Finding(tool="t", kind="sast", file="app.py", line=115, cwe="CWE-79")]
    res = match(findings, gt, line_tolerance=3)
    assert len(res.tp) == 1
    assert not res.fn
    assert not res.fp


def test_sast_miss_is_false_negative():
    gt = _gt(findings=[GroundTruthItem("F1", "app.py", 113, "CWE-79", "xss",
                                       "HIGH", "true-positive")])
    res = match([], gt)
    assert len(res.fn) == 1


def test_reporting_a_false_positive_item_counts_as_fp():
    gt = _gt(findings=[GroundTruthItem("F3", "app.py", 128, "CWE-79", "xss",
                                       "HIGH", "false-positive")])
    findings = [Finding(tool="t", kind="sast", file="app.py", line=128, cwe="CWE-79")]
    res = match(findings, gt)
    assert len(res.fp) == 1
    assert not res.tp


def test_unrelated_finding_is_false_positive():
    gt = _gt(findings=[GroundTruthItem("F1", "app.py", 113, "CWE-79", "xss",
                                       "HIGH", "true-positive")])
    findings = [Finding(tool="t", kind="sast", file="other.py", line=5, cwe="CWE-89")]
    res = match(findings, gt)
    assert len(res.fp) == 1
    assert len(res.fn) == 1


def test_sca_match_by_name_version():
    gt = _gt(sca=[ScaItem("requests", "2.5.0", "pypi", "CVE-2018-18074")])
    findings = [Finding(tool="t", kind="sca", package="requests", version="2.5.0",
                        cve="CVE-2018-18074")]
    res = match(findings, gt)
    assert len(res.sca_tp) == 1
    assert not res.sca_fn


def test_unmatched_false_positive_decoy_is_silent():
    gt = _gt(findings=[GroundTruthItem("F1", "app.py", 128, "CWE-79", "xss",
                                       "HIGH", "false-positive")])
    res = match([], gt)
    assert res.fn == []
    assert res.fp == []
    assert res.tp == []
