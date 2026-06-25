"""Run OSV-Scanner and normalize its JSON output."""

from __future__ import annotations

from pathlib import Path

from eval_suite.models import Finding
from eval_suite.normalize.osv import osv_to_findings
from eval_suite.runners.base import run_cmd

NAME = "osv-scanner"


def run(target: Path) -> list[Finding]:
    """Run OSV-Scanner over a target and return normalized SCA findings.

    :param target: package directory to scan.
    :returns: normalized findings.
    :rtype: list[Finding]
    """
    res = run_cmd(["osv-scanner", "--format", "json", "-r", "."], cwd=target)
    if res.raw is None:
        return []
    return osv_to_findings(res.raw, tool=NAME)
