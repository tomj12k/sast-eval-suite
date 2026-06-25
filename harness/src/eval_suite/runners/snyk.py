"""Run Snyk (code + open-source) and normalize its SARIF output."""

from __future__ import annotations

from pathlib import Path

from eval_suite.models import Finding
from eval_suite.normalize.sarif import sarif_to_findings
from eval_suite.runners.base import run_cmd

NAME = "snyk"


def run(target: Path) -> list[Finding]:
    """Run Snyk Code over a target and return normalized findings.

    Requires ``SNYK_TOKEN`` in the environment; returns empty if unauthenticated.

    :param target: package directory to scan.
    :returns: normalized findings.
    :rtype: list[Finding]
    """
    res = run_cmd(["snyk", "code", "test", "--sarif", "."], cwd=target)
    if res.raw is None:
        return []
    return sarif_to_findings(res.raw, tool=NAME)
