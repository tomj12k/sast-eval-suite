"""Run Semgrep OSS and normalize its SARIF output."""

from __future__ import annotations

from pathlib import Path

from eval_suite.models import Finding
from eval_suite.normalize.sarif import sarif_to_findings
from eval_suite.runners.base import RunResult, run_cmd

NAME = "semgrep"


def run(target: Path) -> list[Finding]:
    """Run Semgrep over a target and return normalized findings.

    :param target: package directory to scan.
    :returns: normalized findings.
    :rtype: list[Finding]
    """
    res: RunResult = run_cmd(
        ["semgrep", "--config", "auto", "--sarif", "--quiet", "."], cwd=target
    )
    if res.raw is None:
        return []
    return sarif_to_findings(res.raw, tool=NAME)
