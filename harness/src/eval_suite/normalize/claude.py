"""Normalize Claude /security-review JSON output into Finding records."""

from __future__ import annotations

from eval_suite.models import Finding


def claude_to_findings(data: dict, tool: str = "claude-security-review") -> list[Finding]:
    """Convert Claude security-review JSON into SAST findings.

    :param data: parsed JSON with a ``findings`` list.
    :param tool: tool name to stamp on each finding.
    :returns: SAST findings.
    :rtype: list[Finding]
    """
    out: list[Finding] = []
    for item in data.get("findings", []):
        out.append(
            Finding(
                tool=tool, kind="sast",
                file=item.get("file"), line=item.get("line"),
                cwe=item.get("cwe"), severity=item.get("severity"),
                message=item.get("title") or item.get("message"),
            )
        )
    return out
