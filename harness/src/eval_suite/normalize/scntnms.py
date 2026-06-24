"""Normalize an exported Scantonomous findings file into Finding records."""

from __future__ import annotations

from eval_suite.models import Finding

_VALID_KINDS = {"sast", "sca", "secret"}


def scntnms_to_findings(data: dict, tool: str) -> list[Finding]:
    """Convert a Scantonomous findings export into normalized findings.

    :param data: parsed export with a ``findings`` list.
    :param tool: tool label, e.g. ``scntnms-standard`` or ``scntnms-ai``.
    :returns: normalized findings.
    :rtype: list[Finding]
    """
    out: list[Finding] = []
    for item in data.get("findings", []):
        kind = item.get("type", "sast")
        if kind not in _VALID_KINDS:
            kind = "sast"
        out.append(
            Finding(
                tool=tool, kind=kind,
                file=item.get("file"), line=item.get("line"),
                cwe=item.get("cwe"), severity=item.get("severity"),
                package=item.get("package"), version=item.get("version"),
                cve=item.get("cve"), message=item.get("message"),
                remediation=item.get("remediation"),
            )
        )
    return out
