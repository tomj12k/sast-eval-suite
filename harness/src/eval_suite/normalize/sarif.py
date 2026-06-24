"""Normalize SARIF tool output into Finding records."""

from __future__ import annotations

import re

from eval_suite.models import Finding

_CWE_RE = re.compile(r"CWE-\d+")
_LEVEL_TO_SEVERITY = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}


def _cwe_from_tags(tags: list[str]) -> str | None:
    for tag in tags:
        m = _CWE_RE.search(tag)
        if m:
            return m.group(0)
    return None


def sarif_to_findings(sarif: dict, tool: str, kind: str = "sast") -> list[Finding]:
    """Convert a SARIF document into normalized findings.

    :param sarif: parsed SARIF JSON.
    :param tool: tool name to stamp on each finding.
    :param kind: finding kind (``sast``/``sca``/``secret``).
    :returns: normalized findings.
    :rtype: list[Finding]
    """
    findings: list[Finding] = []
    for run in sarif.get("runs", []):
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        rule_tags: dict[str, list[str]] = {
            r.get("id", ""): r.get("properties", {}).get("tags", []) for r in rules
        }
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            file = None
            line = None
            locations = result.get("locations", [])
            if locations:
                phys = locations[0].get("physicalLocation", {})
                file = phys.get("artifactLocation", {}).get("uri")
                line = phys.get("region", {}).get("startLine")
            level = result.get("level", "warning")
            findings.append(
                Finding(
                    tool=tool,
                    kind=kind,
                    file=file,
                    line=line,
                    cwe=_cwe_from_tags(rule_tags.get(rule_id, [])),
                    severity=_LEVEL_TO_SEVERITY.get(level, "MEDIUM"),
                    raw_id=rule_id,
                    message=result.get("message", {}).get("text"),
                )
            )
    return findings
