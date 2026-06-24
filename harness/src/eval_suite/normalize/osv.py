"""Normalize OSV-Scanner JSON output into Finding records."""

from __future__ import annotations

from eval_suite.models import Finding


def _pick_cve(aliases: list[str], fallback: str | None) -> str | None:
    for a in aliases:
        if a.startswith("CVE-"):
            return a
    return fallback


def osv_to_findings(data: dict, tool: str = "osv-scanner") -> list[Finding]:
    """Convert OSV-Scanner JSON into SCA findings.

    :param data: parsed OSV-Scanner JSON.
    :param tool: tool name to stamp on each finding.
    :returns: SCA findings.
    :rtype: list[Finding]
    """
    findings: list[Finding] = []
    for result in data.get("results", []):
        for pkg in result.get("packages", []):
            meta = pkg.get("package", {})
            for vuln in pkg.get("vulnerabilities", []):
                findings.append(
                    Finding(
                        tool=tool, kind="sca",
                        package=meta.get("name"), version=meta.get("version"),
                        cve=_pick_cve(vuln.get("aliases", []), vuln.get("id")),
                        raw_id=vuln.get("id"),
                    )
                )
    return findings
