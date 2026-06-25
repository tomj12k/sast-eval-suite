"""Render tool scores as markdown and JSON."""

from __future__ import annotations

from eval_suite.score.metrics import ToolScore


def render_json(scores: list[ToolScore]) -> dict:
    """Render scores as a JSON-serializable dict.

    :param scores: per-tool scores.
    :returns: serializable report.
    :rtype: dict
    """
    return {
        "tools": [
            {
                "tool": s.tool, "recall": s.recall, "precision": s.precision,
                "by_class": {k: list(v) for k, v in s.by_class.items()},
                "by_ecosystem": {k: list(v) for k, v in s.by_ecosystem.items()},
                "triage_accuracy": s.triage_accuracy,
                "remediation_coverage": s.remediation_coverage,
            }
            for s in scores
        ]
    }


def render_markdown(scores: list[ToolScore]) -> str:
    """Render scores as a markdown report.

    :param scores: per-tool scores.
    :returns: markdown text.
    :rtype: str
    """
    lines = ["# Eval Suite Report", "", "## Overall", "",
             "| Tool | Recall | Precision | Triage | Remediation |",
             "|---|---|---|---|---|"]
    for s in scores:
        triage = "n/a" if s.triage_accuracy is None else f"{s.triage_accuracy:.2f}"
        rem = "n/a" if s.remediation_coverage is None else f"{s.remediation_coverage:.2f}"
        lines.append(f"| {s.tool} | {s.recall:.2f} | {s.precision:.2f} | {triage} | {rem} |")
    lines.append("")
    lines.append("## Recall by class")
    lines.append("")
    for s in scores:
        for klass, (recall, _prec) in sorted(s.by_class.items()):
            lines.append(f"- {s.tool} / {klass}: recall={recall:.2f}")
    return "\n".join(lines)
