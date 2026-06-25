"""Command-line entry point for the evaluation suite."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from eval_suite.groundtruth import discover_corpus, load_groundtruth
from eval_suite.models import Finding
from eval_suite.normalize.scntnms import scntnms_to_findings
from eval_suite.report.render import render_json, render_markdown
from eval_suite.report.trend import append_run, check_regression
from eval_suite.runners import claude_review, codeql, osv, semgrep, snyk, trivy
from eval_suite.score.match import match
from eval_suite.score.metrics import ToolScore, score_tool

_RUNNERS = [semgrep, trivy, osv, codeql, snyk, claude_review]


def score_corpus(
    corpus_root: Path, by_package: dict[str, dict[str, list[Finding]]]
) -> list[ToolScore]:
    """Score every tool against the corpus from pre-collected findings.

    :param corpus_root: directory of labeled packages.
    :param by_package: mapping package -> tool -> findings.
    :returns: per-tool aggregate scores.
    :rtype: list[ToolScore]
    """
    corpus = discover_corpus(corpus_root)
    tools = {t for pkg in by_package.values() for t in pkg}
    scores: list[ToolScore] = []
    for tool in sorted(tools):
        per_pkg = []
        for gt in corpus:
            findings = by_package.get(gt.package, {}).get(tool, [])
            per_pkg.append((gt, match(findings, gt), findings))
        scores.append(score_tool(tool, per_pkg))
    return scores


def _collect(corpus_root: Path) -> dict[str, dict[str, list[Finding]]]:
    """Run every available runner over every package (live scan).

    :param corpus_root: directory of labeled packages.
    :returns: mapping package -> tool -> findings.
    :rtype: dict[str, dict[str, list[Finding]]]
    """
    by_package: dict[str, dict[str, list[Finding]]] = {}
    for gt_path in sorted(corpus_root.rglob("groundtruth.yaml")):
        target = gt_path.parent
        gt = load_groundtruth(gt_path)
        by_package[gt.package] = {r.NAME: r.run(target) for r in _RUNNERS}
    return by_package


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    :param argv: argument vector (defaults to ``sys.argv``).
    :returns: process exit code.
    :rtype: int
    """
    parser = argparse.ArgumentParser(prog="eval-suite")
    parser.add_argument("--corpus", type=Path, default=Path("corpus"))
    parser.add_argument("--out", type=Path, default=Path("results/report"))
    parser.add_argument("--trend", type=Path, default=Path("results/trend.json"))
    parser.add_argument("--stamp", default="manual")
    parser.add_argument("--scntnms-export", type=Path, default=None)
    parser.add_argument("--fail-on-regression", action="store_true")
    args = parser.parse_args(argv)

    by_package = _collect(args.corpus)
    if args.scntnms_export and args.scntnms_export.exists():
        data = json.loads(args.scntnms_export.read_text())
        # export is a mapping package -> findings export dict
        for pkg, export in data.items():
            by_package.setdefault(pkg, {})["scntnms"] = scntnms_to_findings(
                export, tool="scntnms"
            )

    scores = score_corpus(args.corpus, by_package)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.with_suffix(".md").write_text(render_markdown(scores))
    args.out.with_suffix(".json").write_text(json.dumps(render_json(scores), indent=2))

    regressions = check_regression(args.trend, scores)
    args.trend.parent.mkdir(parents=True, exist_ok=True)
    append_run(args.trend, scores, stamp=args.stamp)
    for msg in regressions:
        print(msg)
    if regressions and args.fail_on_regression:
        return 1
    return 0
