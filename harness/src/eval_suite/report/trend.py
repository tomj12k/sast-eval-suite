"""Append run summaries to a trend file and detect recall regressions."""

from __future__ import annotations

import json
from pathlib import Path

from eval_suite.score.metrics import ToolScore


def _load(trend_path: Path) -> list[dict]:
    if not trend_path.exists():
        return []
    return json.loads(trend_path.read_text())


def append_run(trend_path: Path, scores: list[ToolScore], stamp: str) -> None:
    """Append a run summary to the trend file.

    :param trend_path: path to ``trend.json``.
    :param scores: per-tool scores for this run.
    :param stamp: ISO-8601 timestamp string for this run.
    :returns: ``None``.
    """
    history = _load(trend_path)
    history.append({
        "stamp": stamp,
        "tools": {
            s.tool: {
                "recall": s.recall,
                "by_class": {k: v[0] for k, v in s.by_class.items()},
            }
            for s in scores
        },
    })
    trend_path.write_text(json.dumps(history, indent=2))


def check_regression(
    trend_path: Path, current: list[ToolScore], min_drop: float = 0.0
) -> list[str]:
    """Compare current per-class recall to the most recent prior run.

    :param trend_path: path to ``trend.json`` holding prior runs.
    :param current: current per-tool scores.
    :param min_drop: only report drops strictly greater than this value.
    :returns: human-readable regression messages (empty if none).
    :rtype: list[str]
    """
    history = _load(trend_path)
    if not history:
        return []
    prev = history[-1]["tools"]
    msgs: list[str] = []
    for s in current:
        prev_classes = prev.get(s.tool, {}).get("by_class", {})
        for klass, (recall, _prec) in s.by_class.items():
            before = prev_classes.get(klass)
            if before is not None and (before - recall) > min_drop:
                msgs.append(
                    f"REGRESSION: {s.tool} / {klass} recall {before:.2f} -> {recall:.2f}"
                )
    return msgs
