import json
from pathlib import Path

from eval_suite.report.trend import append_run, check_regression
from eval_suite.score.metrics import ToolScore


def test_regression_detected_when_recall_drops(tmp_path: Path):
    tp = tmp_path / "trend.json"
    append_run(tp, [ToolScore(tool="joern", recall=1.0, precision=1.0,
                              by_class={"ssrf": (1.0, 1.0)})], stamp="2026-06-23T00:00:00Z")
    msgs = check_regression(
        tp, [ToolScore(tool="joern", recall=0.0, precision=0.0,
                       by_class={"ssrf": (0.0, 0.0)})]
    )
    assert any("joern" in m and "ssrf" in m for m in msgs)


def test_no_regression_when_stable(tmp_path: Path):
    tp = tmp_path / "trend.json"
    append_run(tp, [ToolScore(tool="t", recall=1.0, precision=1.0,
                              by_class={"xss": (1.0, 1.0)})], stamp="2026-06-23T00:00:00Z")
    msgs = check_regression(
        tp, [ToolScore(tool="t", recall=1.0, precision=1.0,
                       by_class={"xss": (1.0, 1.0)})]
    )
    assert msgs == []


def test_append_run_accumulates(tmp_path: Path):
    tp = tmp_path / "trend.json"
    append_run(tp, [ToolScore(tool="t1", recall=0.9, precision=0.85,
                              by_class={"sql": (0.9, 0.85)})], stamp="2026-06-23T00:00:00Z")
    append_run(tp, [ToolScore(tool="t1", recall=0.88, precision=0.87,
                              by_class={"sql": (0.88, 0.87)})], stamp="2026-06-24T00:00:00Z")
    data = json.loads(tp.read_text())
    assert len(data) == 2
