from eval_suite.report.render import render_json, render_markdown
from eval_suite.score.metrics import ToolScore


def test_render_markdown_contains_tool_and_recall():
    s = ToolScore(tool="semgrep", recall=0.8, precision=0.9,
                  by_class={"xss": (1.0, 1.0)})
    md = render_markdown([s])
    assert "semgrep" in md
    assert "0.8" in md


def test_render_json_roundtrips_fields():
    s = ToolScore(tool="t", recall=0.5, precision=0.5)
    out = render_json([s])
    assert out["tools"][0]["tool"] == "t"
    assert out["tools"][0]["recall"] == 0.5
