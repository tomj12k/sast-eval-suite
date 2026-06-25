# harness/tests/test_cli.py
from pathlib import Path

from eval_suite.cli import score_corpus
from eval_suite.models import Finding


def _make_corpus(tmp_path: Path) -> Path:
    d = tmp_path / "python" / "py-xss"
    d.mkdir(parents=True)
    (d / "groundtruth.yaml").write_text(
        "package: py-xss\nlanguage: python\necosystem: pypi\n"
        "findings:\n  - id: F1\n    file: app.py\n    line: 10\n"
        "    cwe: CWE-79\n    class: xss\n    severity: HIGH\n"
        "    exploitability: true-positive\nsca: []\n"
    )
    return tmp_path


def test_score_corpus_perfect_tool(tmp_path: Path):
    corpus = _make_corpus(tmp_path)
    by_package = {
        "py-xss": {"semgrep": [Finding(tool="semgrep", kind="sast",
                                       file="app.py", line=10, cwe="CWE-79")]}
    }
    scores = score_corpus(corpus, by_package)
    semgrep = next(s for s in scores if s.tool == "semgrep")
    assert semgrep.recall == 1.0
