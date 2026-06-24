# harness/tests/test_groundtruth.py
from pathlib import Path

import pytest

from eval_suite.groundtruth import discover_corpus, load_groundtruth
from eval_suite.models import GroundTruth


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "groundtruth.yaml"
    p.write_text(body)
    return p


def test_load_groundtruth_parses_fields(tmp_path: Path):
    p = _write(tmp_path, """
package: py-xss-triad
language: python
ecosystem: pypi
findings:
  - id: F1
    file: app.py
    line: 113
    cwe: CWE-79
    class: xss-reflected
    severity: HIGH
    exploitability: true-positive
sca: []
""")
    gt = load_groundtruth(p)
    assert isinstance(gt, GroundTruth)
    assert gt.package == "py-xss-triad"
    assert gt.findings[0].klass == "xss-reflected"
    assert gt.findings[0].exploitability == "true-positive"


def test_load_groundtruth_rejects_invalid(tmp_path: Path):
    p = _write(tmp_path, """
package: x
language: python
ecosystem: pypi
findings:
  - id: F1
    file: a.py
    line: 1
    cwe: CWE-79
    class: xss
    severity: HIGH
    exploitability: maybe
sca: []
""")
    with pytest.raises(ValueError):
        load_groundtruth(p)


def test_discover_corpus_finds_all(tmp_path: Path):
    for name in ("a", "b"):
        d = tmp_path / "python" / name
        d.mkdir(parents=True)
        (d / "groundtruth.yaml").write_text(
            "package: %s\nlanguage: python\necosystem: pypi\nfindings: []\nsca: []\n" % name
        )
    found = discover_corpus(tmp_path)
    assert {g.package for g in found} == {"a", "b"}
