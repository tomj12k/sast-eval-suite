# harness/tests/test_corpus_integrity.py
from pathlib import Path

from eval_suite.groundtruth import discover_corpus

CORPUS = Path(__file__).resolve().parents[2] / "corpus"


def test_all_groundtruth_valid_and_lines_exist():
    packages = discover_corpus(CORPUS)
    assert packages, "no corpus packages found"
    for gt in packages:
        pkg_dir = next(CORPUS.rglob(f"{gt.package}/groundtruth.yaml")).parent
        for item in gt.findings:
            src = pkg_dir / item.file
            assert src.exists(), f"{gt.package}: missing {item.file}"
            n_lines = len(src.read_text().splitlines())
            assert 1 <= item.line <= n_lines, f"{gt.package}:{item.file}:{item.line} OOB"


def test_python_corpus_has_expected_packages():
    names = {g.package for g in discover_corpus(CORPUS)}
    assert {"py-webapp-cmdi", "py-noentry-lib", "py-sca-pypi-old",
            "py-secrets-basicauth", "py-xss-triad", "py-medsev-bug"} <= names


def test_java_corpus_has_expected_packages():
    from eval_suite.groundtruth import discover_corpus
    names = {g.package for g in discover_corpus(CORPUS)}
    assert {"java-sca-maven-old", "java-cmdi-sqli"} <= names


def test_go_corpus_present():
    from eval_suite.groundtruth import discover_corpus
    names = {g.package for g in discover_corpus(CORPUS)}
    assert {"go-sca-old", "go-cmdi"} <= names


def test_rust_ruby_corpus_present():
    from eval_suite.groundtruth import discover_corpus
    names = {g.package for g in discover_corpus(CORPUS)}
    assert {"rust-sca-old", "ruby-sca-old", "ruby-cmdi"} <= names


def test_schema_accepts_new_ecosystems():
    import json
    from pathlib import Path

    import jsonschema

    schema = json.loads(
        (Path(__file__).resolve().parents[2] / "schema" / "groundtruth.schema.json").read_text()
    )
    sample = {
        "package": "go-sca-old",
        "language": "go",
        "ecosystem": "go",
        "findings": [],
        "sca": [{"name": "x", "version": "1.0.0", "ecosystem": "go"}],
    }
    jsonschema.validate(sample, schema)  # must not raise
