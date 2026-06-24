import json
from pathlib import Path

import jsonschema

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schema"


def _load(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text())


def test_groundtruth_schema_is_valid_and_accepts_sample():
    schema = _load("groundtruth.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)
    sample = {
        "package": "py-xss-triad",
        "language": "python",
        "ecosystem": "pypi",
        "findings": [
            {
                "id": "F1",
                "file": "app.py",
                "line": 113,
                "cwe": "CWE-79",
                "class": "xss-reflected",
                "severity": "HIGH",
                "exploitability": "true-positive",
            }
        ],
        "sca": [],
    }
    jsonschema.validate(sample, schema)


def test_groundtruth_schema_rejects_bad_exploitability():
    schema = _load("groundtruth.schema.json")
    bad = {
        "package": "x",
        "language": "python",
        "ecosystem": "pypi",
        "findings": [
            {"id": "F1", "file": "a.py", "line": 1, "cwe": "CWE-79",
             "class": "xss", "severity": "HIGH", "exploitability": "maybe"}
        ],
        "sca": [],
    }
    with __import__("pytest").raises(jsonschema.ValidationError):
        jsonschema.validate(bad, schema)


def test_finding_schema_is_valid():
    schema = _load("finding.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)
