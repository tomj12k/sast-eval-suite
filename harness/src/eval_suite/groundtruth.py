# harness/src/eval_suite/groundtruth.py
"""Load and validate corpus ground-truth files."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import yaml

from eval_suite.models import GroundTruth, GroundTruthItem, ScaItem

SCHEMA_PATH = Path(__file__).resolve().parents[3] / "schema" / "groundtruth.schema.json"


def _validate(data: dict) -> None:
    """Validate raw ground-truth data against the JSON schema.

    :param data: parsed YAML mapping.
    :raises ValueError: if the data does not match the schema.
    """
    schema = json.loads(SCHEMA_PATH.read_text())
    try:
        jsonschema.validate(data, schema)
    except jsonschema.ValidationError as exc:
        raise ValueError(f"invalid ground truth: {exc.message}") from exc


def load_groundtruth(path: Path) -> GroundTruth:
    """Parse and validate a ``groundtruth.yaml`` file.

    :param path: path to the YAML file.
    :returns: the parsed ground truth.
    :rtype: GroundTruth
    :raises ValueError: if validation fails.
    """
    data = yaml.safe_load(path.read_text())
    _validate(data)
    findings = [
        GroundTruthItem(
            id=f["id"], file=f["file"], line=f["line"], cwe=f["cwe"],
            klass=f["class"], severity=f["severity"],
            exploitability=f["exploitability"], notes=f.get("notes"),
        )
        for f in data["findings"]
    ]
    sca = [
        ScaItem(name=s["name"], version=s["version"], ecosystem=s["ecosystem"],
                cve=s.get("cve"), severity=s.get("severity"))
        for s in data["sca"]
    ]
    return GroundTruth(
        package=data["package"], language=data["language"],
        ecosystem=data["ecosystem"], findings=findings, sca=sca,
    )


def discover_corpus(corpus_root: Path) -> list[GroundTruth]:
    """Find and load every ``groundtruth.yaml`` under a corpus root.

    :param corpus_root: directory containing language subdirs of packages.
    :returns: loaded ground truth for each package, sorted by package name.
    :rtype: list[GroundTruth]
    """
    out = [load_groundtruth(p) for p in sorted(corpus_root.rglob("groundtruth.yaml"))]
    return sorted(out, key=lambda g: g.package)
