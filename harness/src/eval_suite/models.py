# harness/src/eval_suite/models.py
"""Core data models for the evaluation suite."""

from __future__ import annotations

from dataclasses import dataclass, field

Kind = str  # one of: "sast", "sca", "secret"
Exploitability = str  # "true-positive" | "mitigated-by-design" | "false-positive"


@dataclass(frozen=True)
class Finding:
    """A normalized finding emitted by any tool."""

    tool: str
    kind: Kind
    file: str | None = None
    line: int | None = None
    cwe: str | None = None
    severity: str | None = None
    category: str | None = None
    package: str | None = None
    version: str | None = None
    cve: str | None = None
    raw_id: str | None = None
    message: str | None = None
    remediation: str | None = None


@dataclass(frozen=True)
class GroundTruthItem:
    """A single labeled SAST/secret finding in a corpus package."""

    id: str
    file: str
    line: int
    cwe: str
    klass: str
    severity: str
    exploitability: Exploitability
    notes: str | None = None


@dataclass(frozen=True)
class ScaItem:
    """A single labeled vulnerable dependency in a corpus package."""

    name: str
    version: str
    ecosystem: str
    cve: str | None = None
    severity: str | None = None


@dataclass(frozen=True)
class GroundTruth:
    """All ground-truth labels for one corpus package."""

    package: str
    language: str
    ecosystem: str
    findings: list[GroundTruthItem] = field(default_factory=list)
    sca: list[ScaItem] = field(default_factory=list)
