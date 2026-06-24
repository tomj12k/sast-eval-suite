"""Match normalized findings against package ground truth."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath

from eval_suite.models import Finding, GroundTruth, GroundTruthItem, ScaItem


@dataclass(frozen=True)
class MatchResult:
    """Outcome of matching one tool's findings against one package."""

    tp: list[GroundTruthItem] = field(default_factory=list)
    fn: list[GroundTruthItem] = field(default_factory=list)
    fp: list[Finding] = field(default_factory=list)
    matched_pairs: list[tuple[GroundTruthItem, Finding]] = field(default_factory=list)
    sca_tp: list[ScaItem] = field(default_factory=list)
    sca_fn: list[ScaItem] = field(default_factory=list)


def _basename(path: str | None) -> str | None:
    return PurePosixPath(path).name if path else None


def _sast_matches(finding: Finding, item: GroundTruthItem, tol: int) -> bool:
    if finding.kind not in ("sast", "secret"):
        return False
    if _basename(finding.file) != _basename(item.file):
        return False
    if finding.line is None:
        return False
    return abs(finding.line - item.line) <= tol


def _sca_matches(finding: Finding, item: ScaItem) -> bool:
    if finding.kind != "sca":
        return False
    if (finding.package or "").lower() != item.name.lower():
        return False
    return (finding.version or "") == item.version


def match(findings: list[Finding], gt: GroundTruth, line_tolerance: int = 3) -> MatchResult:
    """Match a tool's findings against a package's ground truth.

    :param findings: normalized findings from one tool for one package.
    :param gt: the package ground truth.
    :param line_tolerance: max line distance for a SAST/secret match.
    :returns: the match result.
    :rtype: MatchResult
    """
    res = MatchResult()
    consumed: set[int] = set()

    # SAST / secret matching against every labeled item (incl. FP decoys).
    for item in gt.findings:
        hit: Finding | None = None
        for idx, f in enumerate(findings):
            if idx in consumed:
                continue
            if _sast_matches(f, item, line_tolerance):
                hit = f
                consumed.add(idx)
                break
        if hit is not None:
            if item.exploitability == "false-positive":
                res.fp.append(hit)  # tool reported a known FP decoy
            else:
                res.tp.append(item)
                res.matched_pairs.append((item, hit))
        elif item.exploitability != "false-positive":
            res.fn.append(item)  # a real/mitigated item the tool missed

    # SCA matching.
    sca_consumed: set[int] = set()
    for item in gt.sca:
        hit_sca = False
        for idx, f in enumerate(findings):
            if idx in sca_consumed:
                continue
            if _sca_matches(f, item):
                sca_consumed.add(idx)
                hit_sca = True
                break
        if hit_sca:
            res.sca_tp.append(item)
        else:
            res.sca_fn.append(item)

    # Any SAST/secret finding not matched to a labeled item is a false positive.
    for idx, f in enumerate(findings):
        if f.kind in ("sast", "secret") and idx not in consumed:
            res.fp.append(f)

    return res
