"""Compute recall/precision/triage/remediation scores from match results."""

from __future__ import annotations

from dataclasses import dataclass, field

from eval_suite.models import Finding, GroundTruth
from eval_suite.score.match import MatchResult


@dataclass(frozen=True)
class ToolScore:
    """Aggregate scores for one tool across the corpus."""

    tool: str
    recall: float
    precision: float
    by_class: dict[str, tuple[float, float]] = field(default_factory=dict)
    by_ecosystem: dict[str, tuple[float, float]] = field(default_factory=dict)
    triage_accuracy: float | None = None
    remediation_coverage: float | None = None


def _ratio(num: int, den: int) -> float:
    return num / den if den else 0.0


def score_tool(
    tool: str, per_pkg: list[tuple[GroundTruth, MatchResult, list[Finding]]]
) -> ToolScore:
    """Aggregate per-package match results into a tool score.

    :param tool: tool name.
    :param per_pkg: triples of (ground truth, match result, raw findings).
    :returns: aggregate score.
    :rtype: ToolScore
    """
    tp = fp = fn = 0
    class_tp: dict[str, int] = {}
    class_fn: dict[str, int] = {}
    class_fp: dict[str, int] = {}
    eco_tp: dict[str, int] = {}
    eco_fn: dict[str, int] = {}
    triage_total = triage_ok = 0
    remediable_total = remediable_ok = 0

    for gt, res, _findings in per_pkg:
        sast_tp = len(res.tp) + len(res.sca_tp)
        sast_fn = len(res.fn) + len(res.sca_fn)
        sast_fp = len(res.fp)
        tp += sast_tp
        fn += sast_fn
        fp += sast_fp

        # by_ecosystem tracks SCA recall/precision only; SAST is tracked by by_class.
        sca_tp_count = len(res.sca_tp)
        sca_fn_count = len(res.sca_fn)
        if sca_tp_count or sca_fn_count:
            eco_tp[gt.ecosystem] = eco_tp.get(gt.ecosystem, 0) + sca_tp_count
            eco_fn[gt.ecosystem] = eco_fn.get(gt.ecosystem, 0) + sca_fn_count

        for item, _f in res.matched_pairs:
            class_tp[item.klass] = class_tp.get(item.klass, 0) + 1
        for item in res.fn:
            class_fn[item.klass] = class_fn.get(item.klass, 0) + 1

        # Attribute FP findings to a class via CWE -> class map from ground truth.
        cwe_to_klass: dict[str, str] = {}
        for item in gt.findings:
            if item.cwe not in cwe_to_klass:
                cwe_to_klass[item.cwe] = item.klass
        for f in res.fp:
            if f.cwe is not None and f.cwe in cwe_to_klass:
                klass = cwe_to_klass[f.cwe]
                class_fp[klass] = class_fp.get(klass, 0) + 1

        # Triage: each labeled SAST item is one decision.
        matched_ids = {item.id for item, _ in res.matched_pairs}
        for item in gt.findings:
            triage_total += 1
            if item.exploitability == "false-positive":
                # correct iff the tool did NOT report it (not in matched/fp by location)
                reported = any(
                    _f.file and item.file and _f.file.endswith(item.file.split("/")[-1])
                    and _f.line is not None and abs(_f.line - item.line) <= 3
                    for _f in res.fp
                )
                triage_ok += 0 if reported else 1
            else:
                triage_ok += 1 if item.id in matched_ids else 0

        # Remediation coverage over matched SAST pairs + matched SCA.
        for _item, f in res.matched_pairs:
            remediable_total += 1
            if f.remediation:
                remediable_ok += 1
        for item in res.sca_tp:
            remediable_total += 1
            # find the matching finding's remediation
            for f in _findings:
                if (f.package or "").lower() == item.name.lower() and (f.version or "") == item.version:
                    if f.remediation:
                        remediable_ok += 1
                    break

    by_class = {
        k: (
            _ratio(class_tp.get(k, 0), class_tp.get(k, 0) + class_fn.get(k, 0)),
            _ratio(class_tp.get(k, 0), class_tp.get(k, 0) + class_fp.get(k, 0)),
        )
        for k in set(class_tp) | set(class_fn) | set(class_fp)
    }
    by_eco = {
        k: (
            _ratio(eco_tp.get(k, 0), eco_tp.get(k, 0) + eco_fn.get(k, 0)),
            _ratio(eco_tp.get(k, 0), eco_tp.get(k, 0)),  # precision = tp/(tp+0) for SCA
        )
        for k in set(eco_tp) | set(eco_fn)
    }
    return ToolScore(
        tool=tool,
        recall=_ratio(tp, tp + fn),
        precision=_ratio(tp, tp + fp),
        by_class=by_class,
        by_ecosystem=by_eco,
        triage_accuracy=_ratio(triage_ok, triage_total) if triage_total else None,
        remediation_coverage=_ratio(remediable_ok, remediable_total) if remediable_total else None,
    )
