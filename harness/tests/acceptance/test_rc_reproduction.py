# harness/tests/acceptance/test_rc_reproduction.py
"""Acceptance tests: reproduce RC01-RC05 from fixture findings without live scanners.

Each test asserts one root-cause from the initial evaluation round:

  RC01 — AI/Joern scan returns zero findings on a no-entry-point library.
  RC02 — ODC (scntnms) misses PyPI SCA but catches Maven SCA; a competitor fills the gap.
  RC03 — scntnms has no basic-auth-in-URL secret rule; a competitor finds it.
  RC04 — scntnms reports a MEDIUM finding but with no remediation guidance.
  RC05 — scntnms reports the XSS false-positive decoy, hurting triage accuracy.
"""

from __future__ import annotations

from pathlib import Path

from eval_suite.cli import score_corpus
from eval_suite.models import Finding

# parents[3]: acceptance/ -> tests/ -> harness/ -> repo-root
CORPUS = Path(__file__).resolve().parents[3] / "corpus"


def _scn(**kw: object) -> Finding:
    return Finding(tool="scntnms", **kw)  # type: ignore[arg-type]


def _comp(tool: str, **kw: object) -> Finding:
    return Finding(tool=tool, **kw)  # type: ignore[arg-type]


def _by_package() -> dict[str, dict[str, list[Finding]]]:
    return {
        "py-noentry-lib": {
            "scntnms": [],  # RC01: AI scan silent-zero on no-entry-point repo
            "semgrep": [_comp("semgrep", kind="sast", file="fetcher.py", line=8, cwe="CWE-918")],
        },
        "py-sca-pypi-old": {
            "scntnms": [],  # RC02: ODC misses PyPI
            "osv-scanner": [
                _comp("osv-scanner", kind="sca", package="requests",
                      version="2.5.0", cve="CVE-2018-18074"),
                _comp("osv-scanner", kind="sca", package="pyyaml",
                      version="5.3", cve="CVE-2020-14343"),
                _comp("osv-scanner", kind="sca", package="jinja2",
                      version="2.10", cve="CVE-2019-10906"),
            ],
        },
        "java-sca-maven-old": {
            # RC02 control: Maven SCA IS caught by scntnms (both entries)
            "scntnms": [
                _scn(kind="sca", package="log4j-core", version="2.14.1",
                     cve="CVE-2021-44228"),
                _scn(kind="sca", package="jackson-databind", version="2.9.8",
                     cve="CVE-2019-12384"),
            ],
        },
        "py-secrets-basicauth": {
            "scntnms": [],  # RC03: no basic-auth-in-URL rule
            "trivy": [_comp("trivy", kind="secret", file="config.py", line=4, cwe="CWE-798")],
        },
        "py-medsev-bug": {
            # RC04: MEDIUM finding matched but remediation is null
            "scntnms": [
                _scn(kind="sast", file="crypto_util.py", line=7, cwe="CWE-327",
                     severity="MEDIUM", remediation=None),
            ],
        },
        "py-xss-triad": {
            # RC05: tool reports the FP decoy at line 128 -> triage < 1.0
            "scntnms": [
                _scn(kind="sast", file="app.py", line=113, cwe="CWE-79"),
                _scn(kind="sast", file="app.py", line=128, cwe="CWE-79"),
            ],
        },
    }


def _score(tool: str) -> object:
    scores = score_corpus(CORPUS, _by_package())
    return next(s for s in scores if s.tool == tool)


def test_rc01_joern_silent_zero() -> None:
    """RC01: scntnms returns nothing for the SSRF class; a competitor detects it."""
    scn = _score("scntnms")
    # Scantonomous catches nothing for ssrf; a competitor does.
    assert scn.by_class.get("ssrf", (0.0, 0.0))[0] == 0.0  # type: ignore[union-attr]
    assert _score("semgrep").by_class["ssrf"][0] == 1.0  # type: ignore[union-attr]


def test_rc02_non_maven_sca_gap() -> None:
    """RC02: scntnms ODC misses PyPI SCA; competitor catches it; Maven IS caught."""
    scn = _score("scntnms")
    osv = _score("osv-scanner")
    # PyPI ecosystem recall: scntnms 0, competitor 1; Maven recall for scntnms 1.
    assert scn.by_ecosystem.get("pypi", (0.0, 0.0))[0] == 0.0  # type: ignore[union-attr]
    assert osv.by_ecosystem["pypi"][0] == 1.0  # type: ignore[union-attr]
    assert scn.by_ecosystem["maven"][0] == 1.0  # type: ignore[union-attr]


def test_rc03_basic_auth_secret_gap() -> None:
    """RC03: scntnms has no basic-auth-URL secret rule; trivy catches it."""
    scn = _score("scntnms")
    assert scn.by_class.get("secret-basic-auth-url", (0.0, 0.0))[0] == 0.0  # type: ignore[union-attr]
    assert _score("trivy").by_class["secret-basic-auth-url"][0] == 1.0  # type: ignore[union-attr]


def test_rc04_remediation_gate_on_medium() -> None:
    """RC04: the MEDIUM finding matched but carried no remediation guidance."""
    scn = _score("scntnms")
    # The MEDIUM finding matched but carried no remediation.
    assert scn.remediation_coverage is not None  # type: ignore[union-attr]
    assert scn.remediation_coverage == 0.0  # type: ignore[union-attr]


def test_rc05_triage_fails_on_fp_decoy() -> None:
    """RC05: scntnms reports the XSS FP decoy (line 128), hurting triage accuracy."""
    scn = _score("scntnms")
    assert scn.triage_accuracy is not None  # type: ignore[union-attr]
    assert scn.triage_accuracy < 1.0  # type: ignore[union-attr]
