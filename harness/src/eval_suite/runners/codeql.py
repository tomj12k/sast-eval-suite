"""Run CodeQL CLI (database create + analyze) and normalize SARIF.

CodeQL requires a per-language database build; this runner expects a prebuilt
SARIF at ``<target>/.codeql.sarif`` (produced by CI or a local script) to keep
the harness fast and CI-portable.
"""

from __future__ import annotations

import json
from pathlib import Path

from eval_suite.models import Finding
from eval_suite.normalize.sarif import sarif_to_findings

NAME = "codeql"


def run(target: Path) -> list[Finding]:
    """Load a prebuilt CodeQL SARIF for a target, if present.

    :param target: package directory.
    :returns: normalized findings (empty if no SARIF present).
    :rtype: list[Finding]
    """
    sarif_path = target / ".codeql.sarif"
    if not sarif_path.exists():
        return []
    return sarif_to_findings(json.loads(sarif_path.read_text()), tool=NAME)
