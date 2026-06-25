"""Load Claude /security-review output for a target.

The /security-review command is run out-of-band; this runner reads its JSON
output from ``<target>/.claude-review.json`` when present.
"""

from __future__ import annotations

import json
from pathlib import Path

from eval_suite.models import Finding
from eval_suite.normalize.claude import claude_to_findings

NAME = "claude-security-review"


def run(target: Path) -> list[Finding]:
    """Load Claude security-review findings for a target, if present.

    :param target: package directory.
    :returns: normalized findings (empty if no output present).
    :rtype: list[Finding]
    """
    path = target / ".claude-review.json"
    if not path.exists():
        return []
    return claude_to_findings(json.loads(path.read_text()), tool=NAME)
