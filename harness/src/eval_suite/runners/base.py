"""Subprocess helper for invoking external scanner CLIs."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RunResult:
    """Result of running an external CLI."""

    tool: str
    returncode: int
    stdout: str
    stderr: str
    raw: dict | None


def run_cmd(cmd: list[str], cwd: Path) -> RunResult:
    """Run a command, capturing output without raising on non-zero exit.

    :param cmd: argv list.
    :param cwd: working directory.
    :returns: the run result; ``raw`` is parsed JSON stdout when possible.
    :rtype: RunResult
    """
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    raw: dict | None = None
    try:
        raw = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        raw = None
    return RunResult(cmd[0], proc.returncode, proc.stdout, proc.stderr, raw)
