from pathlib import Path

from eval_suite.runners.base import run_cmd


def test_run_cmd_captures_exit_and_json(tmp_path: Path):
    res = run_cmd(["python", "-c", "print('{\"ok\": 1}')"], cwd=tmp_path)
    assert res.returncode == 0
    assert res.raw == {"ok": 1}


def test_run_cmd_nonzero_does_not_raise(tmp_path: Path):
    res = run_cmd(["python", "-c", "import sys; sys.exit(3)"], cwd=tmp_path)
    assert res.returncode == 3
    assert res.raw is None
