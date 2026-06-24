# SAST/SCA Evaluation Suite

A harness for evaluating SAST/SCA scanner quality — measuring detection rate, false-positive rate, and ranking consistency across tools and rule sets.

## Development

Requires Python 3.13. Uses `uv` for dependency management.

```bash
# Install deps
uv sync

# Run tests
uv run pytest

# Lint
uv run ruff check .

# Type check
uv run pyright
```
