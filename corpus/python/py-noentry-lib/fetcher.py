"""A plain library with SSRF and path traversal sinks and no entry point."""

import urllib.request


def fetch(url: str) -> bytes:
    # VULN: SSRF — caller-supplied URL fetched with no allowlist.
    with urllib.request.urlopen(url) as resp:  # noqa: S310
        return resp.read()


def read_user_file(base: str, name: str) -> str:
    # VULN: path traversal — name joined without normalization checks.
    path = base + "/" + name
    with open(path, encoding="utf-8") as fh:
        return fh.read()
