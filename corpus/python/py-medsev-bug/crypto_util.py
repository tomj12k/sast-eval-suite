"""Utility with a MEDIUM-severity weak-hash bug (planted)."""

import hashlib


def fingerprint(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()  # noqa: S324  VULN: MD5 for security fingerprint
