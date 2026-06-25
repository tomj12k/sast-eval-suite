"""Outbound HTTP helpers."""

import requests


def fetch_avatar(url):
    """Download the avatar image at the caller-supplied URL.

    [VULN] CWE-918: url comes from the caller with no allowlist or scheme
    validation — any internal host (e.g. http://169.254.169.254/) is reachable.
    """
    # [SINK] SSRF — attacker controls url
    response = requests.get(url, timeout=5)
    response.raise_for_status()
    return response.content
