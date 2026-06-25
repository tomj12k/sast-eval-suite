"""Background worker that deserializes untrusted task payloads (planted vuln)."""

import pickle


def handle(payload: bytes) -> object:
    # VULN: untrusted bytes passed to pickle.loads -> arbitrary code execution.
    return pickle.loads(payload)  # noqa: S301
