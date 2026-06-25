# py-medsev-bug

Planted vulnerability: **Weak Hash Algorithm** (CWE-327) — RC04.

`crypto_util.py` line 7: `hashlib.md5(data).hexdigest()` used for a
security-relevant fingerprint. MD5 is cryptographically broken and should not
be used where collision resistance or preimage resistance matter.

This is a MEDIUM-severity finding (not HIGH) — suitable for testing
scanner severity classification and RC04 remediation-gate scenarios.

**RC exercised:** RC04 — detection of weak cryptographic primitives used in
security-relevant contexts.
