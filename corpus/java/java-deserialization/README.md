# java-deserialization

Deliberately-vulnerable Java package for SAST corpus evaluation.

## Vulnerability

**CWE-502 — Deserialization of Untrusted Data** (insecure-deserialization)

`Worker.handle()` creates an `ObjectInputStream` directly from caller-supplied bytes and
calls `readObject()` with no type checking or integrity verification. An attacker who
controls the payload can supply a malicious gadget chain to achieve remote code execution.

## Planted finding

| ID | File | Line | CWE | Severity |
|----|------|------|-----|----------|
| F1 | `src/main/java/com/example/Worker.java` | 10 | CWE-502 | HIGH |

## Remediation (do not apply — corpus file must remain vulnerable)

Use a safe deserialization library (e.g. Jackson with explicit type binding) or validate
HMAC/signature before deserializing. Never call `ObjectInputStream.readObject()` on
untrusted bytes.
