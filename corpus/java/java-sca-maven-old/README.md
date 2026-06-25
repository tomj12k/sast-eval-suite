# java-sca-maven-old

RC02 control package for Maven SCA evaluation. Contains deliberately old/vulnerable
Maven dependencies that a SCA scanner (e.g. OWASP Dependency-Check) should detect.

## Planted vulnerabilities

| Dependency | Version | CVE | Severity |
|---|---|---|---|
| log4j-core | 2.14.1 | CVE-2021-44228 (Log4Shell) | CRITICAL |
| jackson-databind | 2.9.8 | CVE-2019-12384 | HIGH |

## Purpose

Contrasted against `py-sca-pypi-old` (Python/PyPI ecosystem) for RC02 to confirm
cross-ecosystem SCA coverage. No application source code; groundtruth is SCA-only.
