# py-sca-pypi-old

Planted vulnerabilities: **known-vulnerable PyPI dependencies** — RC02.

`requirements.txt` pins three packages at versions with known CVEs:

| Package | Version | CVE | Severity |
|---------|---------|-----|----------|
| requests | 2.5.0 | CVE-2018-18074 | HIGH |
| pyyaml | 5.3 | CVE-2020-14343 | CRITICAL |
| jinja2 | 2.10 | CVE-2019-10906 | HIGH |

There are no SAST findings (no source files). This package exercises SCA-only
scanner coverage.

**RC exercised:** RC02 — SCA detection of pinned vulnerable dependencies.
