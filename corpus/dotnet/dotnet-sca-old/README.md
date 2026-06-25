# dotnet-sca-old

Deliberately outdated .NET library package for SCA evaluation.

## Purpose

Pins `Newtonsoft.Json 12.0.1`, which is affected by **CVE-2024-21907**
(ReDoS via `JsonPath` pattern matching). Used to verify that SCA scanners
(Trivy, OSV-Scanner) correctly flag known-vulnerable NuGet dependencies.

## Expected findings

| Type | Package | Version | CVE |
|------|---------|---------|-----|
| SCA  | Newtonsoft.Json | 12.0.1 | CVE-2024-21907 |

## Notes

- No source code — manifest-only package.
- `packages.lock.json` is the primary SCA manifest; `dotnet-sca-old.csproj`
  is included for completeness and belt-and-suspenders scanner coverage.
