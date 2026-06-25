# dotnet-sqli

Deliberately vulnerable .NET application for SAST evaluation (SQL injection).

## Purpose

Contains an intentional SQL injection sink in `Program.cs` (CWE-89): user input
is concatenated directly into a SQL string passed to `SqlCommand`. Used to verify
that SAST scanners (Semgrep, SonarQube, etc.) detect unsanitised string
concatenation in ADO.NET query construction.

## Expected findings

| ID | File | Line | CWE | Class |
|----|------|------|-----|-------|
| F1 | Program.cs | 8 | CWE-89 | sql-injection |

## Notes

- **DELIBERATELY VULNERABLE** — do not sanitize.
- No NuGet packages — SAST-only target; `sca: []` in groundtruth.
- The tainted value (`user`) flows from the method parameter directly into
  the concatenated query string on line 8.
