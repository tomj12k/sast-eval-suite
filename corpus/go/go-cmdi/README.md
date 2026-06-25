# go-cmdi

Deliberately vulnerable Go HTTP handler with a planted **OS command injection** sink (CWE-78).

`main.go` line 12 passes a user-controlled query parameter (`host`) directly into
`exec.Command("bash", "-c", ...)`, enabling arbitrary shell command execution.

This package exercises Go SAST detection. The vulnerability is intentional — do not
sanitize it. SCA scanners should find no vulnerable dependencies (`sca: []` in groundtruth).

## Intended finding

| Field | Value |
|-------|-------|
| File | `main.go` |
| Line | 12 |
| CWE | CWE-78 (OS Command Injection) |
| Severity | HIGH |
| Exploitability | true-positive |
