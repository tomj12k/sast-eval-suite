# go-sca-old

Deliberately vulnerable Go module pinning `github.com/dgrijalva/jwt-go v3.2.0+incompatible`,
which is affected by **CVE-2020-26160** (JWT audience claim validation bypass, CVSS 7.5 HIGH).

This package exercises non-Maven SCA detection (RC02 breadth). There is no Go source code —
only `go.mod` and `go.sum` are present. SCA scanners (OSV-Scanner, etc.) should flag the
vulnerable dependency via `go.mod`.

**No SAST findings are expected** — `findings` is empty in `groundtruth.yaml`.
