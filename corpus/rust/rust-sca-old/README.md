# rust-sca-old

Deliberately vulnerable Rust package for SCA evaluation.

## Planted vulnerability

- **RUSTSEC-2020-0071** — `time` crate 0.1.43 has a UNIX time-of-check/time-of-use
  vulnerability (unsound `localtime_r` call can trigger UB under concurrent TZ
  mutation).  Fixed in `time` 0.2.23+.

## Purpose

Exercises OSV-Scanner's cargo (Cargo.lock) coverage path.  The package contains
no application source — only the manifest and lock file needed for SCA scanning.
