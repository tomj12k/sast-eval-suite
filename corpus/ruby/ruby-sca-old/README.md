# ruby-sca-old

Deliberately vulnerable Ruby package for SCA evaluation.

## Planted vulnerability

- **CVE-2019-16782** — `rack` 2.0.5 has a session fixation vulnerability in its
  session middleware.  Fixed in `rack` 2.0.8+ and 1.6.12+.

## Purpose

Exercises OSV-Scanner's RubyGems (Gemfile.lock) coverage path.  The package
contains no application source — only the Gemfile and lock file needed for SCA
scanning.
