# ruby-cmdi

Deliberately vulnerable Ruby/Sinatra application for SAST evaluation.

## Planted vulnerability

- **CWE-78 — Command Injection** (`app.rb` line 7)
  The `host` query parameter is interpolated directly into a backtick shell
  command (`ping -c 1 #{host}`) without sanitisation.  An attacker can supply
  `; cat /etc/passwd` to execute arbitrary commands.

## Purpose

Exercises SAST scanners' ability to detect command injection (taint from HTTP
parameter to shell sink) in Ruby source code.
