# java-cmdi-sqli

SAST evaluation package containing deliberately planted command injection and SQL
injection vulnerabilities in Java. These are intentional scan targets — do not
sanitize the vulnerable code.

## Planted vulnerabilities

| ID | File | Line | CWE | Class |
|---|---|---|---|---|
| F1 | src/main/java/com/example/App.java | 9 | CWE-78 | command-injection |
| F2 | src/main/java/com/example/App.java | 16 | CWE-89 | sql-injection |

## Vulnerability details

**F1 (CWE-78):** `App.run()` passes a user-controlled `host` string directly to
`Runtime.getRuntime().exec()`. An attacker can inject shell metacharacters to run
arbitrary commands.

**F2 (CWE-89):** `App.lookup()` builds a SQL query by string concatenation of the
`user` parameter. An attacker can break out of the string literal and inject
arbitrary SQL.
