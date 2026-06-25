# java-rest-api

**SAST evaluation corpus fixture — DO NOT DEPLOY.**

A minimal multi-file Spring-style Java REST service. All classes use only JDK
stdlib; no Spring context is needed. These are static-analysis targets, not a
runnable application.

## Planted vulnerabilities

| ID | File | Line | CWE | Class | Notes |
|----|------|------|-----|-------|-------|
| F1 | `src/main/java/com/example/UserRepository.java` | 29 | CWE-89 | sql-injection | String-concatenated SQL in `findByName()` |
| F2 | `src/main/java/com/example/FetchClient.java` | 24 | CWE-918 | ssrf | Caller-supplied URL in `new URL(url).openStream()` |
| F3 | `src/main/java/com/example/Controller.java` | 22 | CWE-639 | broken-access-control | `getProfile()` with no ownership/auth check |
| F4 | `src/main/java/com/example/AppConfig.java` | 12 | CWE-798 | hardcoded-secret | Literal `API_KEY` value in static field |

## Structure

```
pom.xml
src/main/java/com/example/
    AppConfig.java        # hardcoded secret (F4)
    UserRepository.java   # SQL injection (F1)
    FetchClient.java      # SSRF (F2)
    Controller.java       # IDOR / broken access control (F3)
groundtruth.yaml
README.md
```
