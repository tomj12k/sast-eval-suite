# java-xxe

Deliberately-vulnerable Java package for SAST corpus evaluation.

## Vulnerability

**CWE-611 — Improper Restriction of XML External Entity Reference** (xxe)

`XmlParser.parse()` builds a `DocumentBuilder` from a default `DocumentBuilderFactory`
without disabling DTD processing or external entity resolution. An attacker who controls
the XML input can read arbitrary files from the server or perform server-side request
forgery via `SYSTEM` or `PUBLIC` entity declarations.

## Planted finding

| ID | File | Line | CWE | Severity |
|----|------|------|-----|----------|
| F1 | `src/main/java/com/example/XmlParser.java` | 13 | CWE-611 | HIGH |

## Remediation (do not apply — corpus file must remain vulnerable)

Disable DTD and external entity features on the factory before building the parser:

```java
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```
