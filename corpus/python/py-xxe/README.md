# py-xxe

**Vuln class:** xxe (CWE-611)

XML parser that explicitly enables external entity resolution (`resolve_entities=True`,
`no_network=False`) on untrusted input via lxml's `etree.XMLParser`. An attacker can
supply a crafted XML document with an external entity reference to read local files or
trigger server-side request forgery.

**RC relevance:** Deepens RC05 triage signal and SAST taint coverage; tests whether
scanners flag lxml parser construction with insecure entity-resolution options on
untrusted XML bytes.
