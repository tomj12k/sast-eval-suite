"""XML parser that resolves external entities on untrusted input (planted vuln)."""

from lxml import etree


def parse(xml_bytes: bytes):
    # VULN: external entity resolution enabled on untrusted XML -> XXE.
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    return etree.fromstring(xml_bytes, parser=parser)
