"""Import findings from a Burp Suite scan export.

Burp's REST API is a Professional-only feature, so Horizon doesn't call
Burp live — instead it accepts the standard "Report > XML" export
(Issue activity log / scan report XML) that any Burp edition can produce,
and normalizes it into Horizon findings.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "information": "info",
}


def parse_burp_xml(xml_text: str) -> list[dict]:
    findings: list[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.warning("Failed to parse Burp XML export: %s", exc)
        return findings

    for issue in root.findall("issue"):
        name = _text(issue, "name") or "Untitled Burp issue"
        host_el = issue.find("host")
        host = host_el.text if host_el is not None else None
        path = _text(issue, "path") or ""
        severity_raw = (_text(issue, "severity") or "information").strip().lower()
        confidence = _text(issue, "confidence")

        findings.append(
            {
                "title": name,
                "host": host,
                "path": path,
                "severity": _SEVERITY_MAP.get(severity_raw, "info"),
                "confidence": confidence,
            }
        )

    return findings


def _text(issue: ET.Element, tag: str) -> str | None:
    el = issue.find(tag)
    return el.text if el is not None else None
