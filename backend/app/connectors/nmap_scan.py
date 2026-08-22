"""Nmap integration: shell out to a local `nmap` binary for a live scan,
or parse an already-produced Nmap XML report (`nmap -oX -`) supplied via
the /imports/nmap endpoint. Both paths converge on the same XML parser so
"scan now" and "paste a report a real security team already ran" behave
identically.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import xml.etree.ElementTree as ET

from app.core.config import get_settings

logger = logging.getLogger(__name__)


def nmap_available() -> bool:
    settings = get_settings()
    return settings.nmap_enabled and shutil.which(settings.nmap_binary_path) is not None


def run_live_scan(target: str) -> str | None:
    """Runs a safe, top-1000-port TCP connect scan and returns raw XML."""
    settings = get_settings()
    if not nmap_available():
        return None
    try:
        completed = subprocess.run(
            [settings.nmap_binary_path, "-sT", "-T4", "--top-ports", "1000", "-oX", "-", target],
            capture_output=True,
            text=True,
            timeout=max(60.0, settings.connector_timeout_seconds * 4),
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("nmap scan failed for %s: %s", target, exc)
        return None
    if completed.returncode != 0 or not completed.stdout.strip():
        logger.warning("nmap exited %s for %s: %s", completed.returncode, target, completed.stderr[:500])
        return None
    return completed.stdout


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Extracts one finding dict per open port across all hosts in the report."""
    findings: list[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.warning("Failed to parse Nmap XML: %s", exc)
        return findings

    for host in root.findall("host"):
        address_el = host.find("address")
        host_ip = address_el.get("addr") if address_el is not None else None
        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else host_ip

        for port in host.findall("ports/port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port.find("service")
            service_name = service_el.get("name") if service_el is not None else "unknown"
            product = service_el.get("product") if service_el is not None else None
            version = service_el.get("version") if service_el is not None else None

            findings.append(
                {
                    "host": hostname or host_ip,
                    "ip": host_ip,
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "service": service_name,
                    "product": product,
                    "version": version,
                }
            )

    return findings
