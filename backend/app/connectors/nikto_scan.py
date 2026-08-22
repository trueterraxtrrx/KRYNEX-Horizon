"""Nikto web-server scanner integration. Shells out to a locally-installed
`nikto` binary — Horizon never downloads or installs it. If it isn't on
PATH, `nikto_available()` returns False and the connector is skipped.

ACTIVE connector: Nikto actively probes for known-vulnerable paths and
misconfigurations. Gated by Asset.authorized_for_active_testing.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from app.core.config import get_settings

logger = logging.getLogger(__name__)


def nikto_available() -> bool:
    return shutil.which("nikto") is not None


def run_scan(target_url: str) -> list[dict]:
    if not nikto_available():
        return []
    settings = get_settings()
    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir) / "nikto_output.json"
        try:
            subprocess.run(
                ["nikto", "-h", target_url, "-Format", "json", "-output", str(output_path), "-nointeractive"],
                capture_output=True,
                text=True,
                timeout=max(120.0, settings.connector_timeout_seconds * 8),
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            logger.warning("nikto scan failed for %s: %s", target_url, exc)
            return []

        if not output_path.exists():
            return []
        try:
            data = json.loads(output_path.read_text(encoding="utf-8", errors="ignore"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to parse nikto output for %s: %s", target_url, exc)
            return []

    vulnerabilities = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    findings = []
    for vuln in vulnerabilities:
        findings.append(
            {
                "id": vuln.get("id"),
                "method": vuln.get("method"),
                "url": vuln.get("url"),
                "message": vuln.get("msg"),
            }
        )
    return findings
