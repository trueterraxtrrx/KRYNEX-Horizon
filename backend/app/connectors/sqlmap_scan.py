"""sqlmap integration for automated SQL-injection detection. Shells out to
a locally-installed `sqlmap` — Horizon never downloads or installs it. If
it isn't on PATH, `sqlmap_available()` returns False and the connector is
skipped.

Deliberately conservative invocation: `--level=1 --risk=1` are sqlmap's
lowest settings (fewer test payloads, none of the higher-risk ones that
can modify data), `--batch` for non-interactive mode, `--crawl=1 --forms`
to test the homepage's own forms rather than requiring the caller to
already know an injectable parameter. This is SQL-injection *detection*,
not exploitation — no `--os-shell`, `--dump`, `--sql-shell` or any other
post-exploitation flag is used.

ACTIVE connector: this actively sends crafted payloads to the target.
Gated by Asset.authorized_for_active_testing.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_INJECTION_HEADER_RE = re.compile(r"Parameter:\s*(?P<param>.+)")
_TYPE_RE = re.compile(r"Type:\s*(?P<type>.+)")
_TITLE_RE = re.compile(r"Title:\s*(?P<title>.+)")


def sqlmap_available() -> bool:
    return shutil.which("sqlmap") is not None


def run_scan(target_url: str) -> list[dict]:
    if not sqlmap_available():
        return []
    settings = get_settings()
    try:
        completed = subprocess.run(
            [
                "sqlmap",
                "-u", target_url,
                "--batch",
                "--crawl=1",
                "--forms",
                "--level=1",
                "--risk=1",
                "--timeout=10",
                "--retries=1",
            ],
            capture_output=True,
            text=True,
            timeout=max(180.0, settings.connector_timeout_seconds * 12),
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("sqlmap scan failed for %s: %s", target_url, exc)
        return []

    return _parse_sqlmap_output(completed.stdout)


def _parse_sqlmap_output(stdout: str) -> list[dict]:
    """sqlmap prints human-readable text; this pulls out the structured
    "Parameter / Type / Title" blocks it emits per confirmed injection
    point rather than depending on a machine-readable output format."""
    findings: list[dict] = []
    current: dict | None = None

    for line in stdout.splitlines():
        param_match = _INJECTION_HEADER_RE.search(line)
        if param_match and "is vulnerable" not in line:
            if current:
                findings.append(current)
            current = {"parameter": param_match.group("param").strip(), "type": None, "title": None}
            continue
        if current is not None:
            type_match = _TYPE_RE.search(line)
            if type_match:
                current["type"] = type_match.group("type").strip()
                continue
            title_match = _TITLE_RE.search(line)
            if title_match:
                current["title"] = title_match.group("title").strip()

    if current:
        findings.append(current)
    return findings
