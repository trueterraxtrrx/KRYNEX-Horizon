"""Subdomain enumeration via crt.sh (certificate transparency logs).

No API key required. crt.sh indexes CT log entries and lets you search for
all certificates ever issued for a domain (and its subdomains); the
subject/SAN fields of those certificates are a reliable, free source of
subdomain names that doesn't require actively touching the target.
"""

from __future__ import annotations

import logging

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)


def enumerate_subdomains(root_domain: str) -> set[str]:
    settings = get_settings()
    url = f"{settings.crtsh_base_url}/"
    hostnames: set[str] = set()
    try:
        response = httpx.get(
            url,
            params={"q": f"%.{root_domain}", "output": "json"},
            timeout=settings.connector_timeout_seconds,
            headers={"User-Agent": "KRYNEX-Horizon/1.0 (defensive recon)"},
        )
        response.raise_for_status()
        entries = response.json()
    except httpx.HTTPError as exc:
        logger.warning("crt.sh lookup failed for %s: %s", root_domain, exc)
        return hostnames
    except ValueError:
        # crt.sh occasionally returns truncated/invalid JSON under load.
        logger.warning("crt.sh returned non-JSON response for %s", root_domain)
        return hostnames

    for entry in entries:
        name_value = entry.get("name_value", "")
        for candidate in name_value.split("\n"):
            candidate = candidate.strip().lower().lstrip("*.")
            if not candidate or candidate == root_domain.lower():
                continue
            if candidate.endswith(f".{root_domain.lower()}") or candidate == root_domain.lower():
                hostnames.add(candidate)

    hostnames.add(root_domain.lower())
    return hostnames
