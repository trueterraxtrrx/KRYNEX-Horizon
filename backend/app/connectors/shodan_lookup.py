"""Shodan host lookup. Requires the operator's own HORIZON_SHODAN_API_KEY;
no-ops (returns None) when unset so Horizon works fully without it.
"""

from __future__ import annotations

import logging

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)

SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"


def host_lookup(ip: str) -> dict | None:
    settings = get_settings()
    if not settings.shodan_enabled:
        return None
    try:
        response = httpx.get(
            SHODAN_HOST_URL.format(ip=ip),
            params={"key": settings.shodan_api_key},
            timeout=settings.connector_timeout_seconds,
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data = response.json()
    except httpx.HTTPError as exc:
        logger.warning("Shodan lookup failed for %s: %s", ip, exc)
        return None

    return {
        "ip": ip,
        "org": data.get("org"),
        "os": data.get("os"),
        "ports": sorted(set(data.get("ports", []))),
        "hostnames": data.get("hostnames", []),
        "vulns": sorted(data.get("vulns", []) or []),
    }
