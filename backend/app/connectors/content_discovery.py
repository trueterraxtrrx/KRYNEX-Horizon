"""Lightweight content/path discovery — our own small, original wordlist
probed concurrently over HTTP(S), the same idea as ffuf/gobuster/dirb
without depending on any of those binaries being installed.

ACTIVE connector: this sends dozens of requests to the target looking for
paths that aren't linked from anywhere, which is meaningfully more
intrusive than a single passive GET. Gated by Asset.authorized_for_active_testing.
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)

# Small, original, well-known-by-heart common-path list (not a copy of
# SecLists or any third-party wordlist file) - deliberately short so a scan
# stays fast and polite.
COMMON_PATHS = (
    ".git/config",
    ".git/HEAD",
    ".env",
    ".env.example",
    ".htaccess",
    "admin",
    "admin/login",
    "api",
    "api/docs",
    "backup",
    "backup.zip",
    "config.php",
    "config.json",
    "debug",
    "dashboard",
    "login",
    "phpinfo.php",
    "robots.txt",
    "sitemap.xml",
    "swagger.json",
    "swagger-ui",
    "wp-admin",
    "wp-login.php",
    "server-status",
    ".well-known/security.txt",
)

MAX_CONCURRENCY = 8


async def _probe(client: httpx.AsyncClient, base_url: str, path: str) -> dict | None:
    url = f"{base_url.rstrip('/')}/{path}"
    try:
        response = await client.get(url, follow_redirects=False)
    except httpx.HTTPError:
        return None
    if response.status_code in (200, 201, 301, 302, 401, 403):
        return {"path": path, "url": url, "status_code": response.status_code, "content_length": len(response.content)}
    return None


async def _discover_async(base_url: str) -> list[dict]:
    settings = get_settings()
    limits = httpx.Limits(max_connections=MAX_CONCURRENCY)
    results: list[dict] = []
    async with httpx.AsyncClient(
        timeout=settings.connector_timeout_seconds,
        limits=limits,
        headers={"User-Agent": "KRYNEX-Horizon/1.0 (authorized recon)"},
    ) as client:
        semaphore = asyncio.Semaphore(MAX_CONCURRENCY)

        async def bounded_probe(path: str):
            async with semaphore:
                return await _probe(client, base_url, path)

        outcomes = await asyncio.gather(*(bounded_probe(p) for p in COMMON_PATHS))
    for outcome in outcomes:
        if outcome:
            results.append(outcome)
    return results


def discover(base_url: str) -> list[dict]:
    try:
        return asyncio.run(_discover_async(base_url))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Content discovery failed for %s: %s", base_url, exc)
        return []
