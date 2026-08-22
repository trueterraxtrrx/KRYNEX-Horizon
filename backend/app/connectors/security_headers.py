"""Response security-header audit. One unauthenticated GET, same as
`techfingerprint` — passive, no different from a normal page load.
"""

from __future__ import annotations

import logging

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)

EXPECTED_HEADERS = {
    "strict-transport-security": "HSTS missing - connections can be silently downgraded to plain HTTP",
    "content-security-policy": "CSP missing - no defense-in-depth against injected script content",
    "x-content-type-options": "X-Content-Type-Options missing - browsers may MIME-sniff responses",
    "x-frame-options": "X-Frame-Options missing - page can be framed (clickjacking risk) unless CSP frame-ancestors is set",
    "referrer-policy": "Referrer-Policy missing - full URLs may leak to third parties via the Referer header",
}


def audit(url: str) -> dict | None:
    settings = get_settings()
    try:
        response = httpx.get(
            url,
            timeout=settings.connector_timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": "KRYNEX-Horizon/1.0 (defensive recon)"},
        )
    except httpx.HTTPError as exc:
        logger.info("Security header audit failed for %s: %s", url, exc)
        return None

    headers = {k.lower(): v for k, v in response.headers.items()}
    missing = [name for name in EXPECTED_HEADERS if name not in headers]
    present = {name: headers[name] for name in EXPECTED_HEADERS if name in headers}

    return {
        "url": url,
        "status_code": response.status_code,
        "present": present,
        "missing": [{"header": name, "reason": EXPECTED_HEADERS[name]} for name in missing],
        "server": headers.get("server"),
    }
