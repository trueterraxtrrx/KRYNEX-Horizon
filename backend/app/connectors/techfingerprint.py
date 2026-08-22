"""Lightweight technology fingerprinting from HTTP responses.

This is an original, compact signature set inspired by the general
public-knowledge fingerprinting technique popularized by Wappalyzer
(matching response headers, HTML meta tags and inline script/markup
patterns against known technologies) — it is NOT a copy of Wappalyzer's
proprietary/GPL technology dataset, just the same well-known idea
implemented independently with a small, original signature list. Swap in
a licensed, larger dataset here if you have one; the matching engine below
doesn't care where the signatures come from.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Signature:
    name: str
    category: str
    header_patterns: dict[str, str]  # header name (lowercase) -> regex
    body_patterns: tuple[str, ...] = ()  # regexes searched against response body


SIGNATURES: tuple[Signature, ...] = (
    Signature("Nginx", "web-server", {"server": r"nginx"}),
    Signature("Apache HTTP Server", "web-server", {"server": r"apache"}),
    Signature("Microsoft IIS", "web-server", {"server": r"microsoft-iis"}),
    Signature("Cloudflare", "cdn", {"server": r"cloudflare", "cf-ray": r".+"}),
    Signature("Express.js", "framework", {"x-powered-by": r"express"}),
    Signature("ASP.NET", "framework", {"x-powered-by": r"asp\.net", "x-aspnet-version": r".+"}),
    Signature("PHP", "language", {"x-powered-by": r"php"}),
    Signature("WordPress", "cms", {}, (r'name="generator" content="WordPress', r"/wp-content/", r"/wp-includes/")),
    Signature("Drupal", "cms", {"x-generator": r"drupal"}, (r'name="generator" content="Drupal',)),
    Signature("Joomla", "cms", {}, (r'name="generator" content="Joomla',)),
    Signature("Next.js", "framework", {"x-powered-by": r"next\.js"}, (r"__NEXT_DATA__",)),
    Signature("React", "js-framework", {}, (r"data-reactroot", r"react-dom", r"_react")),
    Signature("Vue.js", "js-framework", {}, (r"data-v-[0-9a-f]{6,8}", r"__vue__")),
    Signature("jQuery", "js-library", {}, (r"jquery(?:\.min)?\.js",)),
    Signature("Bootstrap", "css-framework", {}, (r"bootstrap(?:\.min)?\.css",)),
    Signature("Google Analytics", "analytics", {}, (r"google-analytics\.com/analytics\.js", r"gtag\(")),
    Signature("Google Tag Manager", "tag-manager", {}, (r"googletagmanager\.com/gtm\.js",)),
    Signature("Varnish", "cache", {"x-varnish": r".+", "via": r"varnish"}),
    Signature("HSTS Enabled", "security", {"strict-transport-security": r".+"}),
    Signature("Content Security Policy", "security", {"content-security-policy": r".+"}),
)


def fingerprint(url: str) -> list[dict]:
    settings = get_settings()
    matches: list[dict] = []
    try:
        response = httpx.get(
            url,
            timeout=settings.connector_timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": "KRYNEX-Horizon/1.0 (defensive recon)"},
        )
    except httpx.HTTPError as exc:
        logger.info("Fingerprint request failed for %s: %s", url, exc)
        return matches

    headers = {k.lower(): v for k, v in response.headers.items()}
    body = response.text[:200_000] if response.text else ""

    for signature in SIGNATURES:
        matched_via: list[str] = []
        for header_name, pattern in signature.header_patterns.items():
            value = headers.get(header_name)
            if value and re.search(pattern, value, re.IGNORECASE):
                matched_via.append(f"header:{header_name}")
        for pattern in signature.body_patterns:
            if body and re.search(pattern, body, re.IGNORECASE):
                matched_via.append("body")
                break
        if matched_via:
            matches.append(
                {
                    "technology": signature.name,
                    "category": signature.category,
                    "matched_via": matched_via,
                }
            )

    return matches
