"""WHOIS domain registration lookup. Uses the `python-whois` package, which
speaks the WHOIS protocol directly (socket to the relevant registry server)
— no API key, no external binary. Public registration data only.
"""

from __future__ import annotations

import datetime
import logging

import whois as whois_lib

logger = logging.getLogger(__name__)


def lookup(root_domain: str) -> dict | None:
    try:
        record = whois_lib.whois(root_domain)
    except Exception as exc:  # noqa: BLE001 - third-party lib raises assorted/undocumented errors
        logger.info("WHOIS lookup failed for %s: %s", root_domain, exc)
        return None

    if not record or not record.get("domain_name"):
        return None

    return {
        "registrar": _first(record.get("registrar")),
        "creation_date": _iso(_first(record.get("creation_date"))),
        "expiration_date": _iso(_first(record.get("expiration_date"))),
        "updated_date": _iso(_first(record.get("updated_date"))),
        "name_servers": _list(record.get("name_servers")),
        "status": _list(record.get("status")),
        "org": record.get("org"),
        "country": record.get("country"),
    }


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return sorted({str(v) for v in value})
    return [str(value)]


def _iso(value) -> str | None:
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    return str(value) if value else None
