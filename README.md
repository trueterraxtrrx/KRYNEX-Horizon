# KRYNEX Horizon V1.0

Defensive external attack surface management (ASM): track your own root domains, discover their subdomains, fingerprint the technology running on them, and pull in results from tools your team already runs.

## Quick Start

```bash
cd backend
python -m venv .venv
.venv/Scripts/activate  # or source .venv/bin/activate on Linux/macOS
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

Open `http://localhost:8000` for the dashboard, or `http://localhost:8000/docs` for the API (both disabled outside development by `HORIZON_DEBUG`/`environment`).

Demo mode (`HORIZON_DEMO_MODE=true`, the default) disables the API-key gate so you can try Horizon locally without configuring a service key first.

## Connectors

Horizon's recon runs through pluggable connectors. None require credentials except Shodan; the rest work out of the box:

| Connector | Needs a key? | What it does |
|---|---|---|
| `crtsh` | No | Subdomain enumeration via [crt.sh](https://crt.sh) certificate transparency logs. Free public service — occasionally returns `502`s under load; Horizon fails that connector soft and keeps the rest of the scan going. |
| `dns` | No | MX/TXT/NS records for the root domain, A-record resolution for discovered subdomains. |
| `wappalyzer` | No | Lightweight, original technology fingerprinting (HTTP headers + HTML patterns) — same idea Wappalyzer popularized, own small signature set, not their dataset. |
| `shodan` | Yes (`HORIZON_SHODAN_API_KEY`) | Host/port/vuln data from [Shodan](https://www.shodan.io/) for resolved IPs. No-ops without a key. |
| `nmap` | No, but needs the `nmap` binary installed | Live top-1000-port TCP connect scan of the root domain. |

**Burp Suite** doesn't get a live connector — Burp's REST API is a Professional-only feature. Instead, export a scan as XML (`Report > XML`) from any Burp edition and upload it via `POST /assets/{id}/imports/burp`; the same goes for **Nmap** if you'd rather run it yourself and import the `-oX` output than let Horizon shell out to a local binary.

## API

- `POST /assets` — track a new root domain.
- `GET /assets`, `GET /assets/{id}` — list/inspect tracked assets.
- `POST /assets/{id}/scans` — kick off a connector run (backgrounded; poll `GET /scans/{id}`).
- `GET /assets/{id}/subdomains`, `GET /assets/{id}/findings` — recon results.
- `POST /assets/{id}/imports/nmap`, `POST /assets/{id}/imports/burp` — import an existing scan report instead of running one live.
- `GET /stats` — portfolio-wide counts for the dashboard.

## Security Scope

Defensive recon only: Horizon fingerprints and enumerates, it doesn't exploit, brute-force, or actively attack anything beyond what a normal TCP connect scan and a handful of unauthenticated HTTP GETs do. Production deployments should set `HORIZON_REQUIRE_API_KEY=true` (the default outside demo mode) and a real `HORIZON_SERVICE_API_KEY_SHA256`.

## Roadmap

### Already implemented

- FastAPI backend for asset tracking, connector-based scanning and Nmap/Burp XML import.
- crt.sh subdomain enumeration, DNS record lookups, and an original tech-fingerprinting engine — all credential-free.
- Optional Shodan enrichment and local Nmap live-scan integration.
- Nmap and Burp Suite scan-report import for teams who run those tools themselves.
- Production guards for secrets, CORS, debug mode and demo isolation, matching the rest of the KRYNEX Labs portfolio.
- Vanilla JS/CSS dashboard in the shared KRYNEX design system.

### Will be implemented

- KRYNEX Nexus product-gateway integration (organization-scoped usage/audit emitters).
- Scheduled recurring scans instead of manual triggering.
- Historical diffing (new subdomain appeared, port opened/closed since last scan) and alerting.
- Richer technology signature set and a pluggable interface for adding custom connectors.

## KRYNEX Ecosystem

Part of the [KRYNEX Labs](https://github.com/trueterraxtrrx) portfolio: [SentinelX](https://github.com/trueterraxtrrx/SentinelX-EDR-XDR) (EDR/XDR), [ThreatVault](https://github.com/trueterraxtrrx/ThreatVault) (malware analysis), [VulnScope](https://github.com/trueterraxtrrx/VulnScope) (exposure management), [LogForge](https://github.com/trueterraxtrrx/LogForge) (log management), [DeceptionGrid](https://github.com/trueterraxtrrx/DeceptionGrid) (deception security), [Nexora CRM](https://github.com/trueterraxtrrx/Nexora-CRM) (business CRM).

## License

MIT
