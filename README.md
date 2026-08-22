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

Horizon's recon runs through pluggable connectors, split into two tiers:

- **Passive** — a single standard HTTP request, a DNS/WHOIS lookup, or a public-dataset query. The same footprint as visiting the site in a browser. Never requires authorization.
- **Active** — port scanning, path brute-forcing, vulnerability probing, or injection testing. Requires the asset to have `authorized_for_active_testing=true` (set via the "I have permission to actively test this target" checkbox when adding a domain). Horizon will not run these against a target you haven't confirmed you're allowed to test — requests for them are silently dropped and reported back in the scan's `skipped_unauthorized` summary.

| Connector | Tier | Needs a key/binary? | What it does |
|---|---|---|---|
| `crtsh` | Passive | No | Subdomain enumeration via [crt.sh](https://crt.sh) certificate transparency logs. Free public service — occasionally returns `502`s under load; Horizon fails that connector soft and keeps the rest of the scan going. |
| `dns` | Passive | No | MX/TXT/NS records for the root domain, A-record resolution for discovered subdomains. |
| `wappalyzer` | Passive | No | Lightweight, original technology fingerprinting (HTTP headers + HTML patterns) — same idea Wappalyzer popularized, own small signature set, not their dataset. |
| `tls_audit` | Passive | No | Certificate/protocol/cipher inspection over a standard TLS handshake — expiry, weak protocol versions, cert chain issues. |
| `whois` | Passive | No | Registrar, creation/expiry dates and nameservers via [`python-whois`](https://pypi.org/project/python-whois/). |
| `security_headers` | Passive | No | Checks for HSTS, CSP, X-Content-Type-Options, X-Frame-Options and Referrer-Policy on a single GET. |
| `shodan` | Passive | Yes (`HORIZON_SHODAN_API_KEY`) | Host/port/vuln data from [Shodan](https://www.shodan.io/) for resolved IPs. No-ops without a key. |
| `nmap` | **Active** | No, but needs the `nmap` binary installed | Live top-1000-port TCP connect scan of the root domain. |
| `content_discovery` | **Active** | No | Async path brute-forcer (own small wordlist) checking for exposed `.git`, `.env`, admin panels and similar. |
| `nikto` | **Active** | No, but needs the `nikto` binary installed | Shells out to a locally-installed [Nikto](https://cirt.net/Nikto2) for known web-server vulnerability probing. Never auto-installed. |
| `sqlmap` | **Active** | No, but needs the `sqlmap` binary installed | Shells out to a locally-installed [sqlmap](https://sqlmap.org/) with conservative flags (`--level=1 --risk=1 --batch`, no exploitation/shell flags) to flag likely SQL injection points. Never auto-installed. |

**Burp Suite** doesn't get a live connector — Burp's REST API is a Professional-only feature. Instead, export a scan as XML (`Report > XML`) from any Burp edition and upload it via `POST /assets/{id}/imports/burp`; the same goes for **Nmap** if you'd rather run it yourself and import the `-oX` output than let Horizon shell out to a local binary.

## API

- `POST /assets` — track a new root domain.
- `GET /assets`, `GET /assets/{id}` — list/inspect tracked assets.
- `POST /assets/{id}/scans` — kick off a connector run (backgrounded; poll `GET /scans/{id}`).
- `GET /assets/{id}/subdomains`, `GET /assets/{id}/findings` — recon results.
- `POST /assets/{id}/imports/nmap`, `POST /assets/{id}/imports/burp` — import an existing scan report instead of running one live.
- `GET /stats` — portfolio-wide counts for the dashboard.

## Security Scope

Horizon covers the full range from passive OSINT to active vulnerability probing, gated by an explicit authorization flag per asset. Passive connectors (certificate transparency, DNS, WHOIS, TLS inspection, header audit, tech fingerprinting) always run — they only ever read publicly-available information. Active connectors (Nmap, content discovery, Nikto, sqlmap) require the asset owner to confirm testing permission first; unauthorized requests for them are dropped server-side, not just hidden in the UI. Horizon never downloads or installs the external tools (`nmap`, `nikto`, `sqlmap`) itself — it only shells out to binaries you've already installed locally, and no-ops cleanly if they're absent.

Production deployments should set `HORIZON_REQUIRE_API_KEY=true` (the default outside demo mode) and a real `HORIZON_SERVICE_API_KEY_SHA256`.

## Roadmap

### Already implemented

- FastAPI backend for asset tracking, connector-based scanning and Nmap/Burp XML import.
- 11 connectors across passive OSINT (crt.sh, DNS, WHOIS, TLS audit, security headers, tech fingerprinting, Shodan) and active testing (Nmap, content discovery, Nikto, sqlmap).
- Per-asset authorization gate: active/intrusive connectors are blocked server-side unless the asset owner has confirmed testing permission.
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
