import hmac
import logging
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.connectors import burp_import, nikto_scan, nmap_scan, sqlmap_scan
from app.core.config import PROJECT_ROOT, get_settings, hash_api_key
from app.core.database import get_db, init_db
from app.models.asset import Asset, Subdomain
from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas import (
    AssetCreate,
    AssetResponse,
    BurpImportResult,
    FindingResponse,
    NmapImportResult,
    PlatformStats,
    ScanCreate,
    ScanResponse,
    SubdomainResponse,
)
from app.services import start_scan

settings = get_settings()
logging.basicConfig(level=settings.log_level)
logger = logging.getLogger("horizon")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("Starting %s v%s (demo_mode=%s)", settings.app_name, settings.app_version, settings.demo_mode)
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Defensive attack-surface management: subdomain discovery, DNS/tech fingerprinting, optional Shodan/Nmap enrichment and Nmap/Burp import.",
        lifespan=lifespan,
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None if settings.is_production else "/redoc",
        openapi_url=None if settings.is_production else "/openapi.json",
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'",
        )
        if settings.is_production:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
        if not settings.require_api_key:
            return
        if not x_api_key or not hmac.compare_digest(hash_api_key(x_api_key), settings.service_api_key_sha256):
            raise HTTPException(status_code=401, detail="Invalid API key")

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "service": settings.app_name,
            "version": settings.app_version,
            "demo_mode": settings.demo_mode,
            "connectors": _connector_availability(),
        }

    @app.get("/stats", response_model=PlatformStats)
    def stats(_: None = Depends(require_api_key), db: Session = Depends(get_db)):
        total_assets = db.scalar(select(func.count()).select_from(Asset)) or 0
        total_subdomains = db.scalar(select(func.count()).select_from(Subdomain)) or 0
        total_findings = db.scalar(select(func.count()).select_from(Finding)) or 0
        rows = db.execute(select(Finding.severity, func.count()).group_by(Finding.severity)).all()
        return PlatformStats(
            total_assets=total_assets,
            total_subdomains=total_subdomains,
            total_findings=total_findings,
            findings_by_severity={severity: count for severity, count in rows},
            connectors_available=_connector_availability(),
        )

    @app.post("/assets", response_model=AssetResponse, status_code=201)
    def create_asset(payload: AssetCreate, _: None = Depends(require_api_key), db: Session = Depends(get_db)):
        root_domain = payload.root_domain.strip().lower()
        existing = db.scalar(select(Asset).where(Asset.root_domain == root_domain))
        if existing:
            raise HTTPException(status_code=409, detail="Asset already tracked")
        asset = Asset(
            root_domain=root_domain,
            label=payload.label,
            authorized_for_active_testing=payload.authorized_for_active_testing,
        )
        db.add(asset)
        db.commit()
        db.refresh(asset)
        return _asset_response(asset)

    @app.get("/assets", response_model=list[AssetResponse])
    def list_assets(_: None = Depends(require_api_key), db: Session = Depends(get_db)):
        assets = db.scalars(select(Asset).order_by(Asset.created_at.desc())).all()
        return [_asset_response(asset) for asset in assets]

    @app.get("/assets/{asset_id}", response_model=AssetResponse)
    def get_asset(asset_id: str, _: None = Depends(require_api_key), db: Session = Depends(get_db)):
        asset = db.get(Asset, asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        return _asset_response(asset)

    @app.get("/assets/{asset_id}/subdomains", response_model=list[SubdomainResponse])
    def list_subdomains(asset_id: str, _: None = Depends(require_api_key), db: Session = Depends(get_db)):
        asset = db.get(Asset, asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        subdomains = db.scalars(
            select(Subdomain).where(Subdomain.asset_id == asset_id).order_by(Subdomain.hostname)
        ).all()
        return subdomains

    @app.get("/assets/{asset_id}/findings", response_model=list[FindingResponse])
    def list_findings(
        asset_id: str,
        severity: str | None = None,
        _: None = Depends(require_api_key),
        db: Session = Depends(get_db),
    ):
        asset = db.get(Asset, asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        query = select(Finding).where(Finding.asset_id == asset_id)
        if severity:
            query = query.where(Finding.severity == severity)
        findings = db.scalars(query.order_by(Finding.created_at.desc()).limit(500)).all()
        return findings

    @app.post("/assets/{asset_id}/scans", response_model=ScanResponse, status_code=202)
    def create_scan(
        asset_id: str,
        payload: ScanCreate,
        background_tasks: BackgroundTasks,
        _: None = Depends(require_api_key),
        db: Session = Depends(get_db),
    ):
        asset = db.get(Asset, asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        scan = Scan(asset_id=asset.id, status="pending", connectors_requested=payload.connectors)
        db.add(scan)
        db.commit()
        db.refresh(scan)
        background_tasks.add_task(start_scan, scan.id)
        return scan

    @app.get("/assets/{asset_id}/scans", response_model=list[ScanResponse])
    def list_scans(asset_id: str, _: None = Depends(require_api_key), db: Session = Depends(get_db)):
        scans = db.scalars(
            select(Scan).where(Scan.asset_id == asset_id).order_by(Scan.started_at.desc()).limit(50)
        ).all()
        return scans

    @app.get("/scans/{scan_id}", response_model=ScanResponse)
    def get_scan(scan_id: str, _: None = Depends(require_api_key), db: Session = Depends(get_db)):
        scan = db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan

    @app.post("/assets/{asset_id}/imports/nmap", response_model=NmapImportResult)
    async def import_nmap(
        asset_id: str,
        file: UploadFile = File(...),
        _: None = Depends(require_api_key),
        db: Session = Depends(get_db),
    ):
        asset = db.get(Asset, asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        xml_text = (await file.read()).decode("utf-8", errors="ignore")
        port_findings = nmap_scan.parse_nmap_xml(xml_text)
        for pf in port_findings:
            db.add(
                Finding(
                    asset_id=asset.id,
                    subdomain=pf.get("host"),
                    finding_type="open_port",
                    source="nmap_import",
                    title=f"Port {pf['port']}/{pf['protocol']} open ({pf['service']})",
                    severity="medium" if pf["port"] in {22, 3389, 3306, 5432, 6379, 27017} else "low",
                    detail=pf,
                )
            )
        db.commit()
        return NmapImportResult(findings_created=len(port_findings))

    @app.post("/assets/{asset_id}/imports/burp", response_model=BurpImportResult)
    async def import_burp(
        asset_id: str,
        file: UploadFile = File(...),
        _: None = Depends(require_api_key),
        db: Session = Depends(get_db),
    ):
        asset = db.get(Asset, asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        xml_text = (await file.read()).decode("utf-8", errors="ignore")
        issues = burp_import.parse_burp_xml(xml_text)
        for issue in issues:
            db.add(
                Finding(
                    asset_id=asset.id,
                    subdomain=issue.get("host"),
                    finding_type="web_vulnerability",
                    source="burp_import",
                    title=issue["title"],
                    severity=issue["severity"],
                    detail=issue,
                )
            )
        db.commit()
        return BurpImportResult(findings_created=len(issues))

    frontend_dir = PROJECT_ROOT / "frontend"
    if frontend_dir.exists():
        app.mount("/assets-ui", StaticFiles(directory=frontend_dir / "assets"), name="assets-ui")

        @app.get("/")
        async def dashboard():
            return FileResponse(frontend_dir / "index.html")

    return app


def _connector_availability() -> dict[str, bool]:
    return {
        "crtsh": True,
        "dns": True,
        "wappalyzer": True,
        "tls_audit": True,
        "whois": True,
        "security_headers": True,
        "shodan": settings.shodan_enabled,
        "nmap": nmap_scan.nmap_available(),
        "content_discovery": True,
        "nikto": nikto_scan.nikto_available(),
        "sqlmap": sqlmap_scan.sqlmap_available(),
    }


def _asset_response(asset: Asset) -> AssetResponse:
    return AssetResponse(
        id=asset.id,
        root_domain=asset.root_domain,
        label=asset.label,
        authorized_for_active_testing=asset.authorized_for_active_testing,
        created_at=asset.created_at,
        subdomain_count=len(asset.subdomains),
        finding_count=len(asset.findings),
    )


app = create_app()
