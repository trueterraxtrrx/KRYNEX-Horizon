from functools import lru_cache
from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="HORIZON_")

    app_name: str = "KRYNEX Horizon"
    app_version: str = "1.0.0"
    environment: str = "development"
    debug: bool = False
    demo_mode: bool = True

    database_url: str = "sqlite:///./horizon.db"

    require_api_key: bool = True
    service_api_key_sha256: str = ""

    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    # Connector configuration. All connectors are optional; Horizon runs
    # useful scans with none of these set (crt.sh + DNS + Wappalyzer need no
    # credentials at all).
    shodan_api_key: str = ""
    nmap_binary_path: str = "nmap"
    nmap_enabled: bool = True
    crtsh_base_url: str = "https://crt.sh"
    connector_timeout_seconds: float = 15.0

    log_level: str = "INFO"

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def shodan_enabled(self) -> bool:
        return bool(self.shodan_api_key)

    @model_validator(mode="after")
    def validate_production_settings(self):
        if self.demo_mode:
            # Public demo mode is an explicit, intentional no-auth path.
            self.require_api_key = False
        if self.is_production:
            if self.debug:
                raise ValueError("Debug mode is not allowed in production")
            if self.demo_mode:
                raise ValueError("Demo mode is not allowed in production")
            if "*" in self.cors_origin_list:
                raise ValueError("Wildcard CORS is not allowed in production")
            if self.require_api_key and len(self.service_api_key_sha256) != 64:
                raise ValueError("SERVICE_API_KEY_SHA256 must be a SHA-256 hex digest when API key auth is required")
        return self


def hash_api_key(raw_key: str) -> str:
    import hashlib

    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


@lru_cache
def get_settings() -> Settings:
    return Settings()
