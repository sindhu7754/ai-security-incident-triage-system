"""
AstraSOC - Application Configuration
Centralized settings management using Pydantic v2 BaseSettings.
"""

from functools import lru_cache
from typing import List, Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── Application ──────────────────────────────────────────
    app_name: str = "AstraSOC"
    app_env: Literal["development", "staging", "production"] = "development"
    app_version: str = "1.0.0"
    debug: bool = False
    secret_key: str = "change-in-production"

    # ── API ──────────────────────────────────────────────────
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_workers: int = 4

    # ── Database ─────────────────────────────────────────────
    database_url: str = "sqlite:///./astrasoc.db"

    # ── JWT ──────────────────────────────────────────────────
    jwt_secret_key: str = "change-jwt-secret"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60

    # ── LLM ──────────────────────────────────────────────────
    openai_api_key: str = ""
    llm_provider: Literal["openai", "ollama"] = "openai"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"

    # ── Detection Thresholds ─────────────────────────────────
    brute_force_threshold: int = 5
    port_scan_threshold: int = 20
    dns_entropy_threshold: float = 3.5
    anomaly_contamination: float = 0.05

    # ── Rate Limiting ────────────────────────────────────────
    rate_limit_requests: int = 100
    rate_limit_window: int = 60

    # ── Logging ──────────────────────────────────────────────
    log_level: str = "INFO"
    log_format: Literal["json", "console"] = "json"

    # ── CORS ─────────────────────────────────────────────────
    cors_origins: List[str] = ["http://localhost:8501", "http://localhost:3000"]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors(cls, v):
        if isinstance(v, str):
            import json
            return json.loads(v)
        return v

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings singleton."""
    return Settings()


settings = get_settings()
