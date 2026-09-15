"""Application settings (12-factor, env-driven)."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPSONARA_", env_file=".env", extra="ignore")

    app_name: str = "Opsonara Agent Firewall"
    version: str = "0.1.0"
    log_level: str = "INFO"
    seed_demo_data: bool = True
    """Seed the stores with demo transactions so the dashboard is alive on first run."""
    cors_origins: str = "*"
    """Comma-separated allowed origins, or '*' for any (dev default)."""


settings = Settings()
