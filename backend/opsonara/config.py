"""Application settings (12-factor, env-driven)."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPSONARA_", env_file=".env", extra="ignore")

    app_name: str = "Opsonara Agent Firewall"
    version: str = "0.2.0"
    log_level: str = "INFO"
    seed_demo_data: bool = True
    """Seed the stores with demo transactions so the dashboard is alive on first run."""
    cors_origins: str = "*"
    """Comma-separated allowed origins, or '*' for any (dev default)."""
    store_backend: str = "memory"
    """'memory' (default), 'sqlite' (persists across restarts) or 'postgres' (multi-instance)."""
    db_path: str = "opsonara.db"
    """SQLite database file when store_backend is 'sqlite'."""
    pg_dsn: str = ""
    """Postgres DSN when store_backend is 'postgres', e.g. postgresql://user:pass@host/db."""

    # -- multi-tenancy & gateway ------------------------------------------------
    auth_mode: str = "off"
    """'off' (dev/demo default) or 'api_key' to require per-brand keys + optional signing."""
    auth_signing_required: bool = False
    """When True, requests must carry a valid HMAC signature header (replay-protected)."""
    rate_limit_per_minute: int = 120
    """Per-key request budget for /v1/evaluate and connector endpoints (0 = unlimited)."""
    admin_token: str = ""
    """Operator bootstrap token (OPSONARA_ADMIN_TOKEN). Required in production to
    call operator endpoints (create brands, issue credentials, recalibrate)."""
    webhook_secrets: str = ""
    """Inbound webhook secrets, comma-separated name=secret pairs
    (e.g. 'shopify=whsec_xxx,hooks=whsec_yyy'). Empty disables webhook ingest."""

    # -- agent identity ----------------------------------------------------------
    credential_verification: str = "optional"
    """'off' | 'optional' (verify when presented) | 'strict' (valid JWT credential required)."""

    # -- learning loop -------------------------------------------------------------
    shadow_min_samples: int = 50
    """Minimum shadow samples before a candidate weight set may be promoted."""
    shadow_min_win_rate: float = 0.55
    """Shadow candidate must agree with human outcomes more often than this."""

    # -- billing ---------------------------------------------------------------------
    stripe_api_key: str = ""
    """When set, usage metering reports to Stripe meter events; empty = local meter only."""
    billing_dry_run: bool = True
    """When True (default) Stripe calls are planned but never sent."""


settings = Settings()
