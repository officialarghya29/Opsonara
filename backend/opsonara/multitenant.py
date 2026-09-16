"""Multi-tenant gateway: per-brand API keys, request signing, rate limits.

Every brand (tenant) registers one or more hashed API keys and may rotate
them by prefix. Requests can optionally be HMAC-signed and replay-protected.
A sliding-window limiter enforces a per-key request budget, and brands can
pin which agent IDs are allowed to call the firewall at all.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import Header, HTTPException, Request


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


@dataclass
class BrandTenant:
    """One brand's credentials and gateway policy."""

    brand_id: str
    name: str
    key_hashes: dict[str, str] = field(default_factory=dict)
    """key_prefix -> sha256(full_key); rotation keeps the prefix stable."""
    signing_secret: str | None = None
    """When set, requests must carry an HMAC-SHA256 signature header."""
    allowed_agents: list[str] | None = None
    """None = any agent; otherwise an explicit allow-list of agent IDs."""
    rate_limit_per_minute: int | None = None
    """None = server default."""


class BrandRegistry:
    """Thread-safe in-memory tenant registry (swap for a DB backend later)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._brands: dict[str, BrandTenant] = {}

    def upsert(self, tenant: BrandTenant) -> None:
        with self._lock:
            self._brands[tenant.brand_id] = tenant

    def get(self, brand_id: str) -> BrandTenant | None:
        with self._lock:
            return self._brands.get(brand_id)

    def find_by_key(self, raw_key: str) -> BrandTenant | None:
        digest = _hash_key(raw_key)
        with self._lock:
            for tenant in self._brands.values():
                for prefix, key_hash in tenant.key_hashes.items():
                    if prefix == raw_key[:12] and hmac.compare_digest(key_hash, digest):
                        return tenant
        return None

    def all(self) -> list[BrandTenant]:
        with self._lock:
            return list(self._brands.values())


def issue_api_key() -> tuple[str, str]:
    """Generate ``(raw_key, prefix)``. The raw key is shown once; only the
    SHA-256 hash is stored. Prefix is the first 12 chars for rotation lookup."""
    import secrets

    raw = "opsk_" + secrets.token_urlsafe(24)
    return raw, raw[:12]


def register_key(tenant: BrandTenant, raw_key: str) -> BrandTenant:
    """Attach an externally supplied key (e.g. from config) to a tenant."""
    tenant.key_hashes[raw_key[:12]] = _hash_key(raw_key)
    return tenant


class RateLimiter:
    """Sliding-window per-key limiter, O(1) amortized, prune-on-request."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str, limit: int, window: float = 60.0) -> bool:
        if limit <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if now - t < window]
            if len(hits) >= limit:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


def verify_signature(
    secret: str,
    body: bytes,
    timestamp: str,
    signature: str,
    *,
    tolerance_seconds: int = 300,
) -> bool:
    """HMAC-SHA256 over ``f"{timestamp}.{body}"`` with replay protection."""
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs(time.time() - ts) > tolerance_seconds:
        return False
    expected = hmac.new(
        secret.encode(), f"{ts}.".encode() + body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

_limiter = RateLimiter()


def build_auth_dependency(
    registry: BrandRegistry, *, auth_mode: str, signing_required: bool, default_limit: int
) -> Any:
    """Create the ``Depends`` callable used by protected endpoints."""

    async def require_brand(
        request: Request,
        x_api_key: str | None = Header(default=None),
        x_opsonara_timestamp: str | None = Header(default=None),
        x_opsonara_signature: str | None = Header(default=None),
    ) -> BrandTenant:
        if auth_mode == "off":
            return BrandTenant(brand_id="public", name="public")
        if not x_api_key:
            raise HTTPException(status_code=401, detail="missing X-Api-Key header")
        tenant = registry.find_by_key(x_api_key)
        if tenant is None:
            raise HTTPException(status_code=401, detail="unknown or revoked API key")
        body = await request.body()
        if tenant.signing_secret is not None:
            if not x_opsonara_timestamp or not x_opsonara_signature:
                raise HTTPException(
                    status_code=401,
                    detail="missing signature headers for signed tenant",
                )
            if not verify_signature(
                tenant.signing_secret, body, x_opsonara_timestamp, x_opsonara_signature
            ):
                raise HTTPException(status_code=401, detail="invalid or stale signature")
        elif signing_required:
            raise HTTPException(
                status_code=401, detail="tenant has no signing secret but signing is required"
            )
        limit = tenant.rate_limit_per_minute or default_limit
        if not _limiter.allow(f"{tenant.brand_id}:{x_api_key[:12]}", limit):
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        return tenant

    return require_brand


__all__ = [
    "BrandRegistry",
    "BrandTenant",
    "RateLimiter",
    "build_auth_dependency",
    "issue_api_key",
    "register_key",
    "verify_signature",
]
