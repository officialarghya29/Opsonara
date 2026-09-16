"""Multi-tenant policy packs — brand-scoped rules stored as data.

A *policy pack* is a versioned :class:`BrandPolicy` plus metadata. Brands
may keep several versions (draft, active, archived); the firewall resolves
the active version by ``brand_id`` at evaluate time, falling back to the
request-supplied policy when no pack exists (single-tenant/dev behavior).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from opsonara.core.models import BrandPolicy


@dataclass
class PolicyPack:
    """One versioned policy configuration for a brand."""

    pack_id: str
    brand_id: str
    version: int
    policy: BrandPolicy
    state: str = "active"  # draft | active | archived
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    created_by: str = "system"


class PolicyPackStore:
    """Thread-safe in-memory policy pack registry."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._packs: dict[str, PolicyPack] = {}
        self._active: dict[str, str] = {}  # brand_id -> pack_id
        self._seq = 0

    def create(self, brand_id: str, policy: BrandPolicy, *, created_by: str = "system") -> PolicyPack:
        with self._lock:
            self._seq += 1
            pack = PolicyPack(
                pack_id=f"pack_{self._seq:04d}_{brand_id}",
                brand_id=brand_id,
                version=self._next_version_locked(brand_id),
                policy=policy,
                created_by=created_by,
            )
            self._packs[pack.pack_id] = pack
            # First pack for a brand becomes active automatically.
            if brand_id not in self._active:
                self._active[brand_id] = pack.pack_id
            return pack

    def _next_version_locked(self, brand_id: str) -> int:
        return 1 + max(
            (p.version for p in self._packs.values() if p.brand_id == brand_id),
            default=0,
        )

    def activate(self, pack_id: str) -> PolicyPack:
        with self._lock:
            pack = self._packs.get(pack_id)
            if pack is None:
                raise KeyError(f"unknown policy pack '{pack_id}'")
            pack.state = "active"
            self._active[pack.brand_id] = pack_id
            return pack

    def archive(self, pack_id: str) -> PolicyPack:
        with self._lock:
            pack = self._packs.get(pack_id)
            if pack is None:
                raise KeyError(f"unknown policy pack '{pack_id}'")
            pack.state = "archived"
            if self._active.get(pack.brand_id) == pack_id:
                del self._active[pack.brand_id]
            return pack

    def get_active(self, brand_id: str) -> PolicyPack | None:
        with self._lock:
            pack_id = self._active.get(brand_id)
            return self._packs.get(pack_id) if pack_id else None

    def list(self, brand_id: str | None = None) -> list[PolicyPack]:
        with self._lock:
            packs = [p for p in self._packs.values() if brand_id is None or p.brand_id == brand_id]
        return sorted(packs, key=lambda p: (p.brand_id, p.version))

    def resolve(
        self, brand_id: str, request_policy: BrandPolicy
    ) -> tuple[BrandPolicy, str | None]:
        """Return the effective policy for an evaluate call.

        Precedence: active pack > request-supplied policy. The returned
        source is ``"policy_pack:<pack_id>"`` or ``"request"``.
        """
        pack = self.get_active(brand_id)
        if pack is not None:
            return pack.policy, f"policy_pack:{pack.pack_id}"
        return request_policy, None

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "brands": len(self._active),
                "packs": len(self._packs),
                "active": len(self._active),
            }


__all__ = ["PolicyPack", "PolicyPackStore"]
