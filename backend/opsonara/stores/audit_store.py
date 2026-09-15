"""Audit Log — "Why did the AI do this?"

In-memory, thread-safe, hash-chained audit store. Each record links to the
hash of its predecessor, so any retroactive tampering is detectable via
:meth:`AuditStore.verify_chain`.

Swap this class for a Postgres-backed implementation behind the same
interface in production; the firewall pipeline and API do not change.
"""

from __future__ import annotations

import hashlib
import threading
from typing import Any

from opsonara.core.exceptions import NotFoundError
from opsonara.core.models import AuditRecord

_GENESIS = "0" * 64


def _chain_hash(prev_hash: str, fingerprint: str) -> str:
    payload = f"{prev_hash}|{fingerprint}".encode()
    return hashlib.sha256(payload).hexdigest()


class StoredAudit:
    """An audit record plus chain metadata."""

    __slots__ = ("hash", "id", "prev_hash", "record")

    def __init__(self, id: str, record: AuditRecord, prev_hash: str) -> None:
        self.id = id
        self.record = record
        self.prev_hash = prev_hash
        self.hash = _chain_hash(prev_hash, record.fingerprint())

    def to_dict(self) -> dict[str, Any]:
        data = self.record.to_audit_dict()
        data["id"] = self.id
        data["hash"] = self.hash
        data["prev_hash"] = self.prev_hash
        return data


class AuditStore:
    """Append-only store with O(1) append and chain verification."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: list[StoredAudit] = []
        self._by_id: dict[str, StoredAudit] = {}
        self._prev_hash = _GENESIS

    def append(self, record: AuditRecord) -> str:
        with self._lock:
            audit_id = f"aud_{len(self._records) + 1:06d}_{record.fingerprint()[:8]}"
            stored = StoredAudit(audit_id, record, self._prev_hash)
            self._records.append(stored)
            self._by_id[audit_id] = stored
            self._prev_hash = stored.hash
            return audit_id

    def get(self, audit_id: str) -> StoredAudit:
        with self._lock:
            stored = self._by_id.get(audit_id)
        if stored is None:
            raise NotFoundError(f"audit record '{audit_id}' not found")
        return stored

    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        decision: str | None = None,
        agent_id: str | None = None,
    ) -> tuple[list[StoredAudit], int]:
        """Return (page, total) newest-first with optional filters.

        Walks the record list backwards (newest first) without copying it;
        collection stops as soon as the page is filled, though ``total``
        still requires a full pass when filters are active.
        """
        with self._lock:
            records = self._records
            n = len(records)
            if not decision and not agent_id:
                total = n
                start = max(n - offset, 0)
                end = max(n - offset - limit, 0)
                return records[end:start], total

            page: list[StoredAudit] = []
            total = 0
            wanted_decision = decision.upper() if decision else None
            for stored in reversed(records):
                if wanted_decision and stored.record.decision.value != wanted_decision:
                    continue
                if agent_id and stored.record.agent_id != agent_id:
                    continue
                if total >= offset and len(page) < limit:
                    page.append(stored)
                total += 1
        return page, total

    def counts(self) -> dict[str, Any]:
        """Aggregate decision/band counts in one pass (exact at any volume)."""
        by_decision: dict[str, int] = {}
        by_band: dict[str, int] = {}
        with self._lock:
            total = len(self._records)
            for stored in self._records:
                decision = stored.record.decision.value
                band = stored.record.risk_band.value
                by_decision[decision] = by_decision.get(decision, 0) + 1
                by_band[band] = by_band.get(band, 0) + 1
        # Ensure every known decision appears even at zero.
        for d in ("ALLOW", "REVIEW", "BLOCK"):
            by_decision.setdefault(d, 0)
        return {"total": total, "by_decision": by_decision, "by_risk_band": by_band}

    def verify_chain(self) -> bool:
        """Recompute the whole chain; True iff no record was tampered with."""
        with self._lock:
            records = list(self._records)
        expected_prev = _GENESIS
        for stored in records:
            if stored.prev_hash != expected_prev:
                return False
            if stored.hash != _chain_hash(expected_prev, stored.record.fingerprint()):
                return False
            expected_prev = stored.hash
        return True
