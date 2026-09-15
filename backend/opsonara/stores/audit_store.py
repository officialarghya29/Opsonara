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

    __slots__ = ("id", "record", "prev_hash", "hash")

    def __init__(self, id: str, record: AuditRecord, prev_hash: str) -> None:  # noqa: A002
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
        """Return (page, total) newest-first with optional filters."""
        with self._lock:
            records = list(self._records)
        if decision:
            records = [r for r in records if r.record.decision.value == decision.upper()]
        if agent_id:
            records = [r for r in records if r.record.agent_id == agent_id]
        records.reverse()  # newest first
        total = len(records)
        return records[offset : offset + limit], total

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
