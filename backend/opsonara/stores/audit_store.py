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
        # Incremental-verification state: the chain is append-only, so once
        # a prefix is verified it stays verified unless someone mutates
        # records in place (which only happens outside the store API).
        self._verified_count = 0
        self._verified_ok = True
        self._verified_hash = _GENESIS
        # O(1) aggregate counters, updated on every append (see counts()).
        self._total = 0
        self._by_decision: dict[str, int] = {d: 0 for d in ("ALLOW", "REVIEW", "BLOCK")}
        self._by_band: dict[str, int] = {}

    def append(self, record: AuditRecord) -> str:
        with self._lock:
            audit_id = f"aud_{len(self._records) + 1:06d}_{record.fingerprint()[:8]}"
            stored = StoredAudit(audit_id, record, self._prev_hash)
            self._records.append(stored)
            self._by_id[audit_id] = stored
            self._prev_hash = stored.hash
            # Keep aggregates exact at O(1) per append.
            self._total += 1
            self._by_decision[record.decision.value] = (
                self._by_decision.get(record.decision.value, 0) + 1
            )
            self._by_band[record.risk_band.value] = (
                self._by_band.get(record.risk_band.value, 0) + 1
            )
            return audit_id

    def get(self, audit_id: str) -> StoredAudit:
        with self._lock:
            stored = self._by_id.get(audit_id)
        if stored is None:
            raise NotFoundError(f"audit record '{audit_id}' not found")
        return stored

    def set_human_decision(self, audit_id: str, human_decision: str) -> None:
        """Update the fill-in-later ``human_decision`` pointer.

        Part of the store contract used by review queues (memory and SQLite
        implementations both expose it). Safe with respect to the chain:
        ``fingerprint()`` excludes ``human_decision`` by design.
        """
        with self._lock:
            stored = self._by_id.get(audit_id)
            if stored is None:
                raise NotFoundError(f"audit record '{audit_id}' not found")
            stored.record.human_decision = human_decision

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
        """Aggregate decision/band counts, O(1) via counters kept on append.

        Counters are updated inside the same lock as the append, so they are
        always exact - no periodic rescan needed.
        """
        with self._lock:
            return {
                "total": self._total,
                "by_decision": dict(self._by_decision),
                "by_risk_band": dict(self._by_band),
            }

    def verify_chain(self, force: bool = False) -> bool:
        """Verify the hash chain; O(new records) instead of O(total).

        Verified-prefix caching: ``verify_chain()`` only walks records
        appended since the last successful verification. Pass
        ``force=True`` for a full, authoritative walk (integrity endpoints,
        tamper audits). In-place mutation outside the store API is only
        guaranteed to be caught by a forced walk.
        """
        with self._lock:
            total = len(self._records)
            if not force and self._verified_ok and self._verified_count == total:
                return True
            # A forced walk must restart from the genesis hash - trusting the
            # cached prefix here would be exactly the hole force exists to
            # close (caught by test_chain_detects_tampering).
            if force or not self._verified_ok:
                start = 0
                expected_prev = _GENESIS
            else:
                start = self._verified_count
                expected_prev = self._verified_hash
            ok = True
            for stored in self._records[start:]:
                if stored.prev_hash != expected_prev:
                    ok = False
                    break
                if stored.hash != _chain_hash(expected_prev, stored.record.fingerprint()):
                    ok = False
                    break
                expected_prev = stored.hash
            if ok:
                self._verified_count = total
                self._verified_hash = expected_prev
                self._verified_ok = True
            else:
                self._verified_count = 0
                self._verified_hash = _GENESIS
                self._verified_ok = False
            return ok
