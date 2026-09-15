"""Persistent stores (SQLite) — drop-in replacements for the in-memory ones.

Same interfaces as :class:`AuditStore` and :class:`ReviewStore`, so the
firewall pipeline, API layer, and dashboard work unchanged. Enable with
``OPSONARA_STORE_BACKEND=sqlite`` and ``OPSONARA_DB_PATH=/data/opsonara.db``.

Design notes
------------
* WAL journal mode: concurrent readers never block the writer.
* The hash-chain columns are preserved, so tamper evidence survives restarts.
* All money fields are stored as TEXT (canonical Decimal strings).
* A single lock serializes writes; SQLite additionally enforces durability.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from opsonara.core.exceptions import AlreadyResolvedError, NotFoundError
from opsonara.core.ids import new_id
from opsonara.core.models import AuditRecord, ReviewStatus
from opsonara.stores.audit_store import _GENESIS, StoredAudit, _chain_hash
from opsonara.stores.review_store import ReviewItem

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_records (
    id            TEXT PRIMARY KEY,
    seq           INTEGER UNIQUE,
    data          TEXT NOT NULL,
    record_hash   TEXT NOT NULL,
    prev_hash     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reviews (
    id          TEXT PRIMARY KEY,
    audit_id    TEXT NOT NULL,
    payload     TEXT NOT NULL,
    status      TEXT NOT NULL
);
"""


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class SqliteAuditStore:
    """Append-only, hash-chained audit store persisted to SQLite."""

    def __init__(self, db_path: str | Path) -> None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.commit()

    # -- internal ------------------------------------------------------------

    def _append_locked(self, record: AuditRecord, prev_hash: str, seq: int) -> str:
        audit_id = f"aud_{seq:06d}_{record.fingerprint()[:8]}"
        stored = StoredAudit(audit_id, record, prev_hash)
        self._conn.execute(
            "INSERT INTO audit_records (id, seq, data, record_hash, prev_hash) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                audit_id,
                seq,
                json.dumps(record.to_audit_dict()),
                stored.hash,
                stored.prev_hash,
            ),
        )
        return audit_id

    def _last_row(self) -> tuple[int, str] | None:
        row = self._conn.execute(
            "SELECT seq, record_hash FROM audit_records ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return (int(row[0]), str(row[1])) if row else None

    # -- public (AuditStore interface) ----------------------------------------

    def append(self, record: AuditRecord) -> str:
        with self._lock:
            last = self._last_row()
            seq = (last[0] + 1) if last else 1
            prev_hash = last[1] if last else _GENESIS
            audit_id = self._append_locked(record, prev_hash, seq)
            self._conn.commit()
            return audit_id

    def get(self, audit_id: str) -> StoredAudit:
        row = self._conn.execute(
            "SELECT id, data, record_hash, prev_hash FROM audit_records WHERE id = ?",
            (audit_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(f"audit record '{audit_id}' not found")
        return self._to_stored(row)

    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        decision: str | None = None,
        agent_id: str | None = None,
    ) -> tuple[list[StoredAudit], int]:
        clauses: list[str] = []
        params: list[Any] = []
        if decision:
            clauses.append("json_extract(data, '$.decision') = ?")
            params.append(decision.upper())
        if agent_id:
            clauses.append("json_extract(data, '$.agent_id') = ?")
            params.append(agent_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        total_row = self._conn.execute(
            f"SELECT COUNT(*) FROM audit_records {where}", params
        ).fetchone()
        total = int(total_row[0])
        rows = self._conn.execute(
            "SELECT id, data, record_hash, prev_hash FROM audit_records "
            f"{where} ORDER BY seq DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
        return [self._to_stored(row) for row in rows], total

    def _update_human_decision_locked(self, audit_id: str, human_decision: str) -> None:
        """Persist the fill-in-later ``human_decision`` pointer on an origin row.

        The chain hash columns are untouched: ``fingerprint()`` deliberately
        excludes ``human_decision``, so :meth:`verify_chain` still passes.
        The human's verdict is independently chained in its own record.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM audit_records WHERE id = ?", (audit_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError(f"audit record '{audit_id}' not found")
            data = json.loads(str(row[0]))
            data["human_decision"] = human_decision
            self._conn.execute(
                "UPDATE audit_records SET data = ? WHERE id = ?",
                (json.dumps(data), audit_id),
            )
            self._conn.commit()

    def counts(self) -> dict[str, Any]:
        by_decision: dict[str, int] = {d: 0 for d in ("ALLOW", "REVIEW", "BLOCK")}
        by_band: dict[str, int] = {}
        for row in self._conn.execute(
            "SELECT json_extract(data, '$.decision'), "
            "json_extract(data, '$.risk_band'), COUNT(*) "
            "FROM audit_records GROUP BY 1, 2"
        ):
            decision, band, count = str(row[0]), str(row[1]), int(row[2])
            by_decision[decision] = by_decision.get(decision, 0) + count
            by_band[band] = by_band.get(band, 0) + count
        total_row = self._conn.execute("SELECT COUNT(*) FROM audit_records").fetchone()
        return {"total": int(total_row[0]), "by_decision": by_decision, "by_risk_band": by_band}

    def verify_chain(self) -> bool:
        expected_prev = _GENESIS
        rows = self._conn.execute(
            "SELECT record_hash, prev_hash, data FROM audit_records ORDER BY seq ASC"
        ).fetchall()
        for record_hash, prev_hash, data in rows:
            record_hash, prev_hash, data = str(record_hash), str(prev_hash), str(data)
            if prev_hash != expected_prev:
                return False
            record = AuditRecord(**json.loads(data))
            if record_hash != _chain_hash(expected_prev, record.fingerprint()):
                return False
            expected_prev = record_hash
        return True

    @staticmethod
    def _to_stored(row: tuple[Any, ...]) -> StoredAudit:
        audit_id, data, record_hash, prev_hash = (
            str(row[0]), str(row[1]), str(row[2]), str(row[3]),
        )
        record = AuditRecord(**json.loads(data))
        stored = StoredAudit(audit_id, record, prev_hash)
        stored.hash = record_hash
        return stored


class SqliteReviewStore:
    """Human review queue persisted to SQLite."""

    def __init__(self, db_path: str | Path, audit_store: SqliteAuditStore) -> None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.commit()
        self._audit_store = audit_store

    def create(
        self,
        *,
        audit_id: str,
        action: str,
        amount: str,
        currency: str,
        agent_id: str,
        customer_id: str,
        reason: str,
        risk_band: str,
        risk_score: str,
    ) -> str:
        review_id = new_id("rev")
        item = ReviewItem(
            id=review_id,
            audit_id=audit_id,
            action=action,
            amount=amount,
            currency=currency,
            agent_id=agent_id,
            customer_id=customer_id,
            reason=reason,
            risk_band=risk_band,
            risk_score=risk_score,
        )
        with self._lock:
            self._conn.execute(
                "INSERT INTO reviews (id, audit_id, payload, status) VALUES (?, ?, ?, ?)",
                (review_id, audit_id, json.dumps(item.to_dict()), item.status.value),
            )
            self._conn.commit()
        return review_id

    def get(self, review_id: str) -> ReviewItem:
        row = self._conn.execute(
            "SELECT payload, status FROM reviews WHERE id = ?", (review_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError(f"review '{review_id}' not found")
        return self._to_item(row)

    def list(self, *, status: str | None = None) -> list[ReviewItem]:
        if status:
            rows = self._conn.execute(
                "SELECT payload, status FROM reviews WHERE status = ? "
                "ORDER BY json_extract(payload, '$.created_at') DESC",
                (ReviewStatus(status.lower()).value,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT payload, status FROM reviews "
                "ORDER BY json_extract(payload, '$.created_at') DESC"
            ).fetchall()
        return [self._to_item(row) for row in rows]

    def decide(
        self,
        review_id: str,
        *,
        approved: bool,
        reviewer: str,
    ) -> tuple[ReviewItem, AuditRecord, str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload, status FROM reviews WHERE id = ?", (review_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError(f"review '{review_id}' not found")
            item = self._to_item(row)
            if item.status is not ReviewStatus.PENDING:
                raise AlreadyResolvedError(
                    f"review '{review_id}' already resolved as '{item.status.value}'"
                )
            item.status = ReviewStatus.APPROVED if approved else ReviewStatus.REJECTED
            item.reviewed_by = reviewer
            item.decided_at = datetime.now(UTC)
            self._conn.execute(
                "UPDATE reviews SET payload = ?, status = ? WHERE id = ?",
                (json.dumps(item.to_dict()), item.status.value, review_id),
            )
            self._conn.commit()

        origin = self._audit_store.get(item.audit_id)
        origin.record.human_decision = item.status.value
        # Persist the origin update. Safe because fingerprint() excludes
        # human_decision (the fill-in-later field), so the chain still
        # verifies; the human verdict itself is chained in its own record.
        self._audit_store._update_human_decision_locked(
            item.audit_id, item.status.value
        )

        human_record = AuditRecord(
            action=item.action,
            amount=Decimal(item.amount),
            currency=item.currency,
            customer_id=item.customer_id,
            agent_id=item.agent_id,
            customer_risk=origin.record.customer_risk,
            injection_risk=origin.record.injection_risk,
            risk_score=origin.record.risk_score,
            risk_band=origin.record.risk_band,
            policy_status=origin.record.policy_status,
            authorization="granted" if approved else "denied",
            decision=origin.record.decision,
            reasons=[f"human {'approved' if approved else 'rejected'} review {review_id}"],
            policy_checks=origin.record.policy_checks,
            risk_factors=origin.record.risk_factors,
            review_id=review_id,
            human_decision=item.status.value,
        )
        human_audit_id = self._audit_store.append(human_record)
        return item, human_record, human_audit_id

    @staticmethod
    def _to_item(row: tuple[Any, ...]) -> ReviewItem:
        data = json.loads(str(row[0]))
        return ReviewItem(
            id=data["id"],
            audit_id=data["audit_id"],
            action=data["action"],
            amount=data["amount"],
            currency=data["currency"],
            agent_id=data["agent_id"],
            customer_id=data["customer_id"],
            reason=data["reason"],
            risk_band=data["risk_band"],
            risk_score=data["risk_score"],
            status=ReviewStatus(data.get("status", ReviewStatus.PENDING.value)),
            reviewed_by=data.get("reviewed_by"),
            decided_at=(
                datetime.fromisoformat(data["decided_at"]) if data.get("decided_at") else None
            ),
            created_at=(
                datetime.fromisoformat(data["created_at"])
                if data.get("created_at")
                else datetime.now(UTC)
            ),
        )


def make_stores(backend: str, db_path: str) -> tuple[Any, Any]:
    """Factory honoring ``OPSONARA_STORE_BACKEND`` (memory | sqlite).

    Returns ``(audit_store, review_store)``; both share the SQLite database
    when the backend is ``sqlite``.
    """
    if backend == "sqlite":
        audit_store = SqliteAuditStore(db_path)
        return audit_store, SqliteReviewStore(db_path, audit_store)
    from opsonara.stores.audit_store import AuditStore
    from opsonara.stores.review_store import ReviewStore

    memory_audit_store = AuditStore()
    return memory_audit_store, ReviewStore(memory_audit_store)


__all__ = ["SqliteAuditStore", "SqliteReviewStore", "make_stores"]
