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
from pathlib import Path
from typing import Any

from opsonara.core.exceptions import AlreadyResolvedError, NotFoundError
from opsonara.core.ids import new_id
from opsonara.core.models import AuditRecord, ReviewStatus
from opsonara.stores.audit_store import _GENESIS, StoredAudit, _chain_hash
from opsonara.stores.protocols import AuditStoreProtocol, ReviewStoreProtocol
from opsonara.stores.review_store import (
    _OUTCOME_PARTIAL,
    ReviewItem,
    apply_review_decision,
    build_human_record,
    build_partial_receipt,
)

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
CREATE INDEX IF NOT EXISTS idx_reviews_status ON reviews(status);
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
        # WAL + synchronous=NORMAL: commits don't fsync (the WAL survives
        # process crashes); power-loss can at most roll back the tail, which
        # the hash chain then *detects*. Durability-critical deployments can
        # override with PRAGMA synchronous=FULL.
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.commit()
        # Incremental-verification state (see verify_chain).
        self._verified_ok = True
        self._verified_last = (-1, _GENESIS)
        # Seed O(1) aggregate counters once at startup; appends keep them
        # exact. (A restart rescan is unavoidable and acceptable - once.)
        self._seed_counts()

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
        # Keep aggregate counters exact (same lock as append).
        self._total += 1
        self._by_decision[record.decision.value] = (
            self._by_decision.get(record.decision.value, 0) + 1
        )
        self._by_band[record.risk_band.value] = (
            self._by_band.get(record.risk_band.value, 0) + 1
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

    def set_human_decision(self, audit_id: str, human_decision: str) -> None:
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

    def _seed_counts(self) -> None:
        """One-time GROUP BY at startup; afterwards counters are O(1)."""
        self._total = 0
        self._by_decision: dict[str, int] = {d: 0 for d in ("ALLOW", "REVIEW", "BLOCK")}
        self._by_band: dict[str, int] = {}
        for row in self._conn.execute(
            "SELECT json_extract(data, '$.decision'), "
            "json_extract(data, '$.risk_band'), COUNT(*) "
            "FROM audit_records GROUP BY 1, 2"
        ):
            decision, band, count = str(row[0]), str(row[1]), int(row[2])
            self._by_decision[decision] = self._by_decision.get(decision, 0) + count
            self._by_band[band] = self._by_band.get(band, 0) + count
        total_row = self._conn.execute("SELECT COUNT(*) FROM audit_records").fetchone()
        self._total = int(total_row[0])

    def counts(self) -> dict[str, Any]:
        """Aggregate counts, O(1): seeded once at startup, kept exact on append."""
        with self._lock:
            return {
                "total": self._total,
                "by_decision": dict(self._by_decision),
                "by_risk_band": dict(self._by_band),
            }

    def verify_chain(self, force: bool = False) -> bool:
        """Verify the hash chain incrementally.

        Default calls only walk rows appended since the last successful
        verification (keyed on ``(max seq, last hash)``). ``force=True``
        walks the whole table - integrity endpoints and tamper audits must
        not trust cached prefixes.
        """
        with self._lock:
            last = self._last_row()
            if (
                not force
                and self._verified_ok
                and last is not None
                and (last[0], last[1]) == self._verified_last
            ):
                return True
            # A forced walk must restart from genesis - trusting the cached
            # prefix would defeat the purpose of force=True.
            start_seq = -1 if (force or not self._verified_ok) else self._verified_last[0]
            rows = self._conn.execute(
                "SELECT seq, record_hash, prev_hash, data FROM audit_records "
                "WHERE seq > ? ORDER BY seq ASC",
                (start_seq,),
            ).fetchall()
            expected_prev = (
                _GENESIS if (force or not self._verified_ok) else self._verified_last[1]
            )
            ok = True
            for _seq, record_hash, prev_hash, data in rows:
                record_hash, prev_hash, data = str(record_hash), str(prev_hash), str(data)
                if prev_hash != expected_prev:
                    ok = False
                    break
                record = AuditRecord(**json.loads(data))
                if record_hash != _chain_hash(expected_prev, record.fingerprint()):
                    ok = False
                    break
                expected_prev = record_hash
            new_last = self._last_row()
            if ok:
                if new_last is not None:
                    self._verified_last = (new_last[0], new_last[1])
                self._verified_ok = True
            else:
                self._verified_ok = False
            return ok
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
        self._conn.execute("PRAGMA synchronous=NORMAL")
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
        required_approvals: int = 1,
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
            required_approvals=max(int(required_approvals), 1),
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
        # ORDER BY rowid DESC == newest-first (insertion order) without the
        # expensive per-row json_extract sort; status uses the index.
        if status:
            rows = self._conn.execute(
                "SELECT payload, status FROM reviews WHERE status = ? "
                "ORDER BY rowid DESC",
                (ReviewStatus(status.lower()).value,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT payload, status FROM reviews ORDER BY rowid DESC"
            ).fetchall()
        return [self._to_item(row) for row in rows]

    def count_pending(self) -> int:
        """O(log n) via the status index - no row materialization."""
        row = self._conn.execute(
            "SELECT COUNT(*) FROM reviews WHERE status = ?",
            (ReviewStatus.PENDING.value,),
        ).fetchone()
        return int(row[0])

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
            # Shared decision logic (two-person rule, distinct reviewers).
            outcome = apply_review_decision(item, approved=approved, reviewer=reviewer)

            if outcome == _OUTCOME_PARTIAL:
                # Approval #1 of N: persist the receipt, stay pending.
                self._conn.execute(
                    "UPDATE reviews SET payload = ? WHERE id = ? AND status = ?",
                    (
                        json.dumps(item.to_dict()),
                        review_id,
                        ReviewStatus.PENDING.value,
                    ),
                )
                self._conn.commit()
            else:
                # Conditional UPDATE: the WHERE clause re-asserts "pending"
                # inside the same statement, so two processes (separate
                # connections) racing on the same review cannot both win —
                # rowcount is 0 for the loser, which raises.
                cursor = self._conn.execute(
                    "UPDATE reviews SET payload = ?, status = ? "
                    "WHERE id = ? AND status = ?",
                    (
                        json.dumps(item.to_dict()),
                        item.status.value,
                        review_id,
                        ReviewStatus.PENDING.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise AlreadyResolvedError(
                        f"review '{review_id}' already resolved by another worker"
                    )
                self._conn.commit()

        if outcome == _OUTCOME_PARTIAL:
            receipt = build_partial_receipt(item, review_id, reviewer.strip())
            receipt_id = self._audit_store.append(receipt)
            return item, receipt, receipt_id

        origin = self._audit_store.get(item.audit_id)
        # Persist the origin update. Safe because fingerprint() excludes
        # human_decision (the fill-in-later field), so the chain still
        # verifies; the human verdict itself is chained in its own record.
        self._audit_store.set_human_decision(item.audit_id, item.status.value)

        human_record = build_human_record(item, review_id, origin, approved=approved)
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
            required_approvals=int(data.get("required_approvals", 1)),
            approvals=list(data.get("approvals", [])),
        )


def make_stores(
    backend: str, db_path: str, *, pg_dsn: str = ""
) -> tuple[AuditStoreProtocol, ReviewStoreProtocol]:
    """Factory honoring ``OPSONARA_STORE_BACKEND`` (memory | sqlite | postgres).

    Returns ``(audit_store, review_store)``; both share the same database
    for the sqlite/postgres backends.
    """
    if backend == "sqlite":
        audit_store = SqliteAuditStore(db_path)
        return audit_store, SqliteReviewStore(db_path, audit_store)
    if backend == "postgres":
        if not pg_dsn:
            raise ValueError("OPSONARA_PG_DSN is required when store_backend is 'postgres'")
        from opsonara.stores.pg_store import make_pg_stores

        return make_pg_stores(pg_dsn)
    if backend == "memory":
        from opsonara.stores.audit_store import AuditStore
        from opsonara.stores.review_store import ReviewStore

        memory_audit_store = AuditStore()
        return memory_audit_store, ReviewStore(memory_audit_store)
    raise ValueError(
        f"unknown store backend {backend!r}; expected 'memory', 'sqlite' or 'postgres'"
    )


__all__ = ["SqliteAuditStore", "SqliteReviewStore", "make_stores"]
