"""Postgres stores — horizontal-scale backend (multi-instance safe).

Mirrors the SQLite backend's contract and optimizations (incremental chain
verification, O(1) aggregate counters, conditional-UPDATE review decide so
two workers can never both resolve one review).

Requires the optional dependency ``pg8000`` (pure Python, no compiled
parts) and configuration::

    OPSONARA_STORE_BACKEND=postgres
    OPSONARA_PG_DSN=postgresql://user:pass@host:5432/db
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from urllib.parse import urlparse

from opsonara.core.exceptions import AlreadyResolvedError, NotFoundError
from opsonara.core.ids import new_id
from opsonara.core.models import AuditRecord, ReviewStatus
from opsonara.stores.audit_store import _GENESIS, StoredAudit, _chain_hash
from opsonara.stores.review_store import ReviewItem

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_records (
    id          TEXT PRIMARY KEY,
    seq         BIGINT UNIQUE,
    data        JSONB NOT NULL,
    record_hash TEXT NOT NULL,
    prev_hash   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reviews (
    id       TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL,
    payload  JSONB NOT NULL,
    status   TEXT NOT NULL,
    seq_no   BIGSERIAL
);
CREATE INDEX IF NOT EXISTS idx_reviews_status ON reviews(status);
"""


def _connect(dsn: str) -> Any:
    """Open a pg8000 DB-API connection from a postgresql:// DSN."""
    try:
        import pg8000.dbapi as pg  # optional dependency, imported lazily
    except ImportError as exc:  # pragma: no cover - environment-specific
        raise RuntimeError(
            "store_backend='postgres' requires the 'pg8000' package: pip install pg8000"
        ) from exc

    parsed = urlparse(dsn)
    if parsed.scheme not in ("postgresql", "postgres") or not parsed.hostname:
        raise ValueError(f"unsupported Postgres DSN: {dsn!r}")
    return pg.connect(
        user=parsed.username or "postgres",
        password=parsed.password or "",
        host=parsed.hostname,
        port=parsed.port or 5432,
        database=(parsed.path or "/").lstrip("/") or "postgres",
    )


class _PgPool:
    """Thread-safe Postgres connection pool.

    pg8000 declares ``threadsafety = 1``: a connection must not be shared
    across threads. Under uvicorn, request handlers run on a threadpool,
    so one shared connection is a data-corruption bug under load. Each
    ``_PgPool`` user thread checks a connection out, uses it, and returns
    it; overflow demand creates (and keeps) additional connections.
    """

    def __init__(self, dsn: str, *, initial: int = 4) -> None:
        self._dsn = dsn
        self._lock = threading.Lock()
        self._idle: list[Any] = []
        self._all: set[int] = set()
        self._created = 0
        for _ in range(initial):
            self._idle.append(self._new())

    def _new(self) -> Any:
        conn = _connect(self._dsn)
        with self._lock:
            self._all.add(id(conn))
            self._created += 1
        return conn

    @contextmanager
    def connection(self) -> Iterator[Any]:
        with self._lock:
            conn = self._idle.pop() if self._idle else None
        if conn is None:
            conn = self._new()
        try:
            yield conn
        except Exception:
            # A connection that raised mid-transaction may be in a broken
            # state (aborted transaction); recycle it rather than reuse.
            try:
                conn.rollback()
                with self._lock:
                    self._idle.append(conn)
            except Exception:
                self._discard(conn)
            raise
        with self._lock:
            self._idle.append(conn)

    def _discard(self, conn: Any) -> None:
        try:
            conn.close()
        except Exception:
            pass
        with self._lock:
            self._all.discard(id(conn))

    def close_all(self) -> None:
        with self._lock:
            idle, self._idle = self._idle, []
        for conn in idle:
            try:
                conn.close()
            except Exception:
                pass


class _Pg:
    """DB-API facade: ``?`` placeholders, tuple rows, per-thread connections."""

    def __init__(self, dsn: str) -> None:
        self._pool = _PgPool(dsn)

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> Any:
        """Run one statement on a pooled connection and commit.

        The cursor is fully consumed before the connection returns to the
        pool, so callers can safely ``fetchone()``/``fetchall()`` on the
        returned cursor afterwards.
        """
        with self._pool.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql.replace("?", "%s"), list(params))
            rows = cursor.fetchall()
            conn.commit()
        return _CompletedCursor(rows, cursor.rowcount)

    def close(self) -> None:
        self._pool.close_all()


class _CompletedCursor:
    """Materialized result of one statement (rows + rowcount)."""

    def __init__(self, rows: list[Any], rowcount: int) -> None:
        self._rows = rows
        self.rowcount = rowcount

    def fetchone(self) -> Any:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[Any]:
        return list(self._rows)


def _as_dict(raw: Any) -> dict[str, Any]:
    """pg8000 returns dict for JSONB; sqlite compat expects str parse."""
    if isinstance(raw, dict):
        return raw
    parsed: dict[str, Any] = json.loads(str(raw))
    return parsed


def _as_jsonb(value: dict[str, Any]) -> str:
    return json.dumps(value)


class PgAuditStore:
    """Append-only, hash-chained audit store persisted to Postgres."""

    def __init__(self, dsn: str) -> None:
        self._lock = threading.Lock()
        self._db = _Pg(dsn)
        for statement in filter(None, (st.strip() for st in _SCHEMA.split(";"))):
            self._db.execute(statement)
        self._verified_ok = True
        self._verified_seq = 0
        self._verified_hash = _GENESIS
        self._seed_counts()

    # -- internal ------------------------------------------------------------

    def _append_locked(self, record: AuditRecord, prev_hash: str, seq: int) -> str:
        audit_id = f"aud_{seq:06d}_{record.fingerprint()[:8]}"
        stored = StoredAudit(audit_id, record, prev_hash)
        self._db.execute(
            "INSERT INTO audit_records (id, seq, data, record_hash, prev_hash) "
            "VALUES (?, ?, ?, ?, ?)",
            (audit_id, seq, _as_jsonb(record.to_audit_dict()), stored.hash, stored.prev_hash),
        )
        self._total += 1
        self._by_decision[record.decision.value] = (
            self._by_decision.get(record.decision.value, 0) + 1
        )
        self._by_band[record.risk_band.value] = self._by_band.get(record.risk_band.value, 0) + 1
        return audit_id

    def _seed_counts(self) -> None:
        row = self._db.execute("SELECT COUNT(*) FROM audit_records").fetchone()
        self._total = int(row[0]) if row else 0
        self._by_decision: dict[str, int] = {}
        self._by_band: dict[str, int] = {}
        rows = self._db.execute(
            "SELECT data->>'decision' AS d, data->>'risk_band' AS b, COUNT(*) "
            "FROM audit_records GROUP BY 1, 2"
        ).fetchall()
        for decision, band, count in rows:
            self._by_decision[str(decision)] = self._by_decision.get(str(decision), 0) + int(count)
            self._by_band[str(band)] = self._by_band.get(str(band), 0) + int(count)

    # -- public (AuditStore interface) ----------------------------------------

    def append(self, record: AuditRecord) -> str:
        with self._lock:
            last = self._db.execute(
                "SELECT seq, record_hash FROM audit_records ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            seq = (int(last[0]) + 1) if last else 1
            prev_hash = str(last[1]) if last else _GENESIS
            audit_id = self._append_locked(record, prev_hash, seq)
            return audit_id

    def get(self, audit_id: str) -> StoredAudit:
        row = self._db.execute(
            "SELECT id, data, record_hash, prev_hash FROM audit_records WHERE id = ?",
            (audit_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(f"audit record '{audit_id}' not found")
        return self._to_stored(row)

    def set_human_decision(self, audit_id: str, human_decision: str) -> None:
        """Persist the fill-in-later ``human_decision`` pointer on the origin row.

        Safe with respect to the chain: ``fingerprint()`` excludes
        ``human_decision`` by design; the verdict itself is chained in its
        own audit record.
        """
        with self._lock:
            row = self._db.execute(
                "SELECT data FROM audit_records WHERE id = ?", (audit_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError(f"audit record '{audit_id}' not found")
            data = _as_dict(row[0])
            data["human_decision"] = human_decision
            self._db.execute(
                "UPDATE audit_records SET data = ? WHERE id = ?",
                (_as_jsonb(data), audit_id),
            )

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
            clauses.append("data->>'decision' = ?")
            params.append(decision.upper())
        if agent_id:
            clauses.append("data->>'agent_id' = ?")
            params.append(agent_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        total_row = self._db.execute(
            f"SELECT COUNT(*) FROM audit_records{where}", tuple(params)
        ).fetchone()
        total = int(total_row[0]) if total_row else 0
        rows = self._db.execute(
            f"SELECT id, data, record_hash, prev_hash FROM audit_records{where} "
            "ORDER BY seq DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
        return [self._to_stored(r) for r in rows], total

    def counts(self) -> dict[str, Any]:
        with self._lock:
            return {
                "total": self._total,
                "by_decision": dict(self._by_decision),
                "by_risk_band": dict(self._by_band),
            }

    def verify_chain(self, force: bool = False) -> bool:
        """Incremental verification; ``force=True`` walks from genesis."""
        with self._lock:
            row = self._db.execute("SELECT COUNT(*) FROM audit_records").fetchone()
            total = int(row[0]) if row else 0
            if not force and self._verified_ok and self._verified_seq == total:
                return True
            if force or not self._verified_ok:
                start_seq = 0
                expected_prev = _GENESIS
            else:
                start_seq = self._verified_seq
                expected_prev = self._verified_hash
            ok = True
            rows = self._db.execute(
                "SELECT seq, record_hash, prev_hash, data FROM audit_records "
                "WHERE seq > ? ORDER BY seq ASC",
                (start_seq,),
            ).fetchall()
            for _seq, record_hash, prev_hash, data in rows:
                if str(prev_hash) != expected_prev:
                    ok = False
                    break
                record = AuditRecord(**_as_dict(data))
                if str(record_hash) != _chain_hash(expected_prev, record.fingerprint()):
                    ok = False
                    break
                expected_prev = str(record_hash)
            if ok:
                self._verified_seq = total
                self._verified_hash = expected_prev
                self._verified_ok = True
            else:
                self._verified_seq = 0
                self._verified_hash = _GENESIS
                self._verified_ok = False
            return ok

    @staticmethod
    def _to_stored(row: tuple[Any, ...]) -> StoredAudit:
        audit_id, data, record_hash, prev_hash = str(row[0]), row[1], str(row[2]), str(row[3])
        record = AuditRecord(**_as_dict(data))
        stored = StoredAudit(audit_id, record, prev_hash)
        stored.hash = record_hash
        return stored


class PgReviewStore:
    """Human review queue persisted to Postgres (multi-instance safe)."""

    def __init__(self, dsn: str, audit_store: PgAuditStore) -> None:
        self._lock = threading.Lock()
        self._db = _Pg(dsn)
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
            self._db.execute(
                "INSERT INTO reviews (id, audit_id, payload, status) VALUES (?, ?, ?, ?)",
                (review_id, audit_id, _as_jsonb(item.to_dict()), item.status.value),
            )
        return review_id

    def get(self, review_id: str) -> ReviewItem:
        row = self._db.execute(
            "SELECT payload, status FROM reviews WHERE id = ?", (review_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError(f"review '{review_id}' not found")
        return self._to_item(row)

    def list(self, *, status: str | None = None) -> list[ReviewItem]:
        if status:
            rows = self._db.execute(
                "SELECT payload, status FROM reviews WHERE status = ? ORDER BY seq_no DESC",
                (ReviewStatus(status.lower()).value,),
            ).fetchall()
        else:
            rows = self._db.execute(
                "SELECT payload, status FROM reviews ORDER BY seq_no DESC"
            ).fetchall()
        return [self._to_item(r) for r in rows]

    def count_pending(self) -> int:
        row = self._db.execute(
            "SELECT COUNT(*) FROM reviews WHERE status = ?", (ReviewStatus.PENDING.value,)
        ).fetchone()
        return int(row[0]) if row else 0

    def decide(
        self,
        review_id: str,
        *,
        approved: bool,
        reviewer: str,
    ) -> tuple[ReviewItem, AuditRecord, str]:
        with self._lock:
            row = self._db.execute(
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
            # Conditional UPDATE re-asserts "pending" so two workers with
            # separate connections cannot both resolve the same review.
            cursor = self._db.execute(
                "UPDATE reviews SET payload = ?, status = ? WHERE id = ? AND status = ?",
                (
                    _as_jsonb(item.to_dict()),
                    item.status.value,
                    review_id,
                    ReviewStatus.PENDING.value,
                ),
            )
            if cursor.rowcount != 1:
                raise AlreadyResolvedError(
                    f"review '{review_id}' already resolved by another worker"
                )

        origin = self._audit_store.get(item.audit_id)
        self._audit_store.set_human_decision(item.audit_id, item.status.value)
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
        data = _as_dict(row[0])
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


def make_pg_stores(dsn: str) -> tuple[PgAuditStore, PgReviewStore]:
    audit_store = PgAuditStore(dsn)
    return audit_store, PgReviewStore(dsn, audit_store)


__all__ = ["PgAuditStore", "PgReviewStore", "make_pg_stores"]
