"""Structural contracts for store backends.

The memory and SQLite implementations are independent classes (no shared
base), so the pipeline, API layer, and factory type against these
``Protocol``s: any backend exposing the same surface is a valid substitute.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from opsonara.core.models import AuditRecord
    from opsonara.stores.audit_store import StoredAudit
    from opsonara.stores.review_store import ReviewItem


@runtime_checkable
class AuditStoreProtocol(Protocol):
    """Append-only, hash-chained audit log."""

    def append(self, record: AuditRecord) -> str: ...

    def get(self, audit_id: str) -> StoredAudit: ...

    def set_human_decision(self, audit_id: str, human_decision: str) -> None: ...

    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        decision: str | None = None,
        agent_id: str | None = None,
    ) -> tuple[list[StoredAudit], int]: ...

    def counts(self) -> dict[str, Any]: ...

    def verify_chain(self, force: bool = False) -> bool: ...


@runtime_checkable
class ReviewStoreProtocol(Protocol):
    """Human review queue over a firewall REVIEW decision."""

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
    ) -> str: ...

    def get(self, review_id: str) -> ReviewItem: ...

    def list(self, *, status: str | None = None) -> list[ReviewItem]: ...

    def count_pending(self) -> int: ...

    def decide(
        self,
        review_id: str,
        *,
        approved: bool,
        reviewer: str,
    ) -> tuple[ReviewItem, AuditRecord, str]: ...


__all__ = ["AuditStoreProtocol", "ReviewStoreProtocol"]
