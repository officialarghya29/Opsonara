"""Human Review Queue — where the firewall pauses for human judgment.

REVIEW decisions land here as pending items. A human approves or rejects;
the outcome is written back to the originating audit record and a *new*
audit entry records the human intervention, preserving the append-only
property of the log.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from opsonara.core.exceptions import AlreadyResolvedError, NotFoundError
from opsonara.core.ids import new_id
from opsonara.core.models import AuditRecord, ReviewStatus


@dataclass(slots=True)
class ReviewItem:
    """One pending human decision on a firewall-blocked action."""

    id: str
    audit_id: str
    action: str
    amount: str
    currency: str
    agent_id: str
    customer_id: str
    reason: str
    risk_band: str
    risk_score: str
    status: ReviewStatus = ReviewStatus.PENDING
    reviewed_by: str | None = None
    decided_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "audit_id": self.audit_id,
            "action": self.action,
            "amount": self.amount,
            "currency": self.currency,
            "agent_id": self.agent_id,
            "customer_id": self.customer_id,
            "reason": self.reason,
            "risk_band": self.risk_band,
            "risk_score": self.risk_score,
            "status": self.status.value,
            "reviewed_by": self.reviewed_by,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "created_at": self.created_at.isoformat(),
        }


class ReviewStore:
    """Thread-safe pending-review queue."""

    def __init__(self, audit_store: Any) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, ReviewItem] = {}
        self._audit_store = audit_store

    # -- creation -------------------------------------------------------------

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
            self._items[review_id] = item
        return review_id

    # -- reads ----------------------------------------------------------------

    def get(self, review_id: str) -> ReviewItem:
        with self._lock:
            item = self._items.get(review_id)
        if item is None:
            raise NotFoundError(f"review '{review_id}' not found")
        return item

    def list(self, *, status: str | None = None) -> list[ReviewItem]:
        with self._lock:
            items = list(self._items.values())
        if status:
            wanted = ReviewStatus(status.lower())
            items = [i for i in items if i.status is wanted]
        items.sort(key=lambda i: i.created_at, reverse=True)
        return items

    def count_pending(self) -> int:
        """O(1) pending count for the stats hot path."""
        with self._lock:
            return sum(1 for i in self._items.values() if i.status is ReviewStatus.PENDING)

    # -- decisions ------------------------------------------------------------

    def decide(
        self,
        review_id: str,
        *,
        approved: bool,
        reviewer: str,
    ) -> tuple[ReviewItem, AuditRecord, str]:
        """Resolve a pending review.

        Returns ``(item, human_audit_record, human_audit_id)`` — the new
        audit entry documents the human intervention.
        """
        with self._lock:
            item = self._items.get(review_id)
            if item is None:
                raise NotFoundError(f"review '{review_id}' not found")
            if item.status is not ReviewStatus.PENDING:
                raise AlreadyResolvedError(
                    f"review '{review_id}' already resolved as '{item.status.value}'"
                )
            item.status = ReviewStatus.APPROVED if approved else ReviewStatus.REJECTED
            item.reviewed_by = reviewer
            item.decided_at = datetime.now(UTC)

        # Write the human outcome back onto the originating audit record
        # via the backend-agnostic store contract.
        self._audit_store.set_human_decision(item.audit_id, item.status.value)
        origin = self._audit_store.get(item.audit_id)

        # Append a new audit entry documenting the human intervention.
        human_record = AuditRecord(
            action=item.action,
            amount=Decimal(item.amount),
            currency=item.currency,
            customer_id=item.customer_id,
            agent_id=item.agent_id,
            customer_risk=origin.record.customer_risk,
            injection_risk=origin.record.injection_risk,
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
