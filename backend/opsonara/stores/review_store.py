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
from opsonara.core.models import AuditRecord, Decision, ReviewStatus, RiskBand

_OUTCOME_APPROVED = "approved"
_OUTCOME_REJECTED = "rejected"
_OUTCOME_PARTIAL = "partial"


def apply_review_decision(
    item: ReviewItem, *, approved: bool, reviewer: str
) -> str:
    """Mutate ``item`` with one human decision (shared by all backends).

    Returns the outcome: ``approved`` (review resolved), ``rejected``
    (resolved), or ``partial`` (first approval of a two-person review —
    stays pending for a second, distinct human).

    Raises ``AlreadyResolvedError`` when the review is finished or this
    reviewer already decided it — the two-person rule requires *distinct*
    humans, and one person cannot stuff the ballot.
    """
    reviewer_name = reviewer.strip()
    if not reviewer_name:
        raise ValueError("reviewer name must not be empty")
    if item.status is not ReviewStatus.PENDING:
        raise AlreadyResolvedError(
            f"review '{item.id}' already resolved as '{item.status.value}'"
        )
    if any(a.get("reviewer") == reviewer_name for a in item.approvals):
        raise AlreadyResolvedError(
            f"reviewer '{reviewer_name}' already decided review '{item.id}'"
        )
    if not approved:
        item.status = ReviewStatus.REJECTED
        item.reviewed_by = reviewer_name
        item.decided_at = datetime.now(UTC)
        return _OUTCOME_REJECTED
    item.approvals.append(
        {"reviewer": reviewer_name, "approved": True, "at": datetime.now(UTC).isoformat()}
    )
    if len(item.approvals) >= item.required_approvals:
        item.status = ReviewStatus.APPROVED
        item.reviewed_by = ", ".join(a["reviewer"] for a in item.approvals)
        item.decided_at = datetime.now(UTC)
        return _OUTCOME_APPROVED
    return _OUTCOME_PARTIAL


def build_partial_receipt(item: ReviewItem, review_id: str, reviewer: str) -> AuditRecord:
    """Chained audit record acknowledging approval #1 of a two-person review."""
    return AuditRecord(
        action=item.action,
        amount=Decimal(item.amount),
        currency=item.currency,
        customer_id=item.customer_id,
        agent_id=item.agent_id,
        customer_risk=Decimal("0"),
        injection_risk=Decimal("0"),
        risk_band=RiskBand.MEDIUM,
        policy_status="requires_human",
        authorization="pending_human",
        decision=Decision.REVIEW,
        reasons=[
            f"first approval recorded by '{reviewer}'; awaiting "
            f"{item.required_approvals - len(item.approvals)} more "
            "(two-person approval rule)"
        ],
        policy_checks=[],
        risk_factors=[],
        review_id=review_id,
        human_decision="partial",
    )


def build_human_record(
    item: ReviewItem, review_id: str, origin: Any, *, approved: bool
) -> AuditRecord:
    """Chained audit record documenting a completed human intervention."""
    return AuditRecord(
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
    required_approvals: int = 1
    """Two-person rule (spec §27): 2 means two DISTINCT humans must approve
    before the action may execute."""
    approvals: list[dict[str, Any]] = field(default_factory=list)
    """Approvals recorded so far: ``[{reviewer, approved, at}]``."""

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
            "required_approvals": self.required_approvals,
            "approvals": self.approvals,
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
        """Record one human decision (supports the two-person rule).

        Returns ``(item, human_audit_record, human_audit_id)``. For the
        first approval of a ``required_approvals=2`` review the record is a
        *partial receipt* and the item stays pending.
        """
        with self._lock:
            item = self._items.get(review_id)
            if item is None:
                raise NotFoundError(f"review '{review_id}' not found")
            outcome = apply_review_decision(item, approved=approved, reviewer=reviewer)

        if outcome == _OUTCOME_PARTIAL:
            receipt = build_partial_receipt(item, review_id, reviewer.strip())
            receipt_id = self._audit_store.append(receipt)
            return item, receipt, receipt_id

        # Resolved: write the outcome back and chain the intervention record.
        self._audit_store.set_human_decision(item.audit_id, item.status.value)
        origin = self._audit_store.get(item.audit_id)
        human_record = build_human_record(
            item, review_id, origin, approved=approved
        )
        human_audit_id = self._audit_store.append(human_record)
        return item, human_record, human_audit_id
