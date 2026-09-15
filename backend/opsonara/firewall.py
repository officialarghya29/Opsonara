"""Firewall pipeline — orchestrates the five-stage decision flow.

    AI agent proposes → Context → Policy → Risk → Decision → Audit

Every stage is stateless; all per-request state lives in the immutable
:class:`RequestContext`. The pipeline itself never executes actions — it
returns the verdict plus a complete audit record, and (when the verdict is
REVIEW) opens an entry in the human review queue.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from opsonara.core.ids import new_id
from opsonara.core.models import (
    AgentIdentity,
    AuditRecord,
    BrandPolicy,
    ConversationTurn,
    CustomerProfile,
    Decision,
    OrderContext,
    ProposedAction,
)
from opsonara.engines.context import ContextEngine, RequestContext
from opsonara.engines.decision import DecisionEngine, DecisionResult
from opsonara.engines.policy import PolicyEngine
from opsonara.engines.risk import RiskEngine
from opsonara.stores.audit_store import AuditStore
from opsonara.stores.review_store import ReviewStore


class FirewallRequest(BaseModel):
    """Everything the firewall needs to evaluate one proposed action."""

    model_config = ConfigDict(frozen=True)

    action: ProposedAction
    agent: AgentIdentity
    customer: CustomerProfile
    order: OrderContext | None = None
    policy: BrandPolicy
    conversation: list[ConversationTurn] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    """Optional telemetry, e.g. ``recent_action_counts`` for anomaly checks."""


class FirewallResponse(BaseModel):
    """The firewall's verdict plus the full decision trace."""

    decision: Decision
    authorization: str
    reasons: list[str]
    policy_status: str
    policy_checks: list[Any]
    risk_score: str
    risk_band: str
    risk_factors: list[Any]
    injection_verdict: str
    injection_score: str
    audit_id: str
    review_id: str | None = None
    audit: dict[str, Any]
    """Exportable audit record (same shape as GET /v1/audit entries)."""


class FirewallEngine:
    """Five-stage pipeline with injected stores for audit and reviews."""

    def __init__(self, audit_store: AuditStore, review_store: ReviewStore) -> None:
        self._context = ContextEngine()
        self._policy = PolicyEngine()
        self._risk = RiskEngine()
        self._decision = DecisionEngine()
        self._audit_store = audit_store
        self._review_store = review_store

    def evaluate(self, request: FirewallRequest) -> FirewallResponse:
        ctx: RequestContext = self._context.build(
            action=request.action,
            agent=request.agent,
            customer=request.customer,
            order=request.order,
            policy=request.policy,
            conversation=request.conversation,
            metadata=request.metadata,
        )

        policy_result = self._policy.evaluate(ctx)
        risk_result = self._risk.evaluate(ctx)
        decision_result: DecisionResult = self._decision.decide(
            policy_status=policy_result.status,
            risk_band=risk_result.band,
            amount=ctx.amount,
            policy=ctx.policy,
            injection_flagged=risk_result.injection_verdict != "clean",
        )

        reasons = self._merge_reasons(decision_result.reasons, risk_result.reasons)

        audit_record = AuditRecord(
            action=ctx.action.type.value,
            amount=ctx.amount,
            currency=ctx.action.currency,
            customer_id=ctx.customer.id,
            order_id=ctx.action.order_id or (ctx.order.id if ctx.order else None),
            agent_id=ctx.agent.id,
            customer_risk=risk_result.factors[1].score,
            injection_risk=risk_result.injection_score,
            risk_score=risk_result.total,
            risk_band=risk_result.band,
            policy_status=policy_result.status.value,
            authorization=decision_result.authorization,
            decision=decision_result.decision,
            reasons=reasons,
            policy_checks=policy_result.checks,
            risk_factors=risk_result.factors,
            human_decision="pending" if decision_result.decision is Decision.REVIEW else None,
        )

        audit_id = self._audit_store.append(audit_record)

        review_id: str | None = None
        if decision_result.decision is Decision.REVIEW:
            review_id = self._review_store.create(
                audit_id=audit_id,
                action=ctx.action.type.value,
                amount=str(ctx.amount),
                currency=ctx.action.currency,
                agent_id=ctx.agent.id,
                customer_id=ctx.customer.id,
                reason="; ".join(reasons),
                risk_band=risk_result.band.value,
                risk_score=str(risk_result.total),
            )

        return FirewallResponse(
            decision=decision_result.decision,
            authorization=decision_result.authorization,
            reasons=reasons,
            policy_status=policy_result.status.value,
            policy_checks=[c.model_dump() for c in policy_result.checks],
            risk_score=str(risk_result.total),
            risk_band=risk_result.band.value,
            risk_factors=[f.model_dump(mode="json") for f in risk_result.factors],
            injection_verdict=risk_result.injection_verdict.value,
            injection_score=str(risk_result.injection_score),
            audit_id=audit_id,
            review_id=review_id,
            audit=audit_record.to_audit_dict(),
        )

    @staticmethod
    def _merge_reasons(decision_reasons: list[str], risk_reasons: list[str]) -> list[str]:
        merged: list[str] = []
        seen: set[str] = set()
        for reason in [*decision_reasons, *risk_reasons]:
            if reason and reason not in seen:
                seen.add(reason)
                merged.append(reason)
        return merged


__all__ = [
    "FirewallEngine",
    "FirewallRequest",
    "FirewallResponse",
    "new_id",
]
