"""Firewall pipeline — orchestrates the five-stage decision flow.

    AI agent proposes → Context → Policy → Risk → Decision → Audit

Every stage is stateless; all per-request state lives in the immutable
:class:`RequestContext`. The pipeline itself never executes actions — it
returns the verdict plus a complete audit record, and (when the verdict is
REVIEW) opens an entry in the human review queue.
"""

from __future__ import annotations

from typing import Any, NamedTuple

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
from opsonara.identity import (
    AGENT_QUARANTINED,
    AgentCredential,
    AgentCredentialError,
    CredentialAuthority,
    MandateRegistry,
    provenance_from_credential,
)
from opsonara.policy_store import PolicyPackStore
from opsonara.stores.protocols import AuditStoreProtocol, ReviewStoreProtocol


class AuthContext(NamedTuple):
    """Gateway-derived identity for one request (from the API-key layer)."""

    brand_id: str
    """Tenant the call belongs to ("public" when auth is off)."""
    key_prefix: str | None = None
    """First 12 chars of the API key used, for audit correlation."""


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
    agent_credential: str | None = None
    """Signed agent credential (JWT); verified when present per auth policy."""
    mandate: dict[str, Any] | None = None
    """Optional signed commerce mandate (AP2/Visa IC/Mastercard Agent Suite)."""


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

    def __init__(self, audit_store: AuditStoreProtocol, review_store: ReviewStoreProtocol) -> None:
        self._context = ContextEngine()
        self._policy = PolicyEngine()
        self._risk = RiskEngine()
        self._decision = DecisionEngine()
        self._audit_store = audit_store
        self._review_store = review_store
        self.policy_packs: PolicyPackStore | None = None
        """When set, an active pack for the request's brand overrides the
        request-supplied policy (multi-tenant rules-as-data)."""
        self.credential_authority: CredentialAuthority | None = None
        self.mandate_registry: MandateRegistry | None = None
        self.credential_mode: str = "optional"
        """'off' | 'optional' (verify when presented) | 'strict' (required)."""

    # Actions a quarantined agent may still request without forced review.
    # Everything else (refunds, cancellations, price changes…) is forced to
    # human review while the agent is contained (spec §29).
    _QUARANTINE_SAFE_ACTIONS = {"read", "lookup", "suggest"}

    def evaluate(
        self,
        request: FirewallRequest,
        auth: AuthContext | None = None,
        *,
        simulation: str | None = None,
        create_review: bool = True,
    ) -> FirewallResponse:
        """Run the pipeline for one proposed action.

        ``simulation``: tag the audit record's provenance with the simulating
        pack (policy-simulator replays). ``create_review=False`` skips the
        human-review queue — replays must never open real review items.
        """
        provenance = self._resolve_identity(request, auth)
        if simulation:
            provenance = {**(provenance or {}), "simulation": simulation}
        agent_state = (
            (provenance or {}).get("lifecycle_state")
            or (
                self.credential_authority.state_of(request.agent.id)
                if self.credential_authority is not None
                else None
            )
        )
        policy = request.policy
        if auth is not None and self.policy_packs is not None:
            policy, _pack_source = self.policy_packs.resolve(auth.brand_id, request.policy)

        ctx: RequestContext = self._context.build(
            action=request.action,
            agent=request.agent,
            customer=request.customer,
            order=request.order,
            policy=policy,
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

        # Quarantine containment (spec §29): a quarantined agent's sensitive
        # actions are forced to human review regardless of the computed
        # decision, and the containment is visible in reasons + provenance.
        quarantined = agent_state == AGENT_QUARANTINED
        if quarantined and ctx.action.type.value not in self._QUARANTINE_SAFE_ACTIONS:
            if decision_result.decision is Decision.ALLOW:
                decision_result = DecisionResult(
                    decision=Decision.REVIEW,
                    authorization="denied",
                    reasons=["agent quarantined: human approval required for all sensitive actions"],
                )
                reasons.append("agent quarantined: human approval required for all sensitive actions")
            if provenance is None:
                provenance = {}
            provenance["lifecycle_state"] = AGENT_QUARANTINED

        audit_record = AuditRecord(
            action=ctx.action.type.value,
            amount=ctx.amount,
            currency=ctx.action.currency,
            customer_id=ctx.customer.id,
            order_id=ctx.action.order_id or (ctx.order.id if ctx.order else None),
            agent_id=ctx.agent.id,
            brand_id=auth.brand_id if auth is not None else None,
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
            review_id=None,
            human_decision="pending" if decision_result.decision is Decision.REVIEW else None,
            provenance=provenance,
            request_snapshot={
                "action": request.action.model_dump(mode="json"),
                "agent": request.agent.model_dump(mode="json"),
                "customer": request.customer.model_dump(mode="json"),
                "order": request.order.model_dump(mode="json") if request.order else None,
                "policy": policy.model_dump(mode="json"),
                "conversation": [t.model_dump(mode="json") for t in request.conversation],
                "metadata": request.metadata,
            },
        )

        audit_id = self._audit_store.append(audit_record)

        review_id: str | None = None
        if decision_result.decision is Decision.REVIEW and create_review:
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

    # ------------------------------------------------------------------
    # identity & provenance
    # ------------------------------------------------------------------

    def _resolve_identity(
        self, request: FirewallRequest, auth: AuthContext | None
    ) -> dict[str, Any] | None:
        """Verify presented credentials/mandates; return the audit provenance.

        Raises ValueError (mapped to 422 by the API) when verification fails
        or strict mode demands a credential that is missing/invalid.
        """
        presented = request.agent_credential is not None or request.mandate is not None
        if not presented:
            if self.credential_mode == "strict":
                raise ValueError("strict credential mode requires a signed agent credential")
            return None
        provenance: dict[str, Any] = {
            "credential": "not_presented" if request.agent_credential is None else "pending",
            "mandate": None,
        }
        cred: AgentCredential | None = None
        if request.agent_credential is not None:
            authority = self.credential_authority
            if authority is None:
                raise ValueError("agent credential presented but no credential authority configured")
            try:
                # "public" is the dev/no-auth tenant — don't pin the brand
                # to it, or credentials issued for a real brand would all
                # be rejected in dev mode.
                pin_brand = (
                    auth.brand_id
                    if auth is not None and auth.brand_id != "public"
                    else None
                )
                cred = authority.verify(request.agent_credential, brand_id=pin_brand)
            except AgentCredentialError as exc:
                if self.credential_mode == "strict":
                    raise ValueError(f"agent credential rejected: {exc}") from exc
                provenance["credential"] = f"rejected: {exc}"
            else:
                provenance.update(provenance_from_credential(cred))
                provenance["mandate"] = None

        if request.mandate is not None:
            registry = self.mandate_registry
            if registry is None:
                raise ValueError("mandate presented but no mandate verifier configured")
            brand = auth.brand_id if auth is not None else "default"
            verdict = registry.verify(request.mandate, brand_id=brand)
            provenance["mandate"] = verdict.to_dict()
            if not verdict.valid and self.credential_mode == "strict":
                raise ValueError(f"mandate rejected: {verdict.detail}")
        return provenance

    @staticmethod
    def _merge_reasons(decision_reasons: list[str], risk_reasons: list[str]) -> list[str]:
        merged: list[str] = []
        seen: set[str] = set()
        for reason in [*decision_reasons, *risk_reasons]:
            if reason and reason not in seen:
                seen.add(reason)
                merged.append(reason)
        return merged

    def evaluate_request(self, request: dict[str, Any]) -> FirewallResponse:
        """Dict-entry convenience wrapper around :meth:`evaluate`.

        Used by connectors and webhook adapters that receive raw JSON;
        validation errors surface as pydantic ValidationError.
        """
        return self.evaluate(FirewallRequest.model_validate(request))


__all__ = [
    "FirewallEngine",
    "FirewallRequest",
    "FirewallResponse",
    "new_id",
]
