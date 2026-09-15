"""Domain models for the Opsonara decision pipeline.

These Pydantic models form the single contract between:
  the AI agent  ->  the firewall API  ->  the engine pipeline  ->  the audit log.

All monetary amounts are ``Decimal``-quantized so policy comparisons and the
persisted audit trail are exact (never float drift).
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ActionType(StrEnum):
    """Action families the firewall can gate. Adding a new member only
    requires a matching policy in the brand config — no code changes."""

    REFUND = "refund"
    REPLACEMENT = "replacement"
    CANCEL_ORDER = "cancel_order"
    UPDATE_SHIPPING = "update_shipping"
    DISCOUNT = "discount"
    STORE_CREDIT = "store_credit"
    PRICE_OVERRIDE = "price_override"


# Actions that move real money or goods and are therefore always
# sensitive. Used by the risk engine to baseline sensitivity.
HIGH_VALUE_ACTIONS: frozenset[ActionType] = frozenset(
    {
        ActionType.REFUND,
        ActionType.STORE_CREDIT,
        ActionType.PRICE_OVERRIDE,
    }
)

# Actions that always land in the human queue regardless of size.
ALWAYS_REVIEW_ACTIONS: frozenset[ActionType] = frozenset(
    {
        ActionType.PRICE_OVERRIDE,
    }
)


class Decision(StrEnum):
    """The three-way firewall decision (stronger than safe/risky)."""

    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class PolicyStatus(StrEnum):
    """Result of the policy engine for a proposed action."""

    ALLOWED = "allowed"
    REQUIRES_HUMAN = "requires_human"
    DENIED = "denied"


class ReviewStatus(StrEnum):
    """Lifecycle of a queued human review."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class InjectionVerdict(StrEnum):
    """Heuristic verdict from the prompt-injection detector."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    INJECTED = "injected"


class RiskBand(StrEnum):
    """Human-readable banding of the composite risk score."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------


class AgentIdentity(BaseModel):
    """The AI agent proposing the action."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=120)
    permission_level: int = Field(default=1, ge=0, le=3)
    """0 = read-only, 1 = standard, 2 = senior, 3 = unrestricted."""


class ConversationTurn(BaseModel):
    model_config = ConfigDict(frozen=True)

    role: str = Field(min_length=1, max_length=16)
    content: str = Field(max_length=4000)


class ProposedAction(BaseModel):
    """The action the AI agent wants to execute on the store."""

    model_config = ConfigDict(frozen=True)

    type: ActionType
    amount: Decimal = Field(default=Decimal("0"), ge=0)
    currency: str = Field(default="INR", min_length=3, max_length=3)
    order_id: str | None = None
    customer_id: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)

    @field_validator("amount", mode="before")
    @classmethod
    def _quantize_amount(cls, v: Any) -> Decimal:
        if isinstance(v, float):
            # Refuse float inputs outright: 0.1 cannot be represented exactly
            # and silently quantizing could hide a mismatch between what the
            # agent computed and what we audit.
            raise ValueError("amount must be sent as a string or int, not a float")
        return Decimal(str(v)).quantize(Decimal("0.01"))

    @model_validator(mode="after")
    def _validate_amount_semantics(self) -> ProposedAction:
        if self.type in HIGH_VALUE_ACTIONS and self.amount <= 0:
            raise ValueError(f"action type '{self.type.value}' requires a positive amount")
        return self


class CustomerProfile(BaseModel):
    """Customer context supplied with the request (from the brand's CRM)."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1, max_length=64)
    lifetime_orders: int = Field(default=0, ge=0)
    lifetime_value: Decimal = Field(default=Decimal("0"), ge=0)
    previous_refunds: int = Field(default=0, ge=0)
    previous_refund_value: Decimal = Field(default=Decimal("0"), ge=0)
    chargebacks: int = Field(default=0, ge=0)
    account_age_days: int = Field(default=0, ge=0)
    vip_tier: bool = False

    @field_validator("lifetime_value", "previous_refund_value", mode="before")
    @classmethod
    def _quantize(cls, v: Any) -> Decimal:
        if isinstance(v, float):
            raise ValueError("monetary fields must be strings or ints, not floats")
        return Decimal(str(v)).quantize(Decimal("0.01"))


class OrderContext(BaseModel):
    """The order the proposed action targets."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1, max_length=64)
    customer_id: str = Field(min_length=1, max_length=64)
    status: str = Field(min_length=1, max_length=32)
    total: Decimal = Field(gt=0)
    currency: str = Field(default="INR", min_length=3, max_length=3)
    product_category: str = Field(default="general", max_length=64)
    fulfillment_stage: str = Field(default="none", max_length=32)
    created_days_ago: int = Field(default=0, ge=0)

    @field_validator("total", mode="before")
    @classmethod
    def _quantize(cls, v: Any) -> Decimal:
        if isinstance(v, float):
            raise ValueError("total must be a string or int, not a float")
        return Decimal(str(v)).quantize(Decimal("0.01"))

    @model_validator(mode="after")
    def _validate_status(self) -> OrderContext:
        allowed = {
            "pending",
            "confirmed",
            "processing",
            "shipped",
            "delivered",
            "completed",
            "cancelled",
        }
        if self.status not in allowed:
            raise ValueError(f"unknown order status: {self.status!r}")
        return self


class BrandPolicy(BaseModel):
    """Declarative brand configuration — the heart of the Policy Engine.

    Brands express their authorization rules as data, not code. Every field
    is optional; defaults are deliberately strict.
    """

    model_config = ConfigDict(frozen=True)

    brand_id: str = Field(min_length=1, max_length=64)

    # -- spending limits (per action, in the brand's currency) --------------
    auto_approve_limit: Decimal = Field(default=Decimal("2000"))
    low_risk_limit: Decimal = Field(default=Decimal("10000"))
    human_review_limit: Decimal = Field(default=Decimal("10000"))
    """Amounts above this always require a human, even at low risk."""

    # -- refund policy -------------------------------------------------------
    max_refund_ratio: Decimal = Field(default=Decimal("1.00"))
    """Max refund as a fraction of order total (1.00 = full refund)."""

    refund_window_days: int = Field(default=30, ge=0)

    # -- cancellation policy --------------------------------------------------
    allow_cancel_after_ship: bool = False

    # -- agent permissions -----------------------------------------------------
    min_permission_level: int = Field(default=1, ge=0, le=3)

    # -- customer policy ---------------------------------------------------------
    max_refunds_per_90d: int = Field(default=3, ge=0)
    block_chargeback_history: bool = True
    min_account_age_days: int = Field(default=0, ge=0)

    # -- discount / credit policy --------------------------------------------
    max_discount_pct: Decimal = Field(default=Decimal("30"))

    @field_validator(
        "auto_approve_limit",
        "low_risk_limit",
        "human_review_limit",
        "max_refund_ratio",
        "max_discount_pct",
        mode="before",
    )
    @classmethod
    def _quantize(cls, v: Any) -> Decimal:
        if isinstance(v, float):
            raise ValueError("policy limits must be strings or ints, not floats")
        return Decimal(str(v)).quantize(Decimal("0.01"))


# ---------------------------------------------------------------------------
# Output models (engine results)
# ---------------------------------------------------------------------------


class PolicyCheck(BaseModel):
    """One named policy rule and how the proposed action fared against it."""

    model_config = ConfigDict(frozen=True)

    name: str
    passed: bool
    severity: str = Field(default="info")
    """'info' | 'warning' | 'critical'."""
    detail: str


class PolicyResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: PolicyStatus
    checks: list[PolicyCheck] = Field(default_factory=list)


class RiskFactor(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    score: Decimal = Field(ge=0, le=1)
    """0.0 (no risk) to 1.0 (maximum risk)."""
    weight: Decimal = Field(default=Decimal("0.1"), ge=0, le=1)
    detail: str


class RiskResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    total: Decimal = Field(ge=0, le=1)
    band: RiskBand
    factors: list[RiskFactor] = Field(default_factory=list)
    injection_verdict: InjectionVerdict
    injection_score: Decimal = Field(ge=0, le=1)
    reasons: list[str] = Field(default_factory=list)


class AuditRecord(BaseModel):
    """Immutable, exportable record of one firewall decision.

    Answers: what did my AI agent do, why, which policies applied, what risk
    was detected, and did a human intervene?
    """

    action: str
    amount: Decimal
    currency: str
    customer_id: str | None = None
    order_id: str | None = None
    agent_id: str
    customer_risk: Decimal
    injection_risk: Decimal
    risk_score: Decimal = Field(default=Decimal("0"))
    """Composite transaction risk (0.0-1.0) — the weighted mean of all factors."""
    risk_band: RiskBand
    policy_status: str
    authorization: str
    decision: Decision
    reasons: list[str]
    policy_checks: list[PolicyCheck]
    risk_factors: list[RiskFactor]
    review_id: str | None = None
    human_decision: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def to_audit_dict(self) -> dict[str, Any]:
        """Flat JSON-safe dict, mirroring the shape shown in the product spec."""
        return {
            "action": self.action,
            "amount": str(self.amount),
            "currency": self.currency,
            "customer_id": self.customer_id,
            "order_id": self.order_id,
            "agent_id": self.agent_id,
            "customer_risk": float(self.customer_risk),
            "injection_risk": float(self.injection_risk),
            "risk_score": float(self.risk_score),
            "risk_band": self.risk_band.value,
            "policy_status": self.policy_status,
            "authorization": self.authorization,
            "decision": self.decision.value,
            "reasons": self.reasons,
            "policy_checks": [c.model_dump() for c in self.policy_checks],
            "risk_factors": [f.model_dump(mode="json") for f in self.risk_factors],
            "review_id": self.review_id,
            "human_decision": self.human_decision,
            "timestamp": self.timestamp.isoformat(),
        }

    def fingerprint(self) -> str:
        """Stable SHA-256 over the decision content (chain-hash seed)."""
        payload = (
            f"{self.timestamp.isoformat()}|{self.agent_id}|{self.action}|{self.amount}|"
            f"{self.decision.value}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()
