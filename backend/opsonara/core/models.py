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
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator, model_validator

from opsonara.core.money import parse_money


def _surrogate_free(v: str) -> str:
    """Reject strings containing UTF-16 surrogate code points.

    JSON allows ``"\\udcff"`` syntactically, but Python cannot UTF-8-encode
    a lone surrogate — such a value would crash the API at *response* time
    (UnicodeEncodeError → 500) long after validation. Rejecting at the
    schema boundary keeps hostile bytes a clean 422 (fail-closed).
    """
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in v):
        raise ValueError("string contains unpaired surrogate code points")
    return v


SafeStr = Annotated[str, AfterValidator(_surrogate_free)]

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

    id: SafeStr = Field(min_length=1, max_length=64)
    name: SafeStr = Field(min_length=1, max_length=120)
    permission_level: int = Field(default=1, ge=0, le=3)
    """0 = read-only, 1 = standard, 2 = senior, 3 = unrestricted."""
    denied_actions: frozenset[str] | list[str] = Field(default_factory=frozenset)
    """Action types this agent may NEVER request (agent-to-tool deny list,
    spec §40). 'customer_data_export' etc. — evaluated before policy, and
    always decisive. Normalized to a frozenset for O(1) checks."""
    max_action_amount: Decimal | None = Field(default=None, gt=0)
    """Hard per-action amount ceiling for this agent, across ALL action
    types (spec §2 amount limit). None = no agent-level cap (policy bands
    still apply). Decisive when exceeded."""
    max_actions_per_hour: int | None = Field(default=None, ge=1)
    """Per-agent frequency cap (spec §2 frequency limit). Counted from the
    ``recent_action_counts`` velocity metadata by the API layer. None = no
    agent-level cap."""

    @field_validator("denied_actions", mode="after")
    @classmethod
    def _freeze_denied(cls, v: frozenset[str] | list[str]) -> frozenset[str]:
        return frozenset(v)

    @field_validator("max_action_amount", mode="before")
    @classmethod
    def _quantize_cap(cls, v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, float):
            raise ValueError("max_action_amount must be a string or int, not a float")
        return parse_money(v, "max_action_amount")


class AgentAuthorizationVerdict(BaseModel):
    """Result of the fine-grained agent-authorization gate (spec §2, §40)."""

    model_config = ConfigDict(frozen=True)

    allowed: bool
    check_name: str
    detail: str


class ConversationTurn(BaseModel):
    model_config = ConfigDict(frozen=True)

    role: Literal["customer", "agent"]
    """Strict contract: only these two roles exist. Anything else is a
    client error - a lenient parser here would let mistyped roles silently
    skip security scanning of customer messages."""
    content: SafeStr = Field(min_length=1, max_length=4000)


class ProposedAction(BaseModel):
    """The action the AI agent wants to execute on the store."""

    model_config = ConfigDict(frozen=True)

    type: ActionType
    amount: Decimal = Field(default=Decimal("0"), ge=0)
    currency: SafeStr = Field(default="INR", min_length=3, max_length=3)
    order_id: SafeStr | None = None
    customer_id: SafeStr | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)

    @field_validator("amount", mode="before")
    @classmethod
    def _quantize_amount(cls, v: Any) -> Decimal:
        if isinstance(v, float):
            # Refuse float inputs outright: 0.1 cannot be represented exactly
            # and silently quantizing could hide a mismatch between what the
            # agent computed and what we audit.
            raise ValueError("amount must be sent as a string or int, not a float")
        return parse_money(v, "amount")

    @model_validator(mode="after")
    def _validate_amount_semantics(self) -> ProposedAction:
        if self.type in HIGH_VALUE_ACTIONS and self.amount <= 0:
            raise ValueError(f"action type '{self.type.value}' requires a positive amount")
        return self


class CustomerProfile(BaseModel):
    """Customer context supplied with the request (from the brand's CRM)."""

    model_config = ConfigDict(frozen=True)

    id: SafeStr = Field(min_length=1, max_length=64)
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
        return parse_money(v, "monetary field")


class OrderContext(BaseModel):
    """The order the proposed action targets."""

    model_config = ConfigDict(frozen=True)

    id: SafeStr = Field(min_length=1, max_length=64)
    customer_id: SafeStr = Field(min_length=1, max_length=64)
    status: SafeStr = Field(min_length=1, max_length=32)
    total: Decimal = Field(gt=0)
    currency: str = Field(default="INR", min_length=3, max_length=3)
    product_category: SafeStr = Field(default="general", max_length=64)
    fulfillment_stage: SafeStr = Field(default="none", max_length=32)
    created_days_ago: int = Field(default=0, ge=0)

    @field_validator("total", mode="before")
    @classmethod
    def _quantize(cls, v: Any) -> Decimal:
        if isinstance(v, float):
            raise ValueError("total must be a string or int, not a float")
        return parse_money(v, "order total")

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

    brand_id: SafeStr = Field(min_length=1, max_length=64)

    # -- spending limits (per action, in the brand's currency) --------------
    auto_approve_limit: Decimal = Field(ge=0, default=Decimal("2000"))
    low_risk_limit: Decimal = Field(ge=0, default=Decimal("10000"))
    human_review_limit: Decimal = Field(ge=0, default=Decimal("10000"))
    """Amounts above this always require a human, even at low risk."""

    # -- refund policy -------------------------------------------------------
    max_refund_ratio: Decimal = Field(ge=0, default=Decimal("1.00"))
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
    max_discount_pct: Decimal = Field(ge=0, default=Decimal("30"))

    # -- human oversight -------------------------------------------------------
    two_person_approval_above: Decimal | None = None
    """Amount above which a REVIEW requires TWO distinct human approvals
    before execution (spec §27 two-person rule). None = single approval."""

    @field_validator("two_person_approval_above", mode="before")
    @classmethod
    def _quantize_two_person(cls, v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, float):
            raise ValueError("two_person_approval_above must be a string or int, not a float")
        return parse_money(v, "two_person_approval_above")

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
        return parse_money(v, "policy limit")


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
    order_id: SafeStr | None = None
    agent_id: str
    brand_id: str | None = None
    """Tenant this decision belongs to (None in single-tenant/dev mode)."""
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
    provenance: dict[str, Any] | None = None
    """Agent-identity provenance: credential, framework, mandate verdict."""
    verification_of: str | None = None
    """For post-execution verification records: audit_id of the verified decision."""
    connector_id: str | None = None
    """Connector that executed (or attempted) the action, when applicable."""
    request_snapshot: dict[str, Any] | None = None
    """Full original request inputs (action, agent, customer, order, policy,
    conversation, metadata) for decision reproducibility and policy-simulator
    replay (spec §12, §37). Not part of the chain fingerprint by design: the
    fingerprint pins the *decision*, the snapshot explains it."""
    blast_radius: dict[str, Any] | None = None
    """Maximum-impact estimate (spec §19/§40): direct exposure, amplification,
    max hourly exposure, band."""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def to_audit_dict(self) -> dict[str, Any]:
        """Flat JSON-safe dict, mirroring the shape shown in the product spec."""
        out: dict[str, Any] = {
            "action": self.action,
            "amount": str(self.amount),
            "currency": self.currency,
            "customer_id": self.customer_id,
            "order_id": self.order_id,
            "agent_id": self.agent_id,
            "brand_id": self.brand_id,
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
        if self.provenance is not None:
            out["provenance"] = self.provenance
        if self.verification_of is not None:
            out["verification_of"] = self.verification_of
        if self.connector_id is not None:
            out["connector_id"] = self.connector_id
        if self.request_snapshot is not None:
            out["request_snapshot"] = self.request_snapshot
        if self.blast_radius is not None:
            out["blast_radius"] = self.blast_radius
        return out

    def fingerprint(self) -> str:
        """Stable SHA-256 over the decision content (chain-hash seed).

        ``human_decision`` is deliberately excluded: it is the one field
        designed to be filled in later (when a human resolves a REVIEW).
        The human's actual verdict is tamper-evidently recorded in its own
        follow-up audit record, so the chain still proves what happened —
        it just doesn't pin the mutable status pointer on the origin row.
        """
        payload = (
            f"{self.timestamp.isoformat()}|{self.agent_id}|{self.action}|{self.amount}|"
            f"{self.decision.value}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()
