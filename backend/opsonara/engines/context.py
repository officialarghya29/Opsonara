"""Context Engine — "What is happening?"

Collects and enriches the context the rest of the pipeline needs before any
decision is made: order information, customer history, previous refunds,
transaction value, and agent/conversation signals. In production this data
comes from the brand's commerce platform (Shopify, WooCommerce, custom).
Opsonara accepts it as structured input so integration is a schema, not a
code change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from opsonara.core.models import (
    AgentIdentity,
    BrandPolicy,
    ConversationTurn,
    CustomerProfile,
    OrderContext,
    ProposedAction,
)


@dataclass(slots=True)
class CustomerHistory:
    """Derived behavioural history for the customer in this request."""

    refund_frequency: Decimal = Decimal("0")
    """Previous refunds / lifetime orders (capped at 1.0)."""
    refund_intensity: Decimal = Decimal("0")
    """Previous refunded value / lifetime value (capped at 1.0)."""
    trust_score: Decimal = Decimal("0.5")
    """0.0 (no trust signal) .. 1.0 (very trustworthy)."""
    flags: list[str] = field(default_factory=list)


class ContextEngine:
    """Builds the immutable :class:`RequestContext` for one decision.

    The engine never mutates inputs; it derives normalized views of them so
    the Policy and Risk engines work from one consistent snapshot.
    """

    def build(
        self,
        *,
        action: ProposedAction,
        agent: AgentIdentity,
        customer: CustomerProfile,
        order: OrderContext | None,
        policy: BrandPolicy,
        conversation: list[ConversationTurn] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> RequestContext:
        conversation = conversation or []
        metadata = metadata or {}

        history = self._derive_history(customer)
        self._validate_binding(action=action, customer=customer, order=order)

        return RequestContext(
            action=action,
            agent=agent,
            customer=customer,
            order=order,
            policy=policy,
            conversation=tuple(conversation),
            history=history,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _validate_binding(
        self,
        *,
        action: ProposedAction,
        customer: CustomerProfile,
        order: OrderContext | None,
    ) -> None:
        """Fail fast on inconsistent context before engines run."""
        if action.customer_id and order is not None and action.customer_id != order.customer_id:
            raise ValueError(
                "action.customer_id does not match the order's customer — refusing to evaluate"
            )
        if order is None and action.order_id:
            raise ValueError("action references an order_id but no order context was supplied")
        if customer.id == "unknown" and order is not None:
            # Anonymous customers with order context are valid, but flagged.
            pass

    def _derive_history(self, customer: CustomerProfile) -> CustomerHistory:
        flags: list[str] = []

        refund_frequency = Decimal("0")
        if customer.lifetime_orders > 0:
            refund_frequency = min(
                Decimal(customer.previous_refunds) / Decimal(customer.lifetime_orders),
                Decimal("1"),
            )

        refund_intensity = Decimal("0")
        if customer.lifetime_value > 0:
            refund_intensity = min(
                customer.previous_refund_value / customer.lifetime_value,
                Decimal("1"),
            )

        # Trust starts neutral and is adjusted by durable signals.
        trust = Decimal("0.5")
        if customer.lifetime_orders >= 10:
            trust += Decimal("0.15")
            if customer.lifetime_orders >= 25:
                trust += Decimal("0.10")
        if customer.account_age_days >= 365:
            trust += Decimal("0.10")
        elif customer.account_age_days <= 7:
            trust -= Decimal("0.20")
            flags.append("new_account")
        if customer.vip_tier:
            trust += Decimal("0.10")
        if customer.chargebacks > 0:
            trust -= min(Decimal("0.25") * customer.chargebacks, Decimal("0.5"))
            flags.append("chargeback_history")
        trust = max(Decimal("0"), min(Decimal("1"), trust))

        return CustomerHistory(
            refund_frequency=refund_frequency,
            refund_intensity=refund_intensity,
            trust_score=trust,
            flags=flags,
        )


@dataclass(slots=True, frozen=True)
class RequestContext:
    """Immutable snapshot of everything the pipeline knows about one request."""

    action: ProposedAction
    agent: AgentIdentity
    customer: CustomerProfile
    order: OrderContext | None
    policy: BrandPolicy
    conversation: tuple[ConversationTurn, ...]
    history: CustomerHistory
    metadata: dict[str, Any]

    # -- convenience accessors used by downstream engines -------------------

    @property
    def amount(self) -> Decimal:
        return self.action.amount

    @property
    def order_total(self) -> Decimal:
        return self.order.total if self.order else Decimal("0")

    @property
    def refund_ratio(self) -> Decimal:
        """Proposed amount as a fraction of the order total (0 if no order)."""
        if self.order_total <= 0:
            return Decimal("0")
        return min(self.amount / self.order_total, Decimal("99"))

    @property
    def recent_customer_messages(self) -> list[str]:
        """Customer-side conversation text, newest first."""
        return [
            turn.content for turn in reversed(self.conversation) if turn.role == "customer"
        ]
