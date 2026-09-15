"""Shared fixtures and builders for the Opsonara test suite."""

from __future__ import annotations

from decimal import Decimal

import pytest

from opsonara.core.models import (
    AgentIdentity,
    BrandPolicy,
    ConversationTurn,
    CustomerProfile,
    OrderContext,
    ProposedAction,
)


def make_action(
    type_: str = "refund",
    amount: str = "799",
    order_id: str = "ORD-1",
    customer_id: str = "CUS-1",
    currency: str = "INR",
) -> ProposedAction:
    return ProposedAction(
        type=type_,  # type: ignore[arg-type]
        amount=Decimal(amount),
        currency=currency,
        order_id=order_id,
        customer_id=customer_id,
    )


def make_agent(level: int = 1) -> AgentIdentity:
    return AgentIdentity(id="agt_test", name="TestBot", permission_level=level)


def make_customer(**overrides) -> CustomerProfile:
    base = dict(
        id="CUS-1",
        lifetime_orders=10,
        lifetime_value=Decimal("50000"),
        previous_refunds=1,
        previous_refund_value=Decimal("1000"),
        chargebacks=0,
        account_age_days=365,
        vip_tier=False,
    )
    base.update(overrides)
    return CustomerProfile(**base)


def make_order(**overrides) -> OrderContext:
    base = dict(
        id="ORD-1",
        customer_id="CUS-1",
        status="delivered",
        total=Decimal("5000"),
        currency="INR",
        product_category="electronics",
        created_days_ago=5,
    )
    base.update(overrides)
    return OrderContext(**base)


@pytest.fixture
def default_policy() -> BrandPolicy:
    return BrandPolicy(
        brand_id="brand_test",
        auto_approve_limit=Decimal("2000"),
        low_risk_limit=Decimal("10000"),
        human_review_limit=Decimal("10000"),
        max_refund_ratio=Decimal("1.00"),
        refund_window_days=30,
        max_refunds_per_90d=3,
    )


@pytest.fixture
def trusted_customer() -> CustomerProfile:
    return make_customer()


@pytest.fixture
def sample_order() -> OrderContext:
    return make_order()


@pytest.fixture
def standard_agent() -> AgentIdentity:
    return make_agent(level=1)


def turn(role: str, content: str) -> ConversationTurn:
    return ConversationTurn(role=role, content=content)
