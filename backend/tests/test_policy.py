"""Tests for the Policy Engine."""

from __future__ import annotations

from opsonara.engines.context import ContextEngine
from opsonara.engines.policy import PolicyEngine
from tests.conftest import make_action, make_agent, make_customer, make_order, turn


def build_ctx(action, agent, customer, order, policy, conversation=None):
    return ContextEngine().build(
        action=action,
        agent=agent,
        customer=customer,
        order=order,
        policy=policy,
        conversation=conversation or [],
    )


def evaluate(ctx):
    return PolicyEngine().evaluate(ctx)


class TestAgentPermission:
    def test_sufficient_permission_passes(self, default_policy):
        ctx = build_ctx(make_action(), make_agent(1), make_customer(), make_order(), default_policy)
        assert evaluate(ctx).status.value == "allowed"

    def test_insufficient_permission_is_denied(self, default_policy):
        policy = default_policy.model_copy(update={"min_permission_level": 2})
        ctx = build_ctx(make_action(), make_agent(1), make_customer(), make_order(), policy)
        result = evaluate(ctx)
        assert result.status.value == "denied"
        check = next(c for c in result.checks if c.name == "agent_permission")
        assert not check.passed


class TestSpendingBands:
    def test_within_auto_approve_passes(self, default_policy):
        ctx = build_ctx(make_action(amount="799"), make_agent(), make_customer(), make_order(total="799"), default_policy)
        check = next(c for c in evaluate(ctx).checks if c.name == "spending_band")
        assert check.passed

    def test_conditional_band_is_info(self, default_policy):
        ctx = build_ctx(make_action(amount="4500"), make_agent(), make_customer(), make_order(total="5000"), default_policy)
        check = next(c for c in evaluate(ctx).checks if c.name == "spending_band")
        assert not check.passed
        assert check.severity == "info"

    def test_above_low_risk_requires_human(self, default_policy):
        ctx = build_ctx(make_action(amount="15000"), make_agent(), make_customer(), make_order(total="20000"), default_policy)
        result = evaluate(ctx)
        check = next(c for c in result.checks if c.name == "spending_band")
        assert check.severity == "warning"
        assert result.status.value == "requires_human"


class TestRefundRatio:
    def test_full_refund_allowed(self, default_policy):
        ctx = build_ctx(make_action(amount="5000"), make_agent(), make_customer(), make_order(total="5000"), default_policy)
        check = next(c for c in evaluate(ctx).checks if c.name == "refund_ratio")
        assert check.passed

    def test_over_refund_denied(self, default_policy):
        ctx = build_ctx(make_action(amount="9000"), make_agent(), make_customer(), make_order(total="2500"), default_policy)
        result = evaluate(ctx)
        assert result.status.value == "denied"
        check = next(c for c in result.checks if c.name == "refund_ratio")
        assert not check.passed

    def test_not_applicable_to_discount(self, default_policy):
        ctx = build_ctx(make_action(type_="discount", amount="500"), make_agent(), make_customer(), make_order(), default_policy)
        check = next(c for c in evaluate(ctx).checks if c.name == "refund_ratio")
        assert check.detail == "not applicable"


class TestRefundWindow:
    def test_within_window_passes(self, default_policy):
        ctx = build_ctx(make_action(), make_agent(), make_customer(), make_order(created_days_ago=29), default_policy)
        check = next(c for c in evaluate(ctx).checks if c.name == "refund_window")
        assert check.passed

    def test_outside_window_denied(self, default_policy):
        ctx = build_ctx(make_action(), make_agent(), make_customer(), make_order(created_days_ago=45), default_policy)
        result = evaluate(ctx)
        assert result.status.value == "denied"


class TestCancellation:
    def test_cancel_before_ship_allowed(self, default_policy):
        ctx = build_ctx(make_action(type_="cancel_order"), make_agent(), make_customer(), make_order(status="processing"), default_policy)
        check = next(c for c in evaluate(ctx).checks if c.name == "cancel_policy")
        assert check.passed

    def test_cancel_after_ship_denied(self, default_policy):
        ctx = build_ctx(make_action(type_="cancel_order"), make_agent(), make_customer(), make_order(status="shipped"), default_policy)
        result = evaluate(ctx)
        assert result.status.value == "denied"

    def test_cancel_after_ship_allowed_when_policy_enables(self, default_policy):
        policy = default_policy.model_copy(update={"allow_cancel_after_ship": True})
        ctx = build_ctx(make_action(type_="cancel_order"), make_agent(), make_customer(), make_order(status="shipped"), policy)
        check = next(c for c in evaluate(ctx).checks if c.name == "cancel_policy")
        assert check.passed


class TestRefundFrequency:
    def test_at_cap_denied(self, default_policy):
        customer = make_customer(previous_refunds=3)
        ctx = build_ctx(make_action(), make_agent(), customer, make_order(), default_policy)
        result = evaluate(ctx)
        assert result.status.value == "denied"

    def test_within_cap_passes(self, default_policy):
        customer = make_customer(previous_refunds=2)
        ctx = build_ctx(make_action(), make_agent(), customer, make_order(), default_policy)
        check = next(c for c in evaluate(ctx).checks if c.name == "refund_frequency")
        assert check.passed


class TestChargebacks:
    def test_chargeback_blocks_money_actions(self, default_policy):
        customer = make_customer(chargebacks=1)
        ctx = build_ctx(make_action(type_="refund", amount="500"), make_agent(), customer, make_order(total="5000"), default_policy)
        result = evaluate(ctx)
        assert result.status.value == "denied"

    def test_chargeback_allows_non_monetary(self, default_policy):
        customer = make_customer(chargebacks=1)
        ctx = build_ctx(make_action(type_="update_shipping", amount="0"), make_agent(), customer, make_order(), default_policy)
        assert evaluate(ctx).status.value == "allowed"


class TestDiscountCap:
    def test_discount_within_cap(self, default_policy):
        ctx = build_ctx(make_action(type_="discount", amount="500"), make_agent(), make_customer(), make_order(total="5000"), default_policy)
        check = next(c for c in evaluate(ctx).checks if c.name == "discount_cap")
        assert check.passed

    def test_discount_over_cap_denied(self, default_policy):
        ctx = build_ctx(make_action(type_="discount", amount="2000"), make_agent(), make_customer(), make_order(total="5000"), default_policy)
        result = evaluate(ctx)
        assert result.status.value == "denied"


class TestCurrencyIntegrity:
    def test_currency_mismatch_denied(self, default_policy):
        action = make_action(amount="799", currency="USD")
        order = make_order(currency="INR", total="799")
        ctx = build_ctx(action, make_agent(), make_customer(), order, default_policy)
        result = evaluate(ctx)
        assert result.status.value == "denied"


class TestAlwaysReview:
    def test_price_override_always_flagged(self, default_policy):
        ctx = build_ctx(make_action(type_="price_override", amount="100"), make_agent(), make_customer(), make_order(total="5000"), default_policy)
        result = evaluate(ctx)
        assert result.status.value == "requires_human"


class TestConversation:
    def test_customer_turns_reach_engines(self, default_policy):
        conv = [turn("customer", "please refund"), turn("agent", "ok")]
        ctx = build_ctx(make_action(), make_agent(), make_customer(), make_order(), default_policy, conv)
        assert ctx.recent_customer_messages == ["please refund"]
