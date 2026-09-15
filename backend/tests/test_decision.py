"""Tests for the Decision Engine combination matrix."""

from __future__ import annotations

from decimal import Decimal

from opsonara.core.models import BrandPolicy, Decision, PolicyStatus, RiskBand
from opsonara.engines.decision import DecisionEngine


def policy(low_risk: str = "10000") -> BrandPolicy:
    return BrandPolicy(
        brand_id="b",
        auto_approve_limit=Decimal("2000"),
        low_risk_limit=Decimal(low_risk),
        human_review_limit=Decimal(low_risk),
    )


def decide(policy_status, risk_band, amount="799", injection=False):
    return DecisionEngine().decide(
        policy_status=policy_status,
        risk_band=risk_band,
        amount=Decimal(amount),
        policy=policy(),
        injection_flagged=injection,
    )


class TestBlock:
    def test_policy_denied_blocks_even_at_low_risk(self):
        result = decide(PolicyStatus.DENIED, RiskBand.LOW)
        assert result.decision is Decision.BLOCK
        assert result.authorization == "denied"

    def test_critical_risk_blocks_even_when_allowed(self):
        result = decide(PolicyStatus.ALLOWED, RiskBand.CRITICAL)
        assert result.decision is Decision.BLOCK
        assert "critical risk" in " ".join(result.reasons).lower()

    def test_injection_mentioned_on_high_block(self):
        result = decide(PolicyStatus.ALLOWED, RiskBand.HIGH, injection=True)
        assert result.decision is Decision.BLOCK
        assert any("manipulation" in r for r in result.reasons)


class TestReview:
    def test_requires_human_policy_reviews(self):
        result = decide(PolicyStatus.REQUIRES_HUMAN, RiskBand.LOW)
        assert result.decision is Decision.REVIEW
        assert result.authorization == "pending_human"

    def test_medium_risk_reviews(self):
        result = decide(PolicyStatus.ALLOWED, RiskBand.MEDIUM)
        assert result.decision is Decision.REVIEW

    def test_high_risk_reviews(self):
        result = decide(PolicyStatus.ALLOWED, RiskBand.HIGH)
        assert result.decision is Decision.REVIEW


class TestAllow:
    def test_low_risk_allowed_policy_allows(self):
        result = decide(PolicyStatus.ALLOWED, RiskBand.LOW)
        assert result.decision is Decision.ALLOW
        assert result.authorization == "granted"

    def test_conditional_band_low_risk_allows(self):
        # The controlled-autonomy promise: mid-size amounts auto-approve
        # when every signal is clean.
        result = decide(PolicyStatus.ALLOWED, RiskBand.LOW, amount="4500")
        assert result.decision is Decision.ALLOW


class TestPrecedence:
    def test_block_beats_review(self):
        result = decide(PolicyStatus.REQUIRES_HUMAN, RiskBand.CRITICAL)
        assert result.decision is Decision.BLOCK

    def test_review_beats_allow(self):
        result = decide(PolicyStatus.REQUIRES_HUMAN, RiskBand.MEDIUM)
        assert result.decision is Decision.REVIEW

    def test_reasons_are_deduped(self):
        result = decide(PolicyStatus.DENIED, RiskBand.CRITICAL)
        assert len(result.reasons) == len(set(result.reasons))
