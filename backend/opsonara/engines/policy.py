"""Policy Engine — "Is the agent allowed to do this?"

Enforces declarative brand authorization (:class:`BrandPolicy`) for AI-agent
actions: spending limits, refund ratios and windows, cancellation rules,
agent permission levels, customer-history caps, and currency integrity.

Every rule that runs produces a named :class:`PolicyCheck` so the audit trail
can answer *which policy allowed or denied this*.

Severity semantics
------------------
critical  → any failure forces overall DENIED (BLOCK).
warning   → any failure forces REQUIRES_HUMAN (REVIEW).
info      → failure alone does not gate; combined with risk at decision time.
"""

from __future__ import annotations

from decimal import Decimal

from opsonara.core.models import (
    ALWAYS_REVIEW_ACTIONS,
    ActionType,
    Decision,
    PolicyCheck,
    PolicyResult,
    PolicyStatus,
)

# Actions evaluated against refund-style customer caps.
REFUND_LIKE: frozenset[ActionType] = frozenset(
    {ActionType.REFUND, ActionType.STORE_CREDIT}
)

_SHIPPED_STATES = frozenset({"shipped", "delivered", "completed"})


class PolicyEngine:
    """Stateless rule evaluator — one :meth:`evaluate` call per decision."""

    def evaluate(self, ctx) -> PolicyResult:  # noqa: ANN001 - RequestContext
        checks: list[PolicyCheck] = []

        checks.append(self._check_agent_permission(ctx))
        checks.append(self._check_spending_band(ctx))
        checks.append(self._check_refund_ratio(ctx))
        checks.append(self._check_refund_window(ctx))
        checks.append(self._check_cancellation(ctx))
        checks.append(self._check_refund_frequency(ctx))
        checks.append(self._check_chargebacks(ctx))
        checks.append(self._check_account_age(ctx))
        checks.append(self._check_discount_cap(ctx))
        checks.append(self._check_currency(ctx))
        checks.append(self._check_always_review(ctx))

        if any(c.severity == "critical" and not c.passed for c in checks):
            status = PolicyStatus.DENIED
        elif any(c.severity == "warning" and not c.passed for c in checks):
            status = PolicyStatus.REQUIRES_HUMAN
        else:
            status = PolicyStatus.ALLOWED

        return PolicyResult(status=status, checks=checks)

    # ------------------------------------------------------------------
    # individual rules
    # ------------------------------------------------------------------

    def _check_agent_permission(self, ctx) -> PolicyCheck:
        required = ctx.policy.min_permission_level
        actual = ctx.agent.permission_level
        ok = actual >= required
        return PolicyCheck(
            name="agent_permission",
            passed=ok,
            severity="critical",
            detail=(
                f"agent permission {actual} meets required level {required}"
                if ok
                else f"agent permission {actual} below required level {required}"
            ),
        )

    def _check_spending_band(self, ctx) -> PolicyCheck:
        p, amount = ctx.policy, ctx.amount
        if amount > p.human_review_limit:
            return PolicyCheck(
                name="spending_band",
                passed=False,
                severity="warning",
                detail=(
                    f"amount {amount} {ctx.action.currency} exceeds human-review "
                    f"limit {p.human_review_limit} — manual approval required"
                ),
            )
        if amount > p.low_risk_limit:
            return PolicyCheck(
                name="spending_band",
                passed=False,
                severity="warning",
                detail=(
                    f"amount {amount} {ctx.action.currency} exceeds the automatic "
                    f"band ({p.low_risk_limit}) — manual approval required"
                ),
            )
        if amount > p.auto_approve_limit:
            return PolicyCheck(
                name="spending_band",
                passed=False,
                severity="info",
                detail=(
                    f"amount {amount} {ctx.action.currency} is in the conditional band "
                    f"({p.auto_approve_limit}–{p.low_risk_limit}) — agent may approve "
                    f"only when risk is low"
                ),
            )
        return PolicyCheck(
            name="spending_band",
            passed=True,
            detail=f"amount {amount} {ctx.action.currency} within auto-approve limit "
            f"{p.auto_approve_limit}",
        )

    def _is_conditional_band(self, ctx) -> bool:
        return ctx.policy.auto_approve_limit < ctx.amount <= ctx.policy.low_risk_limit

    def _check_refund_ratio(self, ctx) -> PolicyCheck:
        if ctx.action.type not in REFUND_LIKE or ctx.order is None:
            return PolicyCheck(
                name="refund_ratio", passed=True, detail="not applicable"
            )
        max_allowed = ctx.order.total * ctx.policy.max_refund_ratio
        if ctx.amount > max_allowed:
            return PolicyCheck(
                name="refund_ratio",
                passed=False,
                severity="critical",
                detail=(
                    f"requested {ctx.amount} exceeds max allowed refund "
                    f"{max_allowed} ({ctx.policy.max_refund_ratio} of order total "
                    f"{ctx.order.total})"
                ),
            )
        return PolicyCheck(
            name="refund_ratio",
            passed=True,
            detail=f"requested {ctx.amount} within max refund {max_allowed}",
        )

    def _check_refund_window(self, ctx) -> PolicyCheck:
        if ctx.action.type not in REFUND_LIKE or ctx.order is None:
            return PolicyCheck(
                name="refund_window", passed=True, detail="not applicable"
            )
        days = ctx.order.created_days_ago
        window = ctx.policy.refund_window_days
        if days > window:
            return PolicyCheck(
                name="refund_window",
                passed=False,
                severity="critical",
                detail=(
                    f"order is {days} days old, outside the {window}-day refund window"
                ),
            )
        return PolicyCheck(
            name="refund_window",
            passed=True,
            detail=f"order age {days}d within the {window}-day window",
        )

    def _check_cancellation(self, ctx) -> PolicyCheck:
        if ctx.action.type is not ActionType.CANCEL_ORDER:
            return PolicyCheck(
                name="cancel_policy", passed=True, detail="not applicable"
            )
        if ctx.order is None:
            return PolicyCheck(
                name="cancel_policy",
                passed=False,
                severity="critical",
                detail="cannot cancel an order without order context",
            )
        if ctx.order.status in _SHIPPED_STATES and not ctx.policy.allow_cancel_after_ship:
            return PolicyCheck(
                name="cancel_policy",
                passed=False,
                severity="critical",
                detail=f"order already '{ctx.order.status}' and cancellation after "
                "shipment is disabled",
            )
        return PolicyCheck(
            name="cancel_policy",
            passed=True,
            detail=f"cancellation permitted for order in '{ctx.order.status}'",
        )

    def _check_refund_frequency(self, ctx) -> PolicyCheck:
        if ctx.action.type not in REFUND_LIKE:
            return PolicyCheck(
                name="refund_frequency", passed=True, detail="not applicable"
            )
        cap = ctx.policy.max_refunds_per_90d
        if ctx.customer.previous_refunds >= cap:
            return PolicyCheck(
                name="refund_frequency",
                passed=False,
                severity="critical",
                detail=(
                    f"customer already has {ctx.customer.previous_refunds} refunds, "
                    f"at/above the {cap}-per-90d cap"
                ),
            )
        return PolicyCheck(
            name="refund_frequency",
            passed=True,
            detail=f"customer refunds {ctx.customer.previous_refunds}/{cap} within cap",
        )

    def _check_chargebacks(self, ctx) -> PolicyCheck:
        if ctx.customer.chargebacks <= 0 or not ctx.policy.block_chargeback_history:
            return PolicyCheck(
                name="chargeback_history", passed=True, detail="not applicable"
            )
        if ctx.action.type in REFUND_LIKE or ctx.action.type is ActionType.DISCOUNT:
            return PolicyCheck(
                name="chargeback_history",
                passed=False,
                severity="critical",
                detail=(
                    f"customer has {ctx.customer.chargebacks} chargeback(s); policy "
                    f"blocks monetary actions for chargeback accounts"
                ),
            )
        return PolicyCheck(
            name="chargeback_history", passed=True, detail="not applicable"
        )

    def _check_account_age(self, ctx) -> PolicyCheck:
        min_age = ctx.policy.min_account_age_days
        if ctx.customer.account_age_days >= min_age:
            detail = (
                "not applicable"
                if min_age == 0
                else f"account age {ctx.customer.account_age_days}d >= {min_age}d"
            )
            return PolicyCheck(name="account_age", passed=True, detail=detail)
        if ctx.amount > ctx.policy.auto_approve_limit:
            return PolicyCheck(
                name="account_age",
                passed=False,
                severity="warning",
                detail=(
                    f"account is {ctx.customer.account_age_days}d old (minimum "
                    f"{min_age}d) with a high-value action — manual review"
                ),
            )
        return PolicyCheck(
            name="account_age",
            passed=True,
            detail="young account but low-value action",
        )

    def _check_discount_cap(self, ctx) -> PolicyCheck:
        if ctx.action.type is not ActionType.DISCOUNT:
            return PolicyCheck(
                name="discount_cap", passed=True, detail="not applicable"
            )
        base = ctx.order.total if ctx.order else Decimal("0")
        if base <= 0:
            return PolicyCheck(
                name="discount_cap",
                passed=False,
                severity="critical",
                detail="discount proposed without order context",
            )
        pct = (ctx.amount / base * Decimal("100")).quantize(Decimal("0.01"))
        if pct > ctx.policy.max_discount_pct:
            return PolicyCheck(
                name="discount_cap",
                passed=False,
                severity="critical",
                detail=f"discount {pct}% exceeds the {ctx.policy.max_discount_pct}% cap",
            )
        return PolicyCheck(
            name="discount_cap",
            passed=True,
            detail=f"discount {pct}% within the {ctx.policy.max_discount_pct}% cap",
        )

    def _check_currency(self, ctx) -> PolicyCheck:
        if ctx.order is None or ctx.action.currency == ctx.order.currency:
            detail = (
                "not applicable"
                if ctx.order is None
                else f"currency {ctx.action.currency} matches order"
            )
            return PolicyCheck(name="currency_integrity", passed=True, detail=detail)
        return PolicyCheck(
            name="currency_integrity",
            passed=False,
            severity="critical",
            detail=(
                f"action currency {ctx.action.currency} does not match order "
                f"currency {ctx.order.currency} — possible tampering"
            ),
        )

    def _check_always_review(self, ctx) -> PolicyCheck:
        if ctx.action.type not in ALWAYS_REVIEW_ACTIONS:
            return PolicyCheck(
                name="sensitive_action", passed=True, detail="not applicable"
            )
        return PolicyCheck(
            name="sensitive_action",
            passed=False,
            severity="warning",
            detail=f"'{ctx.action.type.value}' is a sensitive action type; "
            "always routed to a human",
        )


# Decision-space export used by the decision combiner's documentation.
POLICY_TO_DECISION: dict[PolicyStatus, Decision] = {
    PolicyStatus.ALLOWED: Decision.ALLOW,
    PolicyStatus.REQUIRES_HUMAN: Decision.REVIEW,
    PolicyStatus.DENIED: Decision.BLOCK,
}
