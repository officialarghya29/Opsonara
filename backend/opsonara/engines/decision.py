"""Authorization Decision Engine — "What should happen?"

Combines the Policy Engine's authorization verdict with the Risk Engine's
composite score into the final three-way decision:

  ┌────────────────────────┬───────────────────────────────────────────┐
  │ Outcome                │ Rule                                      │
  ├────────────────────────┼───────────────────────────────────────────┤
  │ 🔴 BLOCK               │ policy DENIED, or composite risk CRITICAL │
  │ 🟡 REVIEW              │ policy REQUIRES_HUMAN, or risk HIGH/      │
  │                        │ MEDIUM, or conditional-band amount        │
  │                        │ without low risk                          │
  │ 🟢 ALLOW               │ policy ALLOWED + risk LOW (+ conditional  │
  │                        │ band explicitly permits low-risk auto)    │
  └────────────────────────┴───────────────────────────────────────────┘

Precedence: BLOCK > REVIEW > ALLOW. Danger always wins over convenience —
an agent can never argue its way past a critical risk score.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from opsonara.core.models import BrandPolicy, Decision, PolicyStatus, RiskBand
from opsonara.engines.policy import POLICY_TO_DECISION
from opsonara.engines.risk import RISK_TO_DECISION


@dataclass(slots=True, frozen=True)
class DecisionResult:
    decision: Decision
    authorization: str
    """'granted' | 'denied' | 'pending_human'."""
    reasons: list[str]


class DecisionEngine:
    """Stateless combiner — one :meth:`decide` call per pipeline run."""

    def decide(
        self,
        *,
        policy_status: PolicyStatus,
        risk_band: RiskBand,
        amount: Decimal,
        policy: BrandPolicy,
        injection_flagged: bool,
    ) -> DecisionResult:
        policy_decision = POLICY_TO_DECISION[policy_status]
        risk_decision = RISK_TO_DECISION[risk_band]

        reasons: list[str] = []

        # ---- 1. hard stops -------------------------------------------------
        # Confirmed manipulation at HIGH severity is itself dangerous: the
        # request may not be what the customer actually wants.
        manipulated_high = injection_flagged and risk_band is RiskBand.HIGH
        if (
            policy_decision is Decision.BLOCK
            or risk_decision is Decision.BLOCK
            or manipulated_high
        ):
            if policy_decision is Decision.BLOCK:
                reasons.append("policy violation: action not authorized by brand rules")
            if risk_decision is Decision.BLOCK:
                reasons.append("critical risk score: action is too dangerous to execute")
            if manipulated_high or (
                injection_flagged and risk_band is RiskBand.CRITICAL
            ):
                reasons.append("possible instruction manipulation detected")
            return DecisionResult(
                decision=Decision.BLOCK,
                authorization="denied",
                reasons=self._dedupe(reasons),
            )

        # ---- 2. anything not clearly safe goes to a human -------------------
        if policy_decision is Decision.REVIEW or risk_decision is Decision.REVIEW:
            if policy_status is PolicyStatus.REQUIRES_HUMAN:
                reasons.append("policy requires human approval for this action/amount")
            if risk_band in (RiskBand.MEDIUM, RiskBand.HIGH):
                reasons.append(f"risk band '{risk_band.value}' exceeds autonomous threshold")
            return DecisionResult(
                decision=Decision.REVIEW,
                authorization="pending_human",
                reasons=self._dedupe(reasons),
            )

        # ---- 3. policy allowed + low risk -----------------------------------
        # The conditional band (auto_approve_limit < amount <= low_risk_limit)
        # is explicitly permitted when risk is low — that is the product's
        # "controlled autonomy" promise.
        if amount > policy.low_risk_limit:
            # Defensive: a misconfigured brand table could create this path.
            reasons.append("amount above the automatic band")
            return DecisionResult(
                decision=Decision.REVIEW,
                authorization="pending_human",
                reasons=self._dedupe(reasons),
            )

        reasons.append(
            f"amount {amount} within authorized band and risk band 'low'"
        )
        return DecisionResult(
            decision=Decision.ALLOW,
            authorization="granted",
            reasons=self._dedupe(reasons),
        )

    @staticmethod
    def _dedupe(items: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for item in items:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out
