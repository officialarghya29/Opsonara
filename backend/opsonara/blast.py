"""Blast-radius engine — "if this action is wrong, how bad is it?" (spec §19, §40).

Risk scoring answers *how likely* something is to go wrong; blast radius
answers *how much damage* it could do. A ₹500 refund and a ₹50,000 refund can
carry the same risk score, but their maximum impact differs by 100×.

The engine derives, per evaluated action:

* **direct exposure** — the action's own amount;
* **amplification** — how often this agent could repeat the action within the
  policy windows (requests/hour when the brand provides velocity metadata);
* **maximum hourly exposure** — direct × amplification, the number a kill
  switch decision hinges on;
* **blast-radius band** — LOW / MEDIUM / HIGH / CRITICAL against the brand's
  policy limits.

It is deliberately deterministic and explainable: every number traces to a
policy field or a request fact, and it lands in the audit record + API
response so dashboards can aggregate "autonomous exposure" (§40) directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum

from opsonara.engines.context import RequestContext

# Assumed repetition ceiling when the brand supplies no velocity metadata:
# a compromised agent loop is not limited by humans, so this is deliberately
# generous (it is a *maximum* impact estimate, not a forecast).
_DEFAULT_REPEATS_PER_HOUR = Decimal("60")

# Velocity metadata is a *rate*, not money — clamp it so garbage (or hostile)
# metadata like "1e40" can neither inflate the estimate nor overflow the
# quantize() decimal context when multiplied by the amount.
_MAX_REPEATS_PER_HOUR = Decimal("100000")

# Metadata key the API/SDK may set: recent actions of this type in the last
# hour, e.g. {"recent_action_counts": {"refund": 40}}.
_VELOCITY_KEY = "recent_action_counts"


class BlastBand(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class BlastRadius:
    """Explainable maximum-impact estimate for one evaluated action."""

    direct_exposure: Decimal
    """The action's own amount."""
    repeats_per_hour: Decimal
    """How often this agent could repeat the action in an hour."""
    max_hourly_exposure: Decimal
    """direct × repeats — the kill-switch-relevant number."""
    band: BlastBand
    reason: str
    """Human-readable derivation (lands in the audit trail)."""

    def to_dict(self) -> dict[str, object]:
        return {
            "direct_exposure": str(self.direct_exposure),
            "repeats_per_hour": str(self.repeats_per_hour),
            "max_hourly_exposure": str(self.max_hourly_exposure),
            "band": self.band.value,
            "reason": self.reason,
        }


class BlastRadiusEngine:
    """Deterministic maximum-impact estimator, evaluated alongside risk."""

    def evaluate(self, ctx: RequestContext) -> BlastRadius:
        amount = ctx.amount
        counts = (
            ctx.metadata.get(_VELOCITY_KEY, {}) if isinstance(ctx.metadata, dict) else {}
        )
        observed = counts.get(ctx.action.type.value) if isinstance(counts, dict) else None
        try:
            observed_n = Decimal(str(observed)) if observed is not None else None
        except (ValueError, TypeError, ArithmeticError):  # defensive: garbage metadata
            observed_n = None

        if observed_n is not None and observed_n > 0:
            repeats = min(observed_n, _MAX_REPEATS_PER_HOUR)
            velocity_source = f"observed velocity {observed_n}/h from request metadata"
        else:
            repeats = _DEFAULT_REPEATS_PER_HOUR
            velocity_source = f"default amplification {repeats}/h (no velocity data)"

        # A hostile velocity value could still slip past the clamp if it is
        # not a number at all (Decimal("abc") raises ArithmeticError, not
        # ValueError) — fall back to the conservative default rather than
        # crashing the evaluate path.
        try:
            max_hourly = (amount * repeats).quantize(Decimal("0.01"))
        except ArithmeticError:
            repeats = _DEFAULT_REPEATS_PER_HOUR
            max_hourly = (amount * repeats).quantize(Decimal("0.01"))

        # Bands anchored to the brand's own limits: CRITICAL when one wrong
        # hour could exceed 10× the human-review limit, HIGH above the review
        # limit, MEDIUM above the auto-approve limit.
        review = ctx.policy.human_review_limit
        auto = ctx.policy.auto_approve_limit
        catastrophic = review * Decimal("10")

        if max_hourly >= catastrophic:
            band, reason = BlastBand.CRITICAL, (
                f"max hourly exposure {max_hourly} reaches the catastrophic "
                f"threshold {catastrophic} (10× review limit) ({velocity_source})"
            )
        elif max_hourly >= review:
            band, reason = BlastBand.HIGH, (
                f"max hourly exposure {max_hourly} reaches the human-review "
                f"limit {review} ({velocity_source})"
            )
        elif max_hourly > auto:
            band, reason = BlastBand.MEDIUM, (
                f"max hourly exposure {max_hourly} exceeds the auto-approve "
                f"limit {auto} ({velocity_source})"
            )
        else:
            band, reason = BlastBand.LOW, (
                f"max hourly exposure {max_hourly} stays within the "
                f"auto-approve limit {auto} ({velocity_source})"
            )

        return BlastRadius(
            direct_exposure=amount,
            repeats_per_hour=repeats,
            max_hourly_exposure=max_hourly,
            band=band,
            reason=reason,
        )


__all__ = ["BlastBand", "BlastRadius", "BlastRadiusEngine"]
