"""Fine-grained agent authorization — WHO may do WHAT, HOW MUCH, HOW OFTEN.

The policy engine decides what the *brand* allows. This module decides what
*this specific agent* is allowed, independent of any policy generosity
(spec §2 fine-grained authorization, §40 agent-to-tool permission graph):

* **deny list** — action types the agent may never request (e.g. a support
  bot must never be able to ask for ``customer_data_export``);
* **amount cap** — hard per-action ceiling across all action types;
* **frequency cap** — agent-level actions/hour ceiling, counted from the
  ``recent_action_counts`` velocity metadata the gateway/API attaches.

Every violation produces a named, auditable :class:`PolicyCheck` and is
**decisive**: a brand cannot accidentally re-authorize an action an agent
is explicitly forbidden from requesting. Fail-closed: malformed metadata
never grants permission, it only skips the frequency estimate.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

from opsonara.core.models import AgentAuthorizationVerdict, PolicyCheck


@dataclass(frozen=True)
class AgentAuthzResult:
    """One fine-grained authorization verdict."""

    verdict: AgentAuthorizationVerdict
    """``allowed=True`` means the gate passed (not that the action is safe —
    policy and risk still run). ``allowed=False`` is decisive (BLOCK)."""

    @property
    def blocked(self) -> bool:
        return not self.verdict.allowed

    def to_policy_check(self) -> PolicyCheck:
        return PolicyCheck(
            name=self.verdict.check_name,
            passed=self.verdict.allowed,
            severity="critical",
            detail=self.verdict.detail,
        )


class AgentAuthorizer:
    """Evaluates per-agent rules before the brand policy engine runs."""

    # Metadata key carrying per-action-type counts for the trailing hour
    # (the same key the blast-radius engine reads).
    _VELOCITY_KEY = "recent_action_counts"

    def authorize(self, request: Any, ctx: Any) -> AgentAuthzResult | None:
        """Return a blocking result, or ``None`` when every gate passes.

        ``request`` is a :class:`~opsonara.firewall.FirewallRequest`, ``ctx``
        a :class:`~opsonara.engines.context.RequestContext`. duck-typed so
        the pipeline stays decoupled.
        """
        agent = request.agent
        action_type = ctx.action.type.value
        denied = agent.denied_actions or frozenset()

        # 1 · deny list — the agent-to-tool permission graph (§40)
        if action_type in denied:
            return AgentAuthzResult(
                AgentAuthorizationVerdict(
                    allowed=False,
                    check_name="agent_denied_action",
                    detail=(
                        f"agent '{agent.id}' is not authorized for action type "
                        f"'{action_type}' (agent deny list)"
                    ),
                )
            )

        # 2 · hard amount ceiling (§2 amount limit)
        cap = agent.max_action_amount
        if cap is not None and ctx.amount > cap:
            return AgentAuthzResult(
                AgentAuthorizationVerdict(
                    allowed=False,
                    check_name="agent_amount_cap",
                    detail=(
                        f"agent '{agent.id}' amount {ctx.amount} exceeds its "
                        f"hard per-action cap {cap}"
                    ),
                )
            )

        # 3 · frequency ceiling (§2 frequency limit) — from gateway-supplied
        # velocity metadata. Malformed metadata fails open *for this check
        # only* (we cannot count what was not supplied); the deny list and
        # amount cap remain fully enforceable.
        rate_cap = agent.max_actions_per_hour
        if rate_cap is not None:
            observed = self._observed_hourly(request.metadata)
            if observed is not None and observed >= rate_cap:
                return AgentAuthzResult(
                    AgentAuthorizationVerdict(
                        allowed=False,
                        check_name="agent_frequency_cap",
                        detail=(
                            f"agent '{agent.id}' already issued {observed} "
                            f"actions in the trailing hour (cap {rate_cap})"
                        ),
                    )
                )

        return None

    def _observed_hourly(self, metadata: dict[str, Any] | None) -> int | None:
        """Sum of trailing-hour action counts from metadata; None if absent.

        Defensive by design: junk values are skipped, and a value that cannot
        be parsed at all yields ``None`` (check skipped) — never an exception
        in the evaluate hot path.
        """
        if not isinstance(metadata, dict):
            return None
        counts = metadata.get(self._VELOCITY_KEY)
        if not isinstance(counts, dict):
            return None
        total = 0
        for value in counts.values():
            if isinstance(value, bool) or value is None:
                continue
            try:
                total += int(Decimal(str(value)))
            except (ValueError, InvalidOperation, ArithmeticError):
                continue
        return total


__all__ = ["AgentAuthzResult", "AgentAuthorizer"]
