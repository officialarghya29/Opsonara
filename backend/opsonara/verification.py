"""Post-execution verification — trust, but verify.

The firewall's job ends when it returns ALLOW; the *platform* then executes
the action. Spec §24's requirement: never stop at ALLOW. If the executor
reports back a different amount than the agent requested (a bug, a race, or
a compromised connector), that mismatch must be detected, audited with
tamper-evidence, and contained.

Usage::

    from opsonara.verification import ExecutionVerifier

    verifier = ExecutionVerifier(audit_store)
    result = verifier.verify(
        request={"action": {"type": "refund", "amount": "1500", ...}},
        execution=executor.execute(request, decision),
        audit_id=verdict.audit_id,
        connector_id="conn_1",
    )
    if result.mismatch:
        ...  # alert / pause agent / incident — result.audit_id has the record
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from opsonara.core.models import AuditRecord, Decision, RiskBand, RiskFactor
from opsonara.core.money import parse_money

# Executor detail keys that commonly carry the executed amount.
_AMOUNT_KEY_RE = re.compile(r"amount|total|value", re.IGNORECASE)

# Actions that carry a financial amount worth verifying.
_FINANCIAL_ACTIONS = {"refund", "discount", "price_override", "payout", "adjustment"}


def _extract_amount(detail: dict[str, Any], *, _depth: int = 0) -> Decimal | None:
    """Best-effort executed-amount extraction from an executor's response.

    Depth-first walk (capped at 6 levels) for the first numeric-looking
    ``amount``/``total``/``value`` field in the response body — e.g.
    ``{"response": {"refund": {"amount": "1500"}}}`` nests three deep.
    Returns ``None`` when nothing amount-like is present — verification then
    reports ``unknown`` rather than guessing.
    """
    if _depth > 6 or not isinstance(detail, dict):
        return None
    for key, value in detail.items():
        if _AMOUNT_KEY_RE.search(str(key)) and not isinstance(value, (dict, list)):
            try:
                return parse_money(value, "executed amount")
            except (ValueError, TypeError):
                continue
    for value in detail.values():
        if isinstance(value, dict):
            nested = _extract_amount(value, _depth=_depth + 1)
            if nested is not None:
                return nested
    return None


@dataclass
class VerificationResult:
    """Outcome of one requested-vs-executed comparison."""

    audit_id: str
    status: str  # verified | mismatch | unknown | unverified
    requested_amount: Decimal | None
    executed_amount: Decimal | None
    difference: Decimal | None
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def mismatch(self) -> bool:
        return self.status == "mismatch"


class ExecutionVerifier:
    """Compares what the agent asked for with what the platform actually did.

    Every verification appends an ``execution_verification`` record to the
    hash-chained audit trail (linked to the original decision via
    ``verification_of``), so mismatches are tamper-evidently on record even
    if someone later edits the platform's response.
    """

    def __init__(self, audit_store: Any, *, tolerance: Decimal = Decimal("0")) -> None:
        self._audit_store = audit_store
        self._tolerance = tolerance
        self._lock = threading.Lock()

    def verify(
        self,
        *,
        request: dict[str, Any],
        execution: dict[str, Any],
        audit_id: str,
        connector_id: str | None = None,
    ) -> VerificationResult:
        # Library-safety: callers may pass None or junk (the API always
        # passes dicts, but this module is importable on its own).
        if not isinstance(request, dict):
            request = {}
        if not isinstance(execution, dict):
            execution = {}
        action = request.get("action", {})
        if not isinstance(action, dict):
            action = {}
        action_type = str(action.get("type", ""))
        requested: Decimal | None = None
        try:
            requested = parse_money(action.get("amount", "0"), "requested amount")
        except (ValueError, TypeError):
            requested = None

        executed = _extract_amount(execution if isinstance(execution, dict) else {})

        status: str
        difference: Decimal | None = None
        if action_type not in _FINANCIAL_ACTIONS:
            status = "unverified"  # non-financial action: nothing to compare
        elif executed is None:
            status = "unknown"  # executor gave no amount-like field (e.g. simulated)
        else:
            difference = abs(executed - requested) if requested is not None else None
            limit = self._tolerance
            status = (
                "verified"
                if difference is not None and difference <= limit
                else "mismatch"
            )

        record = AuditRecord(
            action="execution_verification",
            amount=requested if requested is not None else Decimal("0"),
            currency=str(action.get("currency", "XXX")),
            customer_id=action.get("customer_id"),
            agent_id=str(execution.get("platform", "connector")),
            brand_id=None,
            customer_risk=Decimal("0"),
            injection_risk=Decimal("0"),
            risk_score=Decimal("0") if status == "verified" else Decimal("1"),
            risk_band=RiskBand.LOW if status in ("verified", "unverified", "unknown") else RiskBand.HIGH,
            policy_status="allowed",
            authorization=(
                "granted"
                if status == "verified"
                else ("denied" if status == "mismatch" else "not_applicable")
            ),
            decision=(
                Decision.ALLOW
                if status in ("verified", "unverified", "unknown")
                else Decision.BLOCK
            ),
            reasons=[
                f"requested {requested if requested is not None else 'n/a'} vs "
                f"executed {executed if executed is not None else 'n/a'}: {status}",
            ],
            policy_checks=[],
            risk_factors=[
                RiskFactor(
                    name="execution_mismatch",
                    score=Decimal("0") if difference is None else min(difference / (requested or Decimal("1")), Decimal("1")),
                    weight=Decimal("1"),
                    detail=(
                        f"difference {difference}"
                        if difference is not None
                        else "no executed amount reported"
                    ),
                )
            ],
            verification_of=audit_id,
            connector_id=connector_id,
        )
        with self._lock:
            verification_audit_id = self._audit_store.append(record)

        return VerificationResult(
            audit_id=verification_audit_id,
            status=status,
            requested_amount=requested,
            executed_amount=executed,
            difference=difference,
            detail={
                "connector_id": connector_id,
                "decision_audit_id": audit_id,
                "execution": execution,
            },
        )


__all__ = ["ExecutionVerifier", "VerificationResult"]
