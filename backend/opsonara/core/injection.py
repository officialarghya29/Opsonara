"""Prompt-injection and instruction-manipulation detector.

This module is deliberately transparent: it uses a fixed, versioned catalogue
of linguistic attack patterns rather than a black-box classifier, so every
signal in the audit trail can be explained and unit-tested.

It evaluates ONLY customer-side conversation turns. Scanning the agent's own
output or tool metadata would conflate agent behaviour with customer
manipulation — agent behaviour is scored separately by the risk engine.

Detection is one component of the broader transaction-risk system, not the
whole firewall: a flagged conversation raises the composite risk score, which
then combines with policy status at decision time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from decimal import Decimal

__all__ = ["InjectionReport", "analyze_conversation"]


@dataclass(slots=True, frozen=True)
class _Pattern:
    """One named attack pattern with its contribution to the total score."""

    name: str
    keywords: tuple[str, ...]
    weight: Decimal


# The pattern catalogue. Sorted by declaration order; deterministic.
_PATTERNS: tuple[_Pattern, ...] = (
    _Pattern(
        name="instruction_override",
        keywords=("ignore previous instructions", "ignore your instructions",
                  "ignore your previous instructions", "ignore all previous",
                  "ignore your previous", "disregard previous", "disregard your",
                  "disregard your previous", "forget your instructions",
                  "forget all previous", "forget your previous"),
        weight=Decimal("0.40"),
    ),
    _Pattern(
        name="role_hijack",
        keywords=("you are now", "new instructions", "you must comply",
                  "act as", "pretend to be", "from now on you"),
        weight=Decimal("0.30"),
    ),
    _Pattern(
        name="false_authority",
        keywords=("authorized by the manager", "authorised by the manager",
                  "manager said", "boss said", "i am the manager",
                  "i am the ceo", "on behalf of management", "special permission",
                  "i have permission", "this is an emergency"),
        weight=Decimal("0.30"),
    ),
    _Pattern(
        name="audit_lobby",
        keywords=("just refund", "only refund", "no need to check",
                  "without checking", "skip the", "don't check",
                  "bypass the", "expedite the refund", "don't ask questions"),
        weight=Decimal("0.20"),
    ),
    _Pattern(
        name="urgent_pressure",
        keywords=("urgent", "immediately", "right now", "asap", "last warning",
                  "before i", "or i will", "legal action", "police"),
        weight=Decimal("0.10"),
    ),
    _Pattern(
        name="context_switch",
        keywords=("system message", "system prompt", "developer mode",
                  "admin mode", "sudo", "new policy allows"),
        weight=Decimal("0.25"),
    ),
)

def _word_boundary_regex(keyword: str) -> str:
    """Match a keyword at token boundaries so "system" inside "ecosystem"
    does not false-positive."""
    parts = [re.escape(w) for w in keyword.split()]
    return r"\b" + r"\s+".join(parts) + r"\b"


# Compiled pattern catalogue: pattern name -> regex over its keywords.
_COMPILED: dict[str, re.Pattern[str]] = {
    pattern.name: re.compile(
        r"|".join(_word_boundary_regex(kw) for kw in pattern.keywords),
        re.IGNORECASE,
    )
    for pattern in _PATTERNS
}


@dataclass(slots=True)
class InjectionReport:
    """Result of scanning one conversation for injection attempts."""

    verdict: str
    """'clean' | 'suspicious' | 'injected'."""
    score: Decimal
    """0.0 .. 1.0, monotonic in matched pattern weights."""
    matched_patterns: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    scanned_messages: int = 0

    @property
    def is_flagged(self) -> bool:
        return self.verdict != "clean"


def analyze_conversation(conversation) -> InjectionReport:  # noqa: ANN001
    """Scan customer-side turns and return an :class:`InjectionReport`.

    Score semantics: each *distinct* pattern contributes its weight once
    (repetition does not stack). Urgent-pressure contributes half weight on
    its own — it is common in legitimate complaints and only meaningful when
    other manipulation signals co-occur.
    """
    customer_messages = [t.content for t in conversation if getattr(t, "role", "") == "customer"]
    report = InjectionReport(verdict="clean", score=Decimal("0"), scanned_messages=len(customer_messages))

    if not customer_messages:
        return report

    hits: dict[str, list[str]] = {}
    for name, regex in _COMPILED.items():
        for msg in customer_messages:
            m = regex.search(msg)
            if m:
                hits.setdefault(name, []).append(m.group(0))
                break  # one evidence snippet per pattern is enough

    score = Decimal("0")
    for pattern in _PATTERNS:
        if pattern.name in hits:
            score += pattern.weight
    # Solo urgent-pressure is weak evidence; halve it when nothing else fired.
    if hits.keys() == {"urgent_pressure"}:
        score = Decimal("0.05")

    score = min(score, Decimal("1"))

    if score >= Decimal("0.40"):
        verdict = "injected"
    elif score > Decimal("0"):
        verdict = "suspicious"
    else:
        verdict = "clean"

    return InjectionReport(
        verdict=verdict,
        score=score,
        matched_patterns=sorted(hits.keys()),
        evidence=[f"{name}: “{snips[0]}”" for name, snips in sorted(hits.items())],
        scanned_messages=len(customer_messages),
    )
