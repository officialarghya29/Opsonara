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
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

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


# Precomputed keyword catalogue: each keyword maps directly to the pattern
# that owns it. This lets the scanner do ONE regex pass per message and an
# O(1) dict lookup per hit, instead of re-running every pattern's regex over
# every message (which made cost grow linearly with the pattern catalogue).
_KEYWORD_WEIGHTS: dict[str, tuple[str, Decimal]] = {
    keyword: (pattern.name, pattern.weight)
    for pattern in _PATTERNS
    for keyword in pattern.keywords
}

_ALL_KEYWORDS_RE: re.Pattern[str] = re.compile(
    r"|".join(_word_boundary_regex(keyword) for keyword in _KEYWORD_WEIGHTS),
    re.IGNORECASE,
)

# Solo urgent-pressure is weak evidence; it contributes only this fraction
# of its weight when no other pattern fired (see analyze_conversation).
_SOLO_PRESSURE_FACTOR = Decimal("0.5")


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


# Characters invisible or confusable in typical chat rendering. Stripping
# them closes the classic evasion where "ignore" is written as "ig\u200bore".
_INVISIBLE_RE = re.compile(
    r"[\u200b\u200c\u200d\u2060\ufeff\u00ad]"
)


def _normalize_message(message: str) -> str:
    """Canonicalize a message for matching.

    1. NFKC folds lookalike alphabets (full-width ``\uff49`` -> ``i``,
       circled letters, ligatures) back to ASCII-compatible forms.
    2. Invisible characters (zero-width space/joiner, word joiner,
       BOM, soft hyphen) are stripped entirely.
    Whitespace collapsing happens per-keyword at match time.
    """
    folded = unicodedata.normalize("NFKC", message)
    return _INVISIBLE_RE.sub("", folded)


def analyze_conversation(conversation: Sequence[Any]) -> InjectionReport:
    """Scan customer-side turns and return an :class:`InjectionReport`.

    Inputs are Unicode-normalized (NFKC) and stripped of invisible
    characters before matching, closing homoglyph and zero-width
    evasion vectors.

    Score semantics: each *distinct* pattern contributes its weight once
    (repetition does not stack). Urgent-pressure contributes half weight on
    its own — it is common in legitimate complaints and only meaningful when
    other manipulation signals co-occur.

    Complexity: one regex pass over each customer message plus an O(1) dict
    lookup per keyword hit — independent of the size of the pattern
    catalogue.
    """
    customer_messages = [
        _normalize_message(t.content)
        for t in conversation
        if getattr(t, "role", "") == "customer"
    ]

    if not customer_messages:
        return InjectionReport(verdict="clean", score=Decimal("0"), scanned_messages=0)

    hits: dict[str, list[str]] = {}
    for msg in customer_messages:
        for m in _ALL_KEYWORDS_RE.finditer(msg):
            keyword = m.group(0).lower()
            # Collapse whitespace so multi-word hits canonicalize correctly.
            keyword = " ".join(keyword.split())
            name_and_weight = _KEYWORD_WEIGHTS.get(keyword)
            if name_and_weight is None:
                # Regex is case-insensitive; the literal keyword must exist.
                continue
            name, _weight = name_and_weight
            if name not in hits:
                hits[name] = [m.group(0)]

    score = Decimal("0")
    for pattern in _PATTERNS:
        if pattern.name in hits:
            score += pattern.weight
    # Solo urgent-pressure is weak evidence; halve it when nothing else fired.
    if hits.keys() == {"urgent_pressure"}:
        score *= _SOLO_PRESSURE_FACTOR

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
