"""Learning loop — make the risk engine learn from human outcomes.

Pipeline: decision → human review verdict → outcome log → per-brand
recalibration of signal weights → shadow evaluation → promotion.

Design constraints (deliberate):

* **Explainable, bounded** — recalibrated weights stay within a clamp of
  the global defaults (``±MAX_DRIFT``); no black-box step.
* **Every weight change is auditable** — promotions are returned as facts
  the caller must append to the audit trail, so model drift is itself
  part of the tamper-evident log.
* **Shadow before promotion** — a candidate weight set runs silently
  alongside production for N decisions; it is only promotable once it
  agrees with human verdicts on at least ``shadow_min_win_rate`` of a
  minimum number of samples.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import ROUND_HALF_EVEN, Decimal
from typing import Any

from opsonara.config import settings

# Signal names in canonical order — matches RiskEngine factors.
SIGNALS: tuple[str, ...] = (
    "value_size",
    "customer_history",
    "injection",
    "behavioral",
    "action_sensitivity",
)

# Global defaults mirror RiskEngine's compile-time weights.
DEFAULT_WEIGHTS: dict[str, Decimal] = {
    "value_size": Decimal("0.30"),
    "customer_history": Decimal("0.20"),
    "injection": Decimal("0.25"),
    "behavioral": Decimal("0.15"),
    "action_sensitivity": Decimal("0.10"),
}

# Weights are clamped to defaults ± this, so a brand can never drift into
# unexplainable territory (e.g. injection weight ~ 0).
MAX_DRIFT = Decimal("0.10")

# Learning rate for the outcome-driven nudge.
STEP = Decimal("0.02")


def clamp_weights(weights: dict[str, Decimal]) -> dict[str, Decimal]:
    """Clamp every weight into ``[default - MAX_DRIFT, default + MAX_DRIFT]``
    and renormalize to sum to exactly 1.0000 (keeps the weighted mean valid).

    The rounding residual from quantizing is absorbed into the largest
    weight so the sum is *exact* — downstream weighted means then never
    see a drift like 0.9999.
    """
    clamped: dict[str, Decimal] = {}
    for name, default in DEFAULT_WEIGHTS.items():
        lo = default - MAX_DRIFT
        hi = default + MAX_DRIFT
        w = weights.get(name, default)
        clamped[name] = min(max(w, lo), hi)
    total = sum(clamped.values(), Decimal("0"))
    if total <= 0:  # pathological input; fall back to defaults
        return {name: +default for name, default in DEFAULT_WEIGHTS.items()}
    scale = Decimal("1") / total
    result = {
        name: (w * scale).quantize(Decimal("0.0001"), rounding=ROUND_HALF_EVEN)
        for name, w in clamped.items()
    }
    residual = Decimal("1") - sum(result.values(), Decimal("0"))
    if residual != 0:
        # Absorb the quantization residual into the largest weight.
        biggest = max(result, key=lambda n: result[n])
        result[biggest] = (result[biggest] + residual).quantize(Decimal("0.0001"))
    return result


@dataclass
class OutcomeRecord:
    """One human verdict paired with the signals that produced the decision."""

    audit_id: str
    brand_id: str
    review_id: str | None
    approved: bool
    risk_score: str
    signals: dict[str, str] = field(default_factory=dict)
    """signal name -> normalized score (0..1) at decision time."""
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class WeightSet:
    brand_id: str
    weights: dict[str, Decimal]
    version: int = 1
    state: str = "active"  # active | shadow | retired
    shadow_hits: int = 0
    shadow_agrees: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class OutcomeStore:
    """Append-only outcome log (per REVIEW decision) + weight-set registry."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._outcomes: list[OutcomeRecord] = []
        self._weights: dict[str, WeightSet] = {}  # brand_id -> current set
        self._shadow: dict[str, WeightSet] = {}  # brand_id -> shadow set
        self._recalibrated_upto: dict[str, int] = {}  # brand_id -> outcome count
        self._seq = 0

    # -- recalibration bookkeeping ------------------------------------------

    def mark_recalibrated(self, brand_id: str, outcome_count: int) -> None:
        """Record that the first ``outcome_count`` outcomes of ``brand_id``
        have already been consumed by a recalibration run."""
        with self._lock:
            prev = self._recalibrated_upto.get(brand_id, 0)
            self._recalibrated_upto[brand_id] = max(prev, outcome_count)

    def unrecalibrated(self, brand_id: str) -> list[OutcomeRecord]:
        """Outcomes recorded after the last recalibration consumed them.

        The cursor is *per-brand* and indexes each brand's own subsequence —
        filtering must happen BEFORE slicing. Slicing the global list first
        (the old behavior) re-consumes other brands' interleaved records on
        every run, silently double-counting evidence and drifting weights.
        """
        with self._lock:
            items = [o for o in self._outcomes if o.brand_id == brand_id]
            start = self._recalibrated_upto.get(brand_id, 0)
        return items[start:]

    # -- outcomes -----------------------------------------------------------

    def record(
        self,
        *,
        audit_id: str,
        brand_id: str,
        review_id: str | None,
        approved: bool,
        risk_score: str,
        signals: dict[str, str] | None = None,
    ) -> OutcomeRecord:
        rec = OutcomeRecord(
            audit_id=audit_id,
            brand_id=brand_id,
            review_id=review_id,
            approved=approved,
            risk_score=risk_score,
            signals=signals or {},
        )
        with self._lock:
            self._outcomes.append(rec)
        return rec

    def outcomes(self, brand_id: str | None = None) -> list[OutcomeRecord]:
        with self._lock:
            items = [o for o in self._outcomes if brand_id is None or o.brand_id == brand_id]
        return list(items)

    # -- weights -------------------------------------------------------------

    def weights_for(self, brand_id: str) -> WeightSet:
        with self._lock:
            current = self._weights.get(brand_id)
        if current is None:
            return WeightSet(brand_id=brand_id, weights=dict(DEFAULT_WEIGHTS))
        return current

    def set_weights(self, brand_id: str, weights: dict[str, Decimal]) -> tuple[WeightSet, dict[str, Any]]:
        """Promote a recalibrated weight set. Returns ``(new_set, change_info)``
        — ``change_info`` is exactly what the caller should append to the
        audit trail so weight drift is auditable."""
        clean = clamp_weights(weights)
        with self._lock:
            old = self._weights.get(brand_id)
            version = (old.version + 1) if old else 1
            new = WeightSet(brand_id=brand_id, weights=clean, version=version)
            self._weights[brand_id] = new
            self._shadow.pop(brand_id, None)  # promotion retires any shadow run
            self._seq += 1
        changes = {
            name: {
                "from": str(old.weights.get(name, DEFAULT_WEIGHTS[name])) if old else str(DEFAULT_WEIGHTS[name]),
                "to": str(clean[name]),
            }
            for name in SIGNALS
            if not old or old.weights.get(name, DEFAULT_WEIGHTS[name]) != clean[name]
        }
        change_info = {
            "kind": "weights_promoted",
            "brand_id": brand_id,
            "version": version,
            "changes": changes,
            "at": datetime.now(UTC).isoformat(),
        }
        return new, change_info

    # -- shadow mode -----------------------------------------------------------

    def start_shadow(self, brand_id: str, weights: dict[str, Decimal]) -> WeightSet:
        clean = clamp_weights(weights)
        shadow = WeightSet(brand_id=brand_id, weights=clean, state="shadow")
        with self._lock:
            self._shadow[brand_id] = shadow
        return shadow

    def shadow_for(self, brand_id: str) -> WeightSet | None:
        with self._lock:
            return self._shadow.get(brand_id)

    def score_shadow(self, brand_id: str, *, agreed: bool) -> None:
        with self._lock:
            shadow = self._shadow.get(brand_id)
            if shadow is None:
                return
            shadow.shadow_hits += 1
            if agreed:
                shadow.shadow_agrees += 1

    def shadow_promotable(self, brand_id: str, *, min_samples: int, min_win_rate: float) -> bool:
        shadow = self.shadow_for(brand_id)
        if shadow is None or shadow.shadow_hits < min_samples:
            return False
        return (shadow.shadow_agrees / shadow.shadow_hits) >= min_win_rate


class RecalibrationEngine:
    """Nudges per-brand signal weights based on human outcomes.

    Rule: for each signal, if outcomes where that signal scored *high* were
    mostly approved (humans disagree with the risk), the weight steps down;
    if they were mostly rejected (humans agree with the risk), it steps up.
    Bounded by MAX_DRIFT; renormalized to 1.0.
    """

    def __init__(self, store: OutcomeStore) -> None:
        self._store = store

    def recalibrate(
        self, brand_id: str, *, min_outcomes: int = 10
    ) -> tuple[WeightSet | None, dict[str, Any]]:
        """Nudge weights from *new* outcomes only.

        Idempotent per outcome set: re-running without new outcomes is a
        no-op (returns the current weights), so a weekly cron can never
        double-apply the same evidence and drift the model.
        """
        outcomes = self._store.unrecalibrated(brand_id)
        if len(outcomes) < min_outcomes:
            return None, {
                "kind": "recalibration_skipped",
                "brand_id": brand_id,
                "reason": (
                    f"need >= {min_outcomes} new outcomes since the last run, "
                    f"have {len(outcomes)}"
                ),
            }

        current = self._store.weights_for(brand_id)
        new_weights: dict[str, Decimal] = dict(current.weights)
        for signal in SIGNALS:
            high_risk = [
                o for o in outcomes if Decimal(o.signals.get(signal, "0")) >= Decimal("0.5")
            ]
            if not high_risk:
                continue
            approved_share = sum(1 for o in high_risk if o.approved) / len(high_risk)
            if approved_share >= 0.7:
                new_weights[signal] = new_weights[signal] - STEP  # humans overrule risk
            elif approved_share <= 0.3:
                new_weights[signal] = new_weights[signal] + STEP  # humans confirm risk

        new_set, change_info = self._store.set_weights(brand_id, new_weights)
        self._store.mark_recalibrated(brand_id, self._store_total_for(brand_id))
        change_info["kind"] = "recalibrated"
        change_info["outcomes_analyzed"] = len(outcomes)
        return new_set, change_info

    def _store_total_for(self, brand_id: str) -> int:
        """Absolute count of brand outcomes consumed so far (for the cursor)."""
        all_outcomes = self._store.outcomes(brand_id)
        return len(all_outcomes)


class FileOutcomeStore(OutcomeStore):
    """Outcome store persisted to a JSON file.

    The default ``OutcomeStore`` is per-process memory — fine inside one API
    process, but a *weekly recalibration cron runs in a different process*
    and would silently see zero outcomes (a no-op learning loop). This
    subclass swaps the in-memory lists/dicts for a JSON file with an atomic
    write (set ``OPSONARA_OUTCOME_STORE_PATH``), keeping the exact same
    interface so ``main.py`` and ``recalibrate_job`` share one store.
    """

    def __init__(self, path: str) -> None:
        # Deliberately does NOT call super().__init__(): this subclass owns
        # initialization. ``_outcomes`` must always exist — the load branch
        # below only *populates* it when a store file is present.
        self._lock = threading.RLock()  # type: ignore[assignment]  # RLock: _save runs under re-entry
        self._path = path
        self._outcomes: list[OutcomeRecord] = []
        self._weights: dict[str, WeightSet] = {}
        self._shadow: dict[str, WeightSet] = {}
        self._recalibrated_upto: dict[str, int] = {}
        self._seq = 0
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    data = json.load(fh)
                self._weights = {
                    k: WeightSet(
                        brand_id=v["brand_id"],
                        weights={n: Decimal(d) for n, d in v["weights"].items()},
                        version=int(v.get("version", 1)),
                        state=str(v.get("state", "active")),
                        shadow_hits=int(v.get("shadow_hits", 0)),
                        shadow_agrees=int(v.get("shadow_agrees", 0)),
                    )
                    for k, v in data.get("weights", {}).items()
                }
                self._shadow = {
                    k: WeightSet(
                        brand_id=v["brand_id"],
                        weights={n: Decimal(d) for n, d in v["weights"].items()},
                        version=int(v.get("version", 1)),
                        state="shadow",
                        shadow_hits=int(v.get("shadow_hits", 0)),
                        shadow_agrees=int(v.get("shadow_agrees", 0)),
                    )
                    for k, v in data.get("shadow", {}).items()
                }
                self._recalibrated_upto = {
                    k: int(v) for k, v in data.get("recalibrated_upto", {}).items()
                }
                self._outcomes = [
                    OutcomeRecord(
                        audit_id=o["audit_id"],
                        brand_id=o["brand_id"],
                        review_id=o.get("review_id"),
                        approved=bool(o["approved"]),
                        risk_score=str(o.get("risk_score", "0")),
                        signals={k: str(v) for k, v in o.get("signals", {}).items()},
                        created_at=datetime.fromisoformat(o["created_at"])
                        if o.get("created_at")
                        else datetime.now(UTC),
                    )
                    for o in data.get("outcomes", [])
                ]
            except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
                raise RuntimeError(
                    f"outcome store file {path!r} is corrupt: {exc}"
                ) from exc

    # -- persistence ---------------------------------------------------------

    def _save(self) -> None:
        tmp = self._path + ".tmp"
        payload = {
            "outcomes": [
                {
                    "audit_id": o.audit_id,
                    "brand_id": o.brand_id,
                    "review_id": o.review_id,
                    "approved": o.approved,
                    "risk_score": o.risk_score,
                    "signals": o.signals,
                    "created_at": o.created_at.isoformat(),
                }
                for o in self._outcomes
            ],
            "weights": {
                k: {
                    "brand_id": w.brand_id,
                    "weights": {n: str(d) for n, d in w.weights.items()},
                    "version": w.version,
                    "state": w.state,
                    "shadow_hits": w.shadow_hits,
                    "shadow_agrees": w.shadow_agrees,
                }
                for k, w in self._weights.items()
            },
            "shadow": {
                k: {
                    "brand_id": w.brand_id,
                    "weights": {n: str(d) for n, d in w.weights.items()},
                    "version": w.version,
                    "shadow_hits": w.shadow_hits,
                    "shadow_agrees": w.shadow_agrees,
                }
                for k, w in self._shadow.items()
            },
            "recalibrated_upto": self._recalibrated_upto,
        }
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.replace(tmp, self._path)  # atomic on POSIX

    def record(
        self,
        *,
        audit_id: str,
        brand_id: str,
        review_id: str | None,
        approved: bool,
        risk_score: str,
        signals: dict[str, str] | None = None,
    ) -> OutcomeRecord:
        rec = OutcomeRecord(
            audit_id=audit_id,
            brand_id=brand_id,
            review_id=review_id,
            approved=approved,
            risk_score=risk_score,
            signals=signals or {},
        )
        with self._lock:
            self._outcomes.append(rec)
            self._save()
        return rec

    def set_weights(
        self, brand_id: str, weights: dict[str, Decimal]
    ) -> tuple[WeightSet, dict[str, Any]]:
        result: tuple[WeightSet, dict[str, Any]]
        with self._lock:
            result = super().set_weights(brand_id, weights)
            self._save()
        return result

    def mark_recalibrated(self, brand_id: str, outcome_count: int) -> None:
        with self._lock:
            super().mark_recalibrated(brand_id, outcome_count)
            self._save()

    def start_shadow(self, brand_id: str, weights: dict[str, Decimal]) -> WeightSet:
        result: WeightSet
        with self._lock:
            result = super().start_shadow(brand_id, weights)
            self._save()
        return result

    def score_shadow(self, brand_id: str, *, agreed: bool) -> None:
        with self._lock:
            super().score_shadow(brand_id, agreed=agreed)
            self._save()


def open_outcome_store() -> OutcomeStore:
    """Process-shared outcome store, selected by ``OPSONARA_OUTCOME_STORE_PATH``.

    Set it (e.g. ``/data/outcomes.json`` on a mounted volume) and the API
    process records human outcomes there while the weekly recalibration
    cron reads them — the learning loop then actually learns. Unset, every
    process gets an independent in-memory store (fine for dev/demo).
    """
    path = settings.outcome_store_path
    if path:
        return FileOutcomeStore(path)
    return OutcomeStore()


__all__ = [
    "DEFAULT_WEIGHTS",
    "MAX_DRIFT",
    "OutcomeRecord",
    "OutcomeStore",
    "RecalibrationEngine",
    "SIGNALS",
    "STEP",
    "WeightSet",
    "clamp_weights",
    "open_outcome_store",
]
