"""Policy simulator — replay history against a candidate policy (spec §12).

Before a policy pack goes live, answer: *what would have happened?* Every
historical evaluation persists its full inputs (``request_snapshot``), so the
simulator can re-run the real decision pipeline against a candidate pack and
report the decision delta:

    NEW POLICY → REPLAY HISTORICAL TRANSACTIONS → RESULTS

Metrics mirror the spec: ALLOW / REVIEW / BLOCK counts, how many decisions
changed and in which direction, the financial exposure that the candidate
policy would newly review or block, and the estimated human-review reduction.
Nothing here deploys anything — promotion stays an explicit, separate act
(design principle: learning/simulation suggests, humans decide).

Usage::

    sim = PolicySimulator(firewall, audit_store)
    report = sim.simulate_pack(pack_id="pack_0007_b1", limit=10_000)
    report["summary"]["changed"]      # decisions that would differ
    report["would_review"]            # newly reviewed (with exposure)
    report["would_block"]             # newly blocked
"""

from __future__ import annotations

import threading
from decimal import Decimal
from typing import Any

from opsonara.core.models import AuditRecord, ConversationTurn
from opsonara.firewall import FirewallRequest
from opsonara.policy_store import PolicyPackStore


class PolicySimulator:
    """Replays persisted evaluations under a candidate policy pack."""

    def __init__(self, firewall: Any, audit_store: Any) -> None:
        self._firewall = firewall
        self._audit_store = audit_store
        self._lock = threading.Lock()

    # -- replay --------------------------------------------------------------

    def _rebuild_request(self, snapshot: dict[str, Any]) -> FirewallRequest | None:
        """Reconstruct a :class:`FirewallRequest` from a request snapshot.

        Returns ``None`` for legacy records created before snapshots existed
        (they are counted as ``skipped``).
        """
        if not snapshot or "action" not in snapshot:
            return None
        try:
            return FirewallRequest(
                action=snapshot["action"],
                agent=snapshot["agent"],
                customer=snapshot["customer"],
                order=snapshot.get("order"),
                policy=snapshot["policy"],
                conversation=[
                    ConversationTurn(**t) for t in snapshot.get("conversation", [])
                ],
                metadata=snapshot.get("metadata", {}),
            )
        except Exception:  # noqa: BLE001 — malformed snapshot: skip, don't crash
            return None

    def simulate_pack(
        self,
        *,
        pack_id: str,
        brand_id: str | None = None,
        limit: int = 1000,
    ) -> dict[str, Any]:
        """Replay historical audits under ``pack_id`` without deploying it.

        Only records carrying a ``request_snapshot`` can be replayed; the
        candidate pack's policy overrides each replayed request's policy.
        The firewall still appends shadow audit records for the replays (the
        audit trail is append-only) — they are tagged
        ``provenance.simulation = pack_id`` for easy filtering.
        """
        pack = self._pack(pack_id)
        candidate = pack.policy
        scope_brand = brand_id or pack.brand_id

        records, _total = self._audit_store.list(limit=limit)
        replayed = 0
        skipped = 0
        baseline = {"ALLOW": 0, "REVIEW": 0, "BLOCK": 0}
        candidate_counts = {"ALLOW": 0, "REVIEW": 0, "BLOCK": 0}
        would_review: list[dict[str, Any]] = []
        would_block: list[dict[str, Any]] = []
        would_allow: list[dict[str, Any]] = []
        newly_reviewed_exposure = Decimal("0")
        newly_blocked_exposure = Decimal("0")
        review_reduction = 0

        for stored in records:
            record: AuditRecord = stored.record
            if record.action == "execution_verification":
                continue  # synthetic records, not transactions
            if scope_brand and (record.brand_id or scope_brand) != scope_brand:
                continue
            request = self._rebuild_request(record.request_snapshot or {})
            if request is None:
                skipped += 1
                continue
            replayed += 1
            request = request.model_copy(update={"policy": candidate})

            base_decision = record.decision.value
            baseline[base_decision] += 1

            # create_review=False: a replay must never open a real review item
            shadow = self._firewall.evaluate(
                request, simulation=f"sim:{pack_id}", create_review=False
            )
            cand_decision = shadow.decision.value
            candidate_counts[cand_decision] += 1

            delta: dict[str, Any] = {
                "audit_id": stored.id,
                "action": record.action,
                "amount": str(record.amount),
                "currency": record.currency,
                "was": base_decision,
                "now": cand_decision,
            }
            if cand_decision != base_decision:
                if cand_decision == "REVIEW":
                    would_review.append(delta)
                    newly_reviewed_exposure += record.amount
                elif cand_decision == "BLOCK":
                    would_block.append(delta)
                    newly_blocked_exposure += record.amount
                else:  # now ALLOW
                    would_allow.append(delta)
                    if base_decision == "REVIEW":
                        review_reduction += 1

        changed = len(would_review) + len(would_block) + len(would_allow)
        return {
            "pack_id": pack_id,
            "pack_version": pack.version,
            "brand_id": scope_brand,
            "replayed": replayed,
            "skipped": skipped,
            "baseline": baseline,
            "candidate": candidate_counts,
            "summary": {
                "changed": changed,
                "would_review": len(would_review),
                "would_block": len(would_block),
                "would_allow": len(would_allow),
                "review_reduction": review_reduction,
                "newly_reviewed_exposure": str(newly_reviewed_exposure),
                "newly_blocked_exposure": str(newly_blocked_exposure),
                "change_rate": (
                    round(changed / replayed, 4) if replayed else 0.0
                ),
            },
            "details": {
                "would_review": would_review[:50],
                "would_block": would_block[:50],
                "would_allow": would_allow[:50],
            },
        }

    def _pack(self, pack_id: str) -> Any:
        store: PolicyPackStore | None = self._firewall.policy_packs
        if store is None:
            raise ValueError("no policy pack store configured on the firewall")
        packs = {p.pack_id: p for p in store.list()}
        if pack_id not in packs:
            raise KeyError(f"unknown policy pack '{pack_id}'")
        return packs[pack_id]


__all__ = ["PolicySimulator"]
