"""Postgres store integration tests (multi-instance backend).

Runs only when ``OPSONARA_TEST_PG_DSN`` is set (CI provisions a Postgres
service container). Skipped everywhere else, so local dev never needs a
running Postgres.
"""

from __future__ import annotations

import os
from decimal import Decimal

import pytest

from opsonara.core.exceptions import AlreadyResolvedError
from opsonara.core.models import AuditRecord, Decision, ReviewStatus, RiskBand
from opsonara.stores.pg_store import PgAuditStore, PgReviewStore

DSN = os.environ.get("OPSONARA_TEST_PG_DSN", "")

pytestmark = pytest.mark.skipif(
    not DSN, reason="OPSONARA_TEST_PG_DSN not set; Postgres integration tests skipped"
)


def _record(action: str = "refund", amount: str = "500.00") -> AuditRecord:
    return AuditRecord(
        action=action,
        amount=Decimal(amount),
        currency="INR",
        customer_id="cust_1",
        agent_id="agt_1",
        brand_id="brand_pg",
        customer_risk=Decimal("0.1"),
        injection_risk=Decimal("0"),
        risk_score=Decimal("0.2"),
        risk_band=RiskBand.LOW,
        policy_status="allowed",
        authorization="granted",
        decision=Decision.ALLOW,
        reasons=["ok"],
        policy_checks=[],
        risk_factors=[],
    )


@pytest.fixture()
def stores() -> tuple[PgAuditStore, PgReviewStore]:
    audit_store = PgAuditStore(DSN)
    review_store = PgReviewStore(DSN, audit_store)
    return audit_store, review_store


def test_append_and_get_roundtrip(stores: tuple[PgAuditStore, PgReviewStore]) -> None:
    audit_store, _ = stores
    audit_id = audit_store.append(_record(amount="101.00"))
    stored = audit_store.get(audit_id)
    assert stored.record.amount == Decimal("101.00")
    assert stored.record.brand_id == "brand_pg"


def test_list_pagination_and_filter(stores: tuple[PgAuditStore, PgReviewStore]) -> None:
    audit_store, _ = stores
    audit_store.append(_record())
    page, total = audit_store.list(limit=5, decision="ALLOW")
    assert total >= 1
    assert all(s.record.decision is Decision.ALLOW for s in page)


def test_counts_mirror_appends(stores: tuple[PgAuditStore, PgReviewStore]) -> None:
    audit_store, _ = stores
    before = audit_store.counts()["total"]
    audit_store.append(_record())
    assert audit_store.counts()["total"] == before + 1


def test_verify_chain_after_appends(stores: tuple[PgAuditStore, PgReviewStore]) -> None:
    audit_store, _ = stores
    audit_store.append(_record())
    assert audit_store.verify_chain() is True
    assert audit_store.verify_chain(force=True) is True


def test_review_decide_flow_and_persistence(
    stores: tuple[PgAuditStore, PgReviewStore],
) -> None:
    audit_store, review_store = stores
    origin_id = audit_store.append(
        AuditRecord(
            action="refund",
            amount=Decimal("7000.00"),
            currency="INR",
            customer_id="cust_1",
            agent_id="agt_1",
            brand_id="brand_pg",
            customer_risk=Decimal("0.3"),
            injection_risk=Decimal("0"),
            risk_score=Decimal("0.4"),
            risk_band=RiskBand.MEDIUM,
            policy_status="requires_human",
            authorization="pending",
            decision=Decision.REVIEW,
            reasons=["needs review"],
            policy_checks=[],
            risk_factors=[],
            review_id=None,
            human_decision="pending",
        )
    )
    review_id = review_store.create(
        audit_id=origin_id,
        action="refund",
        amount="7000.00",
        currency="INR",
        agent_id="agt_1",
        customer_id="cust_1",
        reason="needs review",
        risk_band="medium",
        risk_score="0.4",
    )
    assert review_store.count_pending() >= 1
    item, _human, _audit_id = review_store.decide(
        review_id, approved=True, reviewer="priya"
    )
    assert item.status is ReviewStatus.APPROVED
    with pytest.raises(AlreadyResolvedError):
        review_store.decide(review_id, approved=False, reviewer="other")
    # human_decision persisted on the origin audit row
    assert audit_store.get(origin_id).record.human_decision == "approved"
