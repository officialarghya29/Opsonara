"""Tests for the SQLite-backed persistent stores."""

from __future__ import annotations

from decimal import Decimal

import pytest

from opsonara.core.exceptions import AlreadyResolvedError, NotFoundError
from opsonara.core.models import BrandPolicy, Decision
from opsonara.firewall import FirewallEngine, FirewallRequest
from opsonara.stores.sqlite_store import SqliteAuditStore, SqliteReviewStore
from tests.conftest import make_action, make_agent, make_customer, make_order, turn


@pytest.fixture()
def db_path(tmp_path):
    return tmp_path / "opsonara.db"


def make_review_request(**overrides):
    payload = dict(
        action=make_action(amount="15000"),
        agent=make_agent(),
        customer=make_customer(),
        order=make_order(total="20000"),
        policy=BrandPolicy(brand_id="brand_test"),
        conversation=[turn("customer", "please refund my order")],
    )
    payload.update(overrides)
    return FirewallRequest(**payload)


class TestSqliteAuditStore:
    def test_append_get_and_chain(self, db_path):
        store = SqliteAuditStore(db_path)
        audit_id = store.append(make_review_request_record())
        stored = store.get(audit_id)
        assert stored.record.amount == Decimal("15000")
        assert stored.prev_hash == "0" * 64
        assert store.verify_chain() is True

    def test_get_missing_raises(self, db_path):
        store = SqliteAuditStore(db_path)
        with pytest.raises(NotFoundError):
            store.get("aud_missing")

    def test_persistence_across_reopen(self, db_path):
        store = SqliteAuditStore(db_path)
        audit_id = store.append(make_review_request_record())

        reopened = SqliteAuditStore(db_path)
        stored = reopened.get(audit_id)
        assert stored.record.action == "refund"
        assert reopened.verify_chain() is True
        # New appends must continue the old chain.
        reopened.append(make_review_request_record(amount="200"))
        assert reopened.verify_chain() is True

    def test_counts_match_records(self, db_path):
        store = SqliteAuditStore(db_path)
        store.append(make_review_request_record())
        store.append(make_review_request_record(amount="200"))
        counts = store.counts()
        assert counts["total"] == 2
        assert counts["by_decision"]["BLOCK"] == 2

    def test_list_filter_by_decision(self, db_path):
        store = SqliteAuditStore(db_path)
        store.append(make_review_request_record())
        store.append(make_review_request_record(amount="200"))
        _, total_blocks = store.list(decision="BLOCK")
        assert total_blocks == 2


class TestSqliteReviewStore:
    def test_review_lifecycle_and_persistence(self, db_path):
        audit_store = SqliteAuditStore(db_path)
        review_store = SqliteReviewStore(db_path, audit_store)
        review_id = review_store.create(
            audit_id=audit_store.append(make_review_request_record()),
            action="refund",
            amount="15000",
            currency="INR",
            agent_id="agt_test",
            customer_id="CUS-1",
            reason="high value",
            risk_band="medium",
            risk_score="0.42",
        )
        item = review_store.get(review_id)
        assert item.status.value == "pending"

        item, _, human_audit_id = review_store.decide(
            review_id, approved=True, reviewer="ops@brand.com"
        )
        assert item.status.value == "approved"
        assert audit_store.get(human_audit_id).record.authorization == "granted"
        assert audit_store.verify_chain() is True

        # Persistence across reopen.
        reopened_reviews = SqliteReviewStore(db_path, audit_store)
        assert reopened_reviews.get(review_id).status.value == "approved"

    def test_double_decision_rejected(self, db_path):
        audit_store = SqliteAuditStore(db_path)
        review_store = SqliteReviewStore(db_path, audit_store)
        review_id = review_store.create(
            audit_id=audit_store.append(make_review_request_record()),
            action="refund",
            amount="15000",
            currency="INR",
            agent_id="agt_test",
            customer_id="CUS-1",
            reason="high value",
            risk_band="medium",
            risk_score="0.42",
        )
        review_store.decide(review_id, approved=True, reviewer="ops@brand.com")
        with pytest.raises(AlreadyResolvedError):
            review_store.decide(review_id, approved=False, reviewer="ops@brand.com")


class TestSqliteApiPersistence:
    def test_audit_survives_app_restart(self, db_path):
        """Two app instances on the same DB simulate a process restart."""
        from fastapi.testclient import TestClient

        from opsonara.main import create_app

        overrides = {
            "seed_demo_data": False,
            "store_backend": "sqlite",
            "db_path": str(db_path),
        }
        first = TestClient(create_app(overrides=overrides))
        res = first.post("/v1/evaluate", json=_api_payload())
        assert res.status_code == 200
        audit_id = res.json()["audit_id"]

        # "Restart": a brand-new app instance over the same file.
        second = TestClient(create_app(overrides=overrides))
        fetched = second.get(f"/v1/audit/{audit_id}")
        assert fetched.status_code == 200
        assert fetched.json()["action"] == "refund"
        assert second.get("/v1/audit/verify").json()["intact"] is True
        stats = second.get("/v1/stats").json()
        assert stats["total_decisions"] == 1


def _api_payload():
    return {
        "action": {
            "type": "refund",
            "amount": "799",
            "currency": "INR",
            "order_id": "ORD-1",
            "customer_id": "CUS-1",
        },
        "agent": {"id": "agt_test", "name": "TestBot", "permission_level": 1},
        "customer": {
            "id": "CUS-1",
            "lifetime_orders": 10,
            "lifetime_value": "50000",
            "previous_refunds": 1,
            "previous_refund_value": "1000",
            "chargebacks": 0,
            "account_age_days": 365,
            "vip_tier": False,
        },
        "order": {
            "id": "ORD-1",
            "customer_id": "CUS-1",
            "status": "delivered",
            "total": "799",
            "currency": "INR",
            "product_category": "electronics",
            "created_days_ago": 5,
        },
        "policy": {"brand_id": "brand_test"},
        "conversation": [
            {"role": "customer", "content": "Item arrived broken, please refund."}
        ],
        "metadata": {},
    }


class TestSqlitePipeline:
    def test_firewall_works_with_sqlite_stores(self, db_path):
        audit_store = SqliteAuditStore(db_path)
        review_store = SqliteReviewStore(db_path, audit_store)
        firewall = FirewallEngine(audit_store=audit_store, review_store=review_store)

        response = firewall.evaluate(make_review_request())
        assert response.decision is Decision.REVIEW
        assert response.review_id is not None

        items, total = audit_store.list(limit=10)
        assert total == 1
        assert items[0].record.human_decision == "pending"
        assert audit_store.verify_chain() is True


def make_review_request_record(amount: str = "15000"):
    return _record_for(amount)


def _record_for(amount: str):
    from opsonara.core.models import AuditRecord, RiskBand

    return AuditRecord(
        action="refund",
        amount=Decimal(amount),
        currency="INR",
        customer_id="CUS-1",
        order_id="ORD-1",
        agent_id="agt_test",
        customer_risk=Decimal("0.42"),
        injection_risk=Decimal("0"),
        risk_score=Decimal("0.42"),
        risk_band=RiskBand.MEDIUM,
        policy_status="requires_human",
        authorization="pending_human",
        decision=Decision.BLOCK,
        reasons=["test record"],
        policy_checks=[],
        risk_factors=[],
    )
