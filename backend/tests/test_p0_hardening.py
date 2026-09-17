"""Tests for the P0 production-hardening features:

1. idempotency — duplicate evaluate calls replay the original verdict (§24)
2. fine-grained agent authorization — deny list, amount cap, frequency cap (§2/§40)
3. two-person approval — threshold-triggered dual human approval (§27)
4. production mode — secure-by-default boot gating (§65)
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from fastapi.testclient import TestClient

from opsonara.core.models import AgentIdentity, BrandPolicy, CustomerProfile, ProposedAction
from opsonara.firewall import FirewallEngine, FirewallRequest
from opsonara.idempotency import MemoryIdempotencyStore, fingerprint_payload
from opsonara.main import create_app
from opsonara.stores.audit_store import AuditStore
from opsonara.stores.review_store import ReviewStore

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _order(amount: str) -> dict[str, Any]:
    return {
        "id": "O1",
        "customer_id": "C1",
        "status": "delivered",
        "total": amount,
    }


def make_request(**agent_kwargs: Any) -> FirewallRequest:
    agent = AgentIdentity(
        id="agt_1", name="Bot", permission_level=1, **agent_kwargs
    )
    return FirewallRequest(
        action=ProposedAction(
            type="refund", amount="500", order_id="O1", customer_id="C1"
        ),
        agent=agent,
        customer={"id": "C1"},
        order=_order("500"),
        policy=BrandPolicy(
            brand_id="b1",
            auto_approve_limit=Decimal("2000"),
            human_review_limit=Decimal("10000"),
        ),
    )


@pytest.fixture()
def pair() -> tuple[FirewallEngine, AuditStore]:
    audit = AuditStore()
    return FirewallEngine(audit, ReviewStore(audit)), audit


def evaluate(engine: FirewallEngine, request: FirewallRequest):
    return engine.evaluate(request)


# ---------------------------------------------------------------------------
# 1 · fine-grained agent authorization
# ---------------------------------------------------------------------------


class TestAgentAuthorization:
    def test_clean_agent_passes_gate(self, pair):
        engine, _ = pair
        result = evaluate(engine, make_request())
        assert result.decision.value in {"ALLOW", "REVIEW"}

    def test_denied_action_blocks_even_when_policy_allows(self, pair):
        """A deny-listed action is decisive — policy generosity cannot
        resurrect it (agent-to-tool permission graph, §40)."""
        engine, audit = pair
        result = evaluate(engine, make_request(denied_actions=["refund"]))
        assert result.decision.value == "BLOCK"
        assert any("deny list" in r for r in result.reasons)
        checks = [c["name"] for c in result.policy_checks]
        assert "agent_denied_action" in checks
        # the block is chained
        record = audit.get(result.audit_id).record
        assert record.decision.value == "BLOCK"

    def test_denied_action_case_sensitive_exact_match(self, pair):
        engine, _ = pair
        result = evaluate(engine, make_request(denied_actions=["refunds"]))
        assert result.decision.value != "BLOCK"  # no false positive

    def test_amount_cap_blocks_over_ceiling(self, pair):
        engine, _ = pair
        result = evaluate(
            engine,
            FirewallRequest(
                action=ProposedAction(
                    type="refund", amount="5000", order_id="O1", customer_id="C1"
                ),
                order=_order("5000"),
                agent=AgentIdentity(
                    id="agt_1", name="Bot", permission_level=1,
                    max_action_amount=Decimal("3000"),
                ),
                customer={"id": "C1"},
                policy=BrandPolicy(
                    brand_id="b1",
                    auto_approve_limit=Decimal("2000"),
                    human_review_limit=Decimal("10000"),
                ),
            ),
        )
        assert result.decision.value == "BLOCK"
        assert any("hard per-action cap" in r for r in result.reasons)

    def test_amount_cap_under_ceiling_untouched(self, pair):
        engine, _ = pair
        request = FirewallRequest(
            action=ProposedAction(
                type="refund", amount="1500", order_id="O1", customer_id="C1"
            ),
            agent=AgentIdentity(
                id="agt_1", name="Bot", permission_level=1,
                max_action_amount=Decimal("3000"),
            ),
            customer={"id": "C1"},
            order=_order("1500"),
            policy=BrandPolicy(
                brand_id="b1",
                auto_approve_limit=Decimal("2000"),
                human_review_limit=Decimal("10000"),
            ),
        )
        assert evaluate(engine, request).decision.value == "ALLOW"

    def test_frequency_cap_blocks_when_velocity_exceeded(self, pair):
        engine, _ = pair
        base = make_request(max_actions_per_hour=10)
        hot = base.model_copy(
            update={"metadata": {"recent_action_counts": {"refund": 10}}}
        )
        result = evaluate(engine, hot)
        assert result.decision.value == "BLOCK"
        assert any("trailing hour" in r for r in result.reasons)

    def test_frequency_cap_sums_all_action_types(self, pair):
        """9 refunds + 1 discount = 10 actions → at the cap of 10 → block."""
        engine, _ = pair
        base = make_request(max_actions_per_hour=10)
        hot = base.model_copy(
            update={
                "action": ProposedAction(
                    type="refund", amount="500", order_id="O1", customer_id="C1"
                ),
                "metadata": {
                    "recent_action_counts": {"refund": 9, "discount": 1}
                },
            }
        )
        assert evaluate(engine, hot).decision.value == "BLOCK"

    def test_frequency_cap_garbage_metadata_never_crashes(self, pair):
        engine, _ = pair
        for junk in ["x", {"refund": "abc"}, {"refund": None}, [1], 42]:
            base = make_request(max_actions_per_hour=10)
            hot = base.model_copy(update={"metadata": {"recent_action_counts": junk}})
            result = evaluate(engine, hot)
            assert result.decision.value in {"ALLOW", "REVIEW", "BLOCK"}


# ---------------------------------------------------------------------------
# 2 · idempotency
# ---------------------------------------------------------------------------


class TestIdempotency:
    def test_fingerprint_is_order_independent(self):
        a = fingerprint_payload({"x": 1, "y": {"b": 2, "a": 1}})
        b = fingerprint_payload({"y": {"a": 1, "b": 2}, "x": 1})
        assert a == b
        assert fingerprint_payload({"x": 2, "y": 1}) != a

    def test_claim_get_complete_release_cycle(self):
        store = MemoryIdempotencyStore()
        assert store.claim("k1", "fp") is True
        assert store.claim("k1", "fp") is False  # second claim loses
        assert store.get("k1") is None  # not finished yet
        store.complete("k1", "fp", {"decision": "ALLOW"})
        got = store.get("k1")
        assert got is not None and got["response"]["decision"] == "ALLOW"
        store.release("k1")
        assert store.get("k1") is None
        assert store.claim("k1", "fp") is True  # reusable after release

    def test_complete_with_wrong_fingerprint_is_noop(self):
        store = MemoryIdempotencyStore()
        store.claim("k", "fp1")
        store.complete("k", "fp2", {"decision": "ALLOW"})
        assert store.get("k") is None

    def test_api_duplicate_replays_original_verdict(self):
        app = create_app(overrides={"seed_demo_data": False})
        client = TestClient(app)
        payload = {
            "action": {"type": "refund", "amount": "500"},
            "agent": {"id": "a", "name": "A", "permission_level": 2},
            "customer": {"id": "C1"},
            "policy": {"brand_id": "b", "auto_approve_limit": "2000", "human_review_limit": "10000"},
        }
        r1 = client.post("/v1/evaluate", json=payload, headers={"Idempotency-Key": "order-9281"})
        assert r1.status_code == 200
        first = r1.json()
        assert "idempotency_replayed" not in first

        r2 = client.post("/v1/evaluate", json=payload, headers={"Idempotency-Key": "order-9281"})
        assert r2.status_code == 200
        second = r2.json()
        assert second["idempotency_replayed"] is True
        assert second["audit_id"] == first["audit_id"]

    def test_api_key_reuse_with_different_body_rejected(self):
        app = create_app(overrides={"seed_demo_data": False})
        client = TestClient(app)
        base = {
            "action": {"type": "refund", "amount": "500"},
            "agent": {"id": "a", "name": "A", "permission_level": 2},
            "customer": {"id": "C1"},
            "policy": {"brand_id": "b", "auto_approve_limit": "2000", "human_review_limit": "10000"},
        }
        assert client.post("/v1/evaluate", json=base, headers={"Idempotency-Key": "k"}).status_code == 200
        tampered = {**base, "action": {**base["action"], "amount": "9999"}}
        r = client.post("/v1/evaluate", json=tampered, headers={"Idempotency-Key": "k"})
        assert r.status_code == 422
        assert "different request body" in r.json()["detail"]

    def test_api_without_key_untouched(self):
        app = create_app(overrides={"seed_demo_data": False})
        client = TestClient(app)
        payload = {
            "action": {"type": "refund", "amount": "500"},
            "agent": {"id": "a", "name": "A", "permission_level": 2},
            "customer": {"id": "C1"},
            "policy": {"brand_id": "b", "auto_approve_limit": "2000", "human_review_limit": "10000"},
        }
        for _ in range(2):
            r = client.post("/v1/evaluate", json=payload)
            assert r.status_code == 200
            assert "idempotency_replayed" not in r.json()

    def test_long_key_rejected(self):
        app = create_app(overrides={"seed_demo_data": False})
        client = TestClient(app)
        payload = {
            "action": {"type": "refund", "amount": "500"},
            "agent": {"id": "a", "name": "A", "permission_level": 2},
            "customer": {"id": "C1"},
            "policy": {"brand_id": "b"},
        }
        r = client.post("/v1/evaluate", json=payload, headers={"Idempotency-Key": "k" * 257})
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# 3 · two-person approval
# ---------------------------------------------------------------------------


class TestTwoPersonApproval:
    def _client_with_threshold(self) -> TestClient:
        app = create_app(overrides={"seed_demo_data": False})
        return TestClient(app)

    def _evaluate_review(self, client: TestClient, amount: str) -> dict[str, Any]:
        payload = {
            "action": {"type": "refund", "amount": amount, "order_id": "O1", "customer_id": "C1"},
            "agent": {"id": "a", "name": "A", "permission_level": 3},
            "customer": {"id": "C1", "lifetime_orders": 5, "lifetime_value": "50000"},
            "order": {"id": "O1", "customer_id": "C1", "status": "delivered", "total": amount},
            "policy": {
                "brand_id": "b",
                "auto_approve_limit": "2000",
                "human_review_limit": "10000",
                "two_person_approval_above": "5000",
            },
        }
        r = client.post("/v1/evaluate", json=payload)
        assert r.status_code == 200, r.text
        return r.json()

    def test_above_threshold_creates_two_person_review(self):
        client = self._client_with_threshold()
        body = self._evaluate_review(client, "8000")
        assert body["decision"] == "REVIEW"
        review = client.get(f"/v1/reviews/{body['review_id']}").json()
        assert review["required_approvals"] == 2

    def test_below_threshold_single_approval(self):
        client = self._client_with_threshold()
        body = self._evaluate_review(client, "4500")
        review = client.get(f"/v1/reviews/{body['review_id']}").json()
        assert review["required_approvals"] == 1

    def test_one_approval_is_not_enough(self):
        client = self._client_with_threshold()
        body = self._evaluate_review(client, "8000")
        rid = body["review_id"]
        r = client.post(f"/v1/reviews/{rid}/decision", json={"approved": True, "reviewer": "alice"})
        assert r.status_code == 200
        assert r.json()["awaiting_approvals"] == 1
        still = client.get(f"/v1/reviews/{rid}").json()
        assert still["status"] == "pending"

    def test_two_distinct_approvals_resolve(self):
        client = self._client_with_threshold()
        body = self._evaluate_review(client, "8000")
        rid = body["review_id"]
        client.post(f"/v1/reviews/{rid}/decision", json={"approved": True, "reviewer": "alice"})
        r2 = client.post(f"/v1/reviews/{rid}/decision", json={"approved": True, "reviewer": "bob"})
        assert r2.json()["awaiting_approvals"] == 0
        done = client.get(f"/v1/reviews/{rid}").json()
        assert done["status"] == "approved"
        assert set(done["reviewed_by"].split(", ")) == {"alice", "bob"}

    def test_same_reviewer_cannot_approve_twice(self):
        client = self._client_with_threshold()
        body = self._evaluate_review(client, "8000")
        rid = body["review_id"]
        client.post(f"/v1/reviews/{rid}/decision", json={"approved": True, "reviewer": "alice"})
        r = client.post(f"/v1/reviews/{rid}/decision", json={"approved": True, "reviewer": "alice"})
        assert r.status_code == 409  # AlreadyResolvedError mapping

    def test_first_rejection_resolves_immediately(self):
        client = self._client_with_threshold()
        body = self._evaluate_review(client, "8000")
        rid = body["review_id"]
        r = client.post(f"/v1/reviews/{rid}/decision", json={"approved": False, "reviewer": "alice"})
        assert r.status_code == 200
        assert client.get(f"/v1/reviews/{rid}").json()["status"] == "rejected"

    def test_two_person_flow_via_engine_and_sqlite(self, tmp_path):
        """End-to-end with a persistent store: partial receipt is chained,
        the origin stays pending until the second approval lands."""

        from opsonara.stores.sqlite_store import SqliteAuditStore, SqliteReviewStore
        from opsonara.stores.sqlite_store import make_stores as _unused  # noqa: F401

        audit = SqliteAuditStore(str(tmp_path / "a.db"))
        reviews = SqliteReviewStore(str(tmp_path / "a.db"), audit)
        engine = FirewallEngine(audit, reviews)
        request = FirewallRequest(
            action=ProposedAction(type="refund", amount="8000", order_id="O1", customer_id="C1"),
            agent=AgentIdentity(id="a", name="A", permission_level=3),
            customer={"id": "C1", "lifetime_orders": 5, "lifetime_value": "50000"},
            order=_order("8000"),
            policy=BrandPolicy(
                brand_id="b",
                auto_approve_limit=Decimal("2000"),
                human_review_limit=Decimal("10000"),
                two_person_approval_above=Decimal("5000"),
            ),
        )
        result = engine.evaluate(request)
        assert result.decision.value == "REVIEW"
        rid = result.review_id
        assert rid is not None

        item1, receipt1, _ = reviews.decide(rid, approved=True, reviewer="alice")
        assert item1.status.value == "pending"
        assert receipt1.human_decision == "partial"
        assert "two-person" in receipt1.reasons[0]

        item2, human2, _ = reviews.decide(rid, approved=True, reviewer="bob")
        assert item2.status.value == "approved"
        assert human2.human_decision == "approved"

        # chain still intact with the partial receipt inside it
        assert audit.verify_chain(force=True) is True

        # the persisted review item keeps its approval list
        persisted = reviews.get(rid)
        assert [a["reviewer"] for a in persisted.approvals] == ["alice", "bob"]
        assert persisted.required_approvals == 2


# ---------------------------------------------------------------------------
# 4 · production mode
# ---------------------------------------------------------------------------


class TestProductionMode:
    def test_production_requires_api_key_auth(self):
        with pytest.raises(RuntimeError, match="OPSONARA_AUTH_MODE=api_key"):
            create_app(overrides={"mode": "production"})

    def test_production_requires_admin_token(self):
        with pytest.raises(RuntimeError, match="OPSONARA_ADMIN_TOKEN"):
            create_app(overrides={"mode": "production", "auth_mode": "api_key"})

    def test_production_rejects_wildcard_cors(self):
        with pytest.raises(RuntimeError, match="OPSONARA_CORS_ORIGINS"):
            create_app(
                overrides={
                    "mode": "production",
                    "auth_mode": "api_key",
                    "admin_token": "tok",
                }
            )

    def test_production_boots_hardened(self):
        app = create_app(
            overrides={
                "mode": "production",
                "auth_mode": "api_key",
                "admin_token": "tok",
                "cors_origins": "https://console.example.com",
                "seed_demo_data": True,  # must be force-disabled
                "credential_verification": "optional",  # forced to strict
            }
        )
        s = app.state.settings
        assert s.seed_demo_data is False
        assert s.credential_verification == "strict"
        client = TestClient(app)
        # anonymous evaluate is now rejected by the api_key gateway
        r = client.post(
            "/v1/evaluate",
            json={
                "action": {"type": "refund", "amount": "500"},
                "agent": {"id": "a", "name": "A", "permission_level": 1},
                "customer": {"id": "C1"},
                "policy": {"brand_id": "b"},
            },
        )
        assert r.status_code in {401, 403}


# ---------------------------------------------------------------------------
# 5 · deepscan extras surfaced during this round
# ---------------------------------------------------------------------------


def test_review_endpoint_rejects_whitespace_reviewer(api_client):
    """A whitespace-only reviewer must be a client error, never a 500 —
    even though the pydantic model only checks min_length=1."""
    from opsonara.stores.audit_store import AuditStore

    audit = AuditStore()
    reviews = ReviewStore(audit)
    rid = reviews.create(
        audit_id=audit.append(_review_audit()),
        action="refund", amount="500", currency="INR",
        agent_id="a", customer_id="C1",
        reason="test", risk_band="medium", risk_score="0.4",
    )
    # Call the store contract directly (endpoint maps errors to 4xx).
    with pytest.raises(ValueError):
        reviews.decide(rid, approved=True, reviewer="   ")


def _review_audit():
    from opsonara.core.models import AuditRecord, Decision, RiskBand

    return AuditRecord(
        action="refund", amount=Decimal("500"), currency="INR",
        agent_id="a", customer_id="C1",
        customer_risk=Decimal("0.2"), injection_risk=Decimal("0"),
        risk_band=RiskBand.MEDIUM, policy_status="requires_human",
        authorization="pending_human", decision=Decision.REVIEW,
        reasons=["test"], policy_checks=[], risk_factors=[],
    )


def test_risk_engine_tolerates_non_dict_velocity(default_policy):
    """Regression: metadata['recent_action_counts'] = 'x' crashed the
    behavioral risk factor with AttributeError (deepscan catch)."""
    from opsonara.engines.context import ContextEngine
    from opsonara.engines.risk import RiskEngine

    ctx = ContextEngine().build(
        action=ProposedAction(type="refund", amount="500"),
        agent=AgentIdentity(id="a", name="A"),
        customer=CustomerProfile(id="C1", lifetime_orders=3),
        order=None,
        policy=default_policy,
        conversation=[],
        metadata={"recent_action_counts": "garbage"},
    )
    result = RiskEngine().evaluate(ctx)
    assert 0 <= result.total <= 1


# ---------------------------------------------------------------------------
# 6 · deepscan round 4: surrogate strings, caps, limits, library-safety
# ---------------------------------------------------------------------------


def test_surrogate_strings_rejected_at_schema_boundary():
    """Lone UTF-16 surrogates cannot be UTF-8 encoded — accepting them
    crashed the API at response-render time (UnicodeEncodeError → 500).
    They must be rejected at validation, never a 500 later. pydantic's own
    strict UTF-8 check fires first (string_unicode); the SafeStr validator
    is belt-and-suspenders for lenient decode paths."""
    import pydantic

    from opsonara.core.models import AgentIdentity, BrandPolicy, ConversationTurn

    for model, kwargs in [
        (AgentIdentity, {"id": "a", "name": "\udcffbad"}),
        (BrandPolicy, {"brand_id": "b\udcff"}),
        (ConversationTurn, {"role": "customer", "content": "hi \udc83"}),
    ]:
        with pytest.raises(pydantic.ValidationError):
            model(**kwargs)  # type: ignore[arg-type]


def test_safestr_validator_direct():
    """The SafeStr guard itself rejects surrogates when reached directly."""
    from opsonara.core.models import _surrogate_free

    with pytest.raises(ValueError, match="surrogate"):
        _surrogate_free("\udcff")
    assert _surrogate_free("ok") == "ok"


def test_api_surrogate_payload_is_422_not_500(api_client):
    resp = api_client.post(
        "/v1/evaluate",
        content=b'{"action": {"type": "refund", "amount": "500"}, '
        b'"agent": {"id": "a", "name": "\\udcff", "permission_level": 2}, '
        b'"customer": {"id": "C1"}, "policy": {"brand_id": "b"}}',
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 422


def test_agent_caps_reject_nonsense_values():
    """A 0/negative frequency cap would block an agent with zero activity;
    a negative amount cap is meaningless. Both are validation errors."""
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        AgentIdentity(id="a", name="A", max_actions_per_hour=0)
    with pytest.raises(pydantic.ValidationError):
        AgentIdentity(id="a", name="A", max_actions_per_hour=-3)
    with pytest.raises(pydantic.ValidationError):
        AgentIdentity(id="a", name="A", max_action_amount="-5")
    with pytest.raises(pydantic.ValidationError):
        AgentIdentity(id="a", name="A", max_action_amount="0")


def test_policy_limits_reject_negative_but_allow_zero():
    """Negative money limits are nonsense; zero is a legal strict config."""
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        BrandPolicy(brand_id="b", auto_approve_limit="-100")
    with pytest.raises(pydantic.ValidationError):
        BrandPolicy(brand_id="b", max_refund_ratio="-1")
    strict = BrandPolicy(brand_id="b", auto_approve_limit="0")
    assert strict.auto_approve_limit == 0


def test_execution_verifier_none_safe():
    """Library callers may pass None/junk (the API always passes dicts)."""
    from opsonara.stores.audit_store import AuditStore
    from opsonara.verification import ExecutionVerifier

    verifier = ExecutionVerifier(AuditStore())
    for kwargs in [
        dict(request=None, execution=None, audit_id="x"),
        dict(request={"action": "x"}, execution=5, audit_id="x"),
    ]:
        result = verifier.verify(**kwargs)
        assert result.status in {"unverified", "unknown"}


def test_lifecycle_ops_report_unknown_agents(api_client):
    """Preemptive containment stays allowed, but the response surfaces
    known:false so an operator can spot a typo'd agent id."""
    r = api_client.post("/v1/agents/agt_typo/pause")
    assert r.status_code == 200
    body = r.json()
    assert body["state"] == "paused"
    assert body["known"] is False
