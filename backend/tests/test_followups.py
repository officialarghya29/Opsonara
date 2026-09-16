"""Tests for the three roadmap followups:

1. post-execution verification (spec §24) — requested vs executed amounts
2. agent lifecycle: quarantine + kill switch (spec §3, §28–§29)
3. policy simulator: replay history against a candidate pack (spec §12)
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from fastapi.testclient import TestClient

from opsonara.core.models import BrandPolicy
from opsonara.firewall import FirewallEngine, FirewallRequest
from opsonara.identity import (
    AGENT_QUARANTINED,
    AgentStateError,
    CredentialAuthority,
)
from opsonara.main import create_app
from opsonara.policy_store import PolicyPackStore
from opsonara.simulator import PolicySimulator
from opsonara.stores.audit_store import AuditStore
from opsonara.stores.review_store import ReviewStore
from opsonara.verification import ExecutionVerifier
from tests.test_platform import (
    make_action,
    make_agent,
    make_customer,
    make_order,
    make_policy,
)


def _request(amount: Decimal) -> FirewallRequest:
    return FirewallRequest(
        action=make_action(amount=amount),
        agent=make_agent(),
        customer=make_customer(),
        order=make_order(total=Decimal("5000")),
        policy=make_policy(),
        conversation=[],
    )


# ---------------------------------------------------------------------------
# 1. post-execution verification
# ---------------------------------------------------------------------------


class TestExecutionVerification:
    def test_matching_amount_is_verified(self) -> None:
        store = AuditStore()
        verifier = ExecutionVerifier(store)
        result = verifier.verify(
            request={"action": {"type": "refund", "amount": "1500", "currency": "INR"}},
            execution={"status": 201, "response": {"refund": {"amount": "1500"}}},
            audit_id="aud_orig",
            connector_id="conn_1",
        )
        assert result.status == "verified"
        assert result.difference == Decimal("0.00")
        assert not result.mismatch

    def test_mismatch_is_detected_and_chained(self) -> None:
        store = AuditStore()
        verifier = ExecutionVerifier(store)
        result = verifier.verify(
            request={"action": {"type": "refund", "amount": "1500", "currency": "INR"}},
            execution={"status": 201, "response": {"refund": {"amount": "15000"}}},
            audit_id="aud_orig",
        )
        assert result.status == "mismatch"
        assert result.mismatch is True
        assert result.difference == Decimal("13500.00")
        stored = store.get(result.audit_id)
        assert stored.record.verification_of == "aud_orig"
        assert stored.record.decision.value == "BLOCK"
        assert stored.record.risk_band.value == "high"
        assert store.verify_chain(force=True) is True

    def test_simulated_response_is_unknown(self) -> None:
        verifier = ExecutionVerifier(AuditStore())
        result = verifier.verify(
            request={"action": {"type": "refund", "amount": "100"}},
            execution={"simulated": True},
            audit_id="aud_orig",
        )
        assert result.status == "unknown"
        assert not result.mismatch

    def test_non_financial_action_is_unverified(self) -> None:
        verifier = ExecutionVerifier(AuditStore())
        result = verifier.verify(
            request={"action": {"type": "update_shipping", "amount": "0"}},
            execution={"status": 200},
            audit_id="aud_orig",
        )
        assert result.status == "unverified"

    def test_tolerance_allows_rounding(self) -> None:
        verifier = ExecutionVerifier(AuditStore(), tolerance=Decimal("0.50"))
        result = verifier.verify(
            request={"action": {"type": "refund", "amount": "100"}},
            execution={"response": {"amount": "100.30"}},
            audit_id="aud_orig",
        )
        assert result.status == "verified"

    def test_connector_service_wires_verification(self) -> None:
        from opsonara.connectors import ConnectorService, ShopifyExecutor

        calls: list[dict[str, Any]] = []

        def transport(url: str, **kwargs: Any) -> tuple[int, dict[str, Any]]:
            # platform "executes" the refund but reports a different amount
            calls.append({"url": url, **kwargs})
            return 201, {"refund": {"amount": "9999"}}

        store = AuditStore()
        fw = FirewallEngine(store, ReviewStore(store))
        service = ConnectorService(fw, ReviewStore(store), verifier=ExecutionVerifier(store))
        service.register(
            "conn_x",
            platform="shopify",
            executor=ShopifyExecutor("test.myshopify.com", "tok", transport=transport),
            brand_id="brand_test",
        )
        request: dict[str, Any] = {
            "action": {
                "type": "refund",
                "amount": "500",
                "currency": "INR",
                "order_id": "o1",
                "customer_id": "c1",
            },
            "agent": {"id": "a1", "name": "bot", "permission_level": 2},
            "customer": {"id": "c1"},
            "order": {
                "id": "o1",
                "customer_id": "c1",
                "status": "delivered",
                "total": "5000",
            },
            "policy": {
                "brand_id": "brand_test",
                "auto_approve_limit": "2000",
                "human_review_limit": "10000",
            },
        }
        outcome = service.process("conn_x", request)
        assert outcome["outcome"] == "executed_with_mismatch"
        assert outcome["verification"]["mismatch"] is True
        assert outcome["verification"]["difference"] == "9499.00"


# ---------------------------------------------------------------------------
# 2. agent lifecycle: quarantine + kill switch
# ---------------------------------------------------------------------------


class TestAgentLifecycle:
    def test_pause_blocks_verification(self) -> None:
        authority = CredentialAuthority(signing_key="k")
        token, _ = authority.issue("a1", "b1", 2)
        authority.pause("a1")
        with pytest.raises(AgentStateError, match="paused"):
            authority.verify(token, brand_id="b1")
        authority.resume("a1")
        assert authority.verify(token, brand_id="b1").agent_id == "a1"

    def test_quarantine_flags_but_does_not_block_verification(self) -> None:
        authority = CredentialAuthority(signing_key="k")
        token, _ = authority.issue("a1", "b1", 2)
        authority.quarantine("a1")
        cred = authority.verify(token, brand_id="b1")
        assert cred.lifecycle_state == AGENT_QUARANTINED

    def test_quarantine_forces_review_in_firewall(self) -> None:
        store = AuditStore()
        fw = FirewallEngine(store, ReviewStore(store))
        authority = CredentialAuthority()
        fw.credential_authority = authority
        request = _request(Decimal("500"))
        assert fw.evaluate(request).decision.value == "ALLOW"
        authority.quarantine(request.agent.id)
        verdict = fw.evaluate(request)
        assert verdict.decision.value == "REVIEW"
        assert any("quarantined" in r for r in verdict.reasons)
        assert verdict.review_id is not None
        assert verdict.audit["provenance"]["lifecycle_state"] == "quarantined"

    def test_kill_switch_pauses_and_resume_all_restores(self) -> None:
        authority = CredentialAuthority(signing_key="k")
        t1, _ = authority.issue("a1", "b1", 2)
        t2, _ = authority.issue("a2", "b1", 2)
        paused = authority.kill_switch()
        assert paused == ["a1", "a2"]
        for token in (t1, t2):
            with pytest.raises(AgentStateError):
                authority.verify(token, brand_id="b1")
        assert authority.resume_all() == ["a1", "a2"]
        assert authority.verify(t1, brand_id="b1").agent_id == "a1"
        assert authority.verify(t2, brand_id="b1").agent_id == "a2"

    def test_quarantine_survives_kill_switch_cycle(self) -> None:
        authority = CredentialAuthority(signing_key="k")
        authority.issue("a1", "b1", 2)
        authority.quarantine("a1")
        authority.kill_switch()
        authority.resume_all()
        assert authority.state_of("a1") == AGENT_QUARANTINED


# ---------------------------------------------------------------------------
# 3. policy simulator
# ---------------------------------------------------------------------------


def _build_history(audit: AuditStore, fw: FirewallEngine) -> tuple[PolicyPackStore, Any]:
    fw_engine = fw
    packs = PolicyPackStore()
    fw_engine.policy_packs = packs
    candidate = BrandPolicy(
        brand_id="brand_x",
        auto_approve_limit="100",
        low_risk_limit="250",
        human_review_limit="10000",
        max_refund_ratio="1.00",
    )
    packs.create(brand_id="brand_x", policy=candidate)
    for i in range(12):
        fw_engine.evaluate(
            FirewallRequest(
                action=make_action(amount=Decimal(100 * (i + 1))),
                agent=make_agent(),
                customer=make_customer(),
                order=make_order(total=Decimal("5000")),
                policy=make_policy(),
                conversation=[],
            )
        )
    return packs, candidate


class TestPolicySimulator:
    def test_replay_reports_decision_delta(self) -> None:
        audit = AuditStore()
        fw = FirewallEngine(audit, ReviewStore(audit))
        _packs, _cand = _build_history(audit, fw)
        report = PolicySimulator(fw, audit).simulate_pack(
            pack_id=_packs.list()[0].pack_id, limit=100
        )
        assert report["replayed"] == 12
        assert report["baseline"] == {"ALLOW": 12, "REVIEW": 0, "BLOCK": 0}
        assert report["candidate"]["REVIEW"] == 10
        assert report["summary"]["would_review"] == 10
        assert report["summary"]["newly_reviewed_exposure"] == "7500.00"
        assert report["summary"]["change_rate"] == round(10 / 12, 4)

    def test_replay_never_pollutes_review_queue(self) -> None:
        audit = AuditStore()
        reviews = ReviewStore(audit)
        fw = FirewallEngine(audit, reviews)
        packs, _cand = _build_history(audit, fw)
        before = len(reviews.list())
        PolicySimulator(fw, audit).simulate_pack(pack_id=packs.list()[0].pack_id, limit=100)
        assert len(reviews.list()) == before  # no real review items opened

    def test_replay_records_are_tagged_and_chain_intact(self) -> None:
        audit = AuditStore()
        fw = FirewallEngine(audit, ReviewStore(audit))
        packs, _cand = _build_history(audit, fw)
        PolicySimulator(fw, audit).simulate_pack(pack_id=packs.list()[0].pack_id, limit=100)
        assert audit.verify_chain(force=True) is True
        last = audit.list(limit=1)[0][0].record
        assert (last.provenance or {}).get("simulation", "").startswith("sim:pack_")

    def test_unknown_pack_raises_keyerror(self) -> None:
        audit = AuditStore()
        fw = FirewallEngine(audit, ReviewStore(audit))
        fw.policy_packs = PolicyPackStore()
        with pytest.raises(KeyError):
            PolicySimulator(fw, audit).simulate_pack(pack_id="pack_nope")

    def test_simulate_endpoint(self) -> None:
        client = TestClient(
            create_app(
                overrides={
                    "seed_demo_data": False,
                    "admin_token": "op-admin",
                    "store_backend": "memory",
                }
            )
        )
        headers = {"X-Admin-Token": "op-admin"}
        # create candidate pack
        pack = client.post(
            "/v1/policy-packs",
            params={"brand_id": "brand_sim"},
            json={
                "brand_id": "brand_sim",
                "auto_approve_limit": "100",
                "low_risk_limit": "250",
                "human_review_limit": "10000",
            },
            headers=headers,
        )
        assert pack.status_code == 200, pack.text
        pack_id = pack.json()["pack_id"]
        # no history yet: empty replay is fine
        report = client.post(
            f"/v1/policy-packs/{pack_id}/simulate?limit=50", headers=headers
        )
        assert report.status_code == 200, report.text
        body = report.json()
        assert body["pack_id"] == pack_id
        assert body["replayed"] == 0
        # unknown pack -> 404
        missing = client.post("/v1/policy-packs/pack_nope/simulate", headers=headers)
        assert missing.status_code == 404


class TestAgentLifecycleEndpoints:
    def test_kill_switch_endpoints(self) -> None:
        client = TestClient(
            create_app(
                overrides={
                    "seed_demo_data": False,
                    "admin_token": "op-admin",
                    "store_backend": "memory",
                }
            )
        )
        headers = {"X-Admin-Token": "op-admin"}
        cred = client.post(
            "/v1/credentials",
            json={"agent_id": "agt_kill", "brand_id": "brand_x", "permission_level": 2},
            headers=headers,
        )
        assert cred.status_code == 200, cred.text
        agents = client.get("/v1/agents", headers=headers)
        assert agents.status_code == 200
        assert agents.json()["agents"].get("agt_kill") == "active"

        paused = client.post("/v1/agents/kill-switch", headers=headers)
        assert paused.status_code == 200
        assert "agt_kill" in paused.json()["paused"]

        resumed = client.post("/v1/agents/resume-all", headers=headers)
        assert resumed.status_code == 200
        assert "agt_kill" in resumed.json()["resumed"]

    def test_quarantine_endpoint(self) -> None:
        client = TestClient(
            create_app(
                overrides={
                    "seed_demo_data": False,
                    "admin_token": "op-admin",
                    "store_backend": "memory",
                }
            )
        )
        headers = {"X-Admin-Token": "op-admin"}
        q = client.post("/v1/agents/agt_q/quarantine", headers=headers)
        assert q.status_code == 200
        assert q.json()["state"] == "quarantined"
        agents = client.get("/v1/agents", headers=headers).json()["agents"]
        assert agents["agt_q"] == "quarantined"
