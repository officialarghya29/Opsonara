"""Opsonara API — the Agent Transaction Firewall HTTP surface.

    POST /v1/evaluate            evaluate a proposed agent action
    GET  /v1/audit               audit trail (paginated, filterable)
    GET  /v1/audit/{id}          one audit record
    GET  /v1/audit/verify        hash-chain integrity check
    GET  /v1/reviews             human review queue
    POST /v1/reviews/{id}/decision  human approve/reject
    GET  /v1/stats               dashboard metrics
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError

from opsonara.commercial import DecisionExplainer, StripeBilling, UsageMeter
from opsonara.config import settings
from opsonara.connectors import (
    ConnectorService,
    verify_generic_webhook,
    verify_shopify_webhook,
)
from opsonara.core.exceptions import AlreadyResolvedError, NotFoundError
from opsonara.core.models import BrandPolicy
from opsonara.firewall import AuthContext, FirewallEngine, FirewallRequest
from opsonara.idempotency import MemoryIdempotencyStore, fingerprint_payload
from opsonara.identity import Ap2MandateVerifier, CredentialAuthority, MandateRegistry
from opsonara.learning import RecalibrationEngine, open_outcome_store
from opsonara.multitenant import (
    BrandRegistry,
    BrandTenant,
    build_auth_dependency,
    issue_api_key,
    new_brand_id,
    register_key,
)
from opsonara.policy_store import PolicyPackStore
from opsonara.simulator import PolicySimulator
from opsonara.stores import make_stores
from opsonara.verification import ExecutionVerifier

logger = logging.getLogger("opsonara.api")


class ReviewDecisionRequest(BaseModel):
    """Body for the human decision endpoint."""

    approved: bool
    reviewer: str = Field(min_length=1, max_length=120, pattern=r"\S")
    """Must contain a non-whitespace char — the two-person rule keys
    distinct approvals on this name, so blank names are a client error."""


class CreateBrandRequest(BaseModel):
    """Body for brand registration. The signing secret travels in the body
    (never a URL/query, which end up in access logs and proxies)."""

    name: str = Field(min_length=1, max_length=120)
    signing_secret: str | None = Field(default=None, max_length=256)
    rate_limit_per_minute: int | None = Field(default=None, ge=0)


class IssueCredentialRequest(BaseModel):
    """Body for credential issuance."""

    agent_id: str = Field(min_length=1, max_length=64)
    brand_id: str = Field(min_length=1, max_length=64)
    permission_level: int = Field(default=1, ge=0, le=3)
    ttl_seconds: int = Field(default=3600, ge=30, le=86400 * 30)


class ShadowWeightsRequest(BaseModel):
    """Body for starting a shadow weight run."""

    weights: dict[str, str]


class RecalibrateRequest(BaseModel):
    """Body for manual recalibration triggers."""

    brand_id: str = Field(min_length=1, max_length=64)
    min_outcomes: int = Field(default=10, ge=1, le=10_000)


class ConnectorProcessRequest(BaseModel):
    """Body for the connector process endpoint."""

    request: dict[str, Any]


# ---------------------------------------------------------------------------
# app factory
# ---------------------------------------------------------------------------


def create_app(overrides: dict[str, Any] | None = None) -> FastAPI:
    """Create the app; ``overrides`` lets tests override settings hermetically."""
    if overrides:
        app_settings = settings.model_copy(update=overrides)
    else:
        app_settings = settings

    if app_settings.mode == "production":
        # Secure-by-default hardening (spec §65). Deliberate operator choices
        # are preserved; permissive leftovers are overridden or refused.
        if app_settings.auth_mode != "api_key":
            raise RuntimeError(
                "OPSONARA_MODE=production requires OPSONARA_AUTH_MODE=api_key"
            )
        if not app_settings.admin_token:
            raise RuntimeError(
                "OPSONARA_MODE=production requires an explicit OPSONARA_ADMIN_TOKEN"
            )
        _cors = app_settings.cors_origins.strip()
        if _cors in ("", "*"):
            raise RuntimeError(
                "OPSONARA_MODE=production requires OPSONARA_CORS_ORIGINS "
                "(comma-separated origins; '*' is not allowed)"
            )
        app_settings = app_settings.model_copy(
            update={
                "seed_demo_data": False,
                "credential_verification": "strict",
            }
        )
    app = FastAPI(
        title=app_settings.app_name,
        version=app_settings.version,
        description=(
            "Risk intelligence and authorization for AI agents in D2C "
            "e-commerce. Every agent-proposed action is evaluated by the "
            "Context, Policy, and Risk engines before it may execute; "
            "every decision is recorded in a tamper-evident audit trail."
        ),
    )
    app.state.settings = app_settings

    origins = (
        "*"
        if app_settings.cors_origins.strip() == "*"
        else [o.strip() for o in app_settings.cors_origins.split(",") if o.strip()]
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    audit_store, review_store = make_stores(
        app_settings.store_backend, app_settings.db_path, pg_dsn=app_settings.pg_dsn
    )
    firewall = FirewallEngine(audit_store=audit_store, review_store=review_store)

    # -- multi-tenant gateway, policy packs, identity, learning, commercial -----
    # Bootstrap: in api_key mode with no operator token configured, generate a
    # per-boot token and surface it once in the log (operator must grab it
    # there). Production sets OPSONARA_ADMIN_TOKEN explicitly.
    operator_token = app_settings.admin_token
    if app_settings.auth_mode == "api_key" and not operator_token:
        import secrets as _secrets

        operator_token = _secrets.token_urlsafe(32)
        logger.warning(
            "OPSONARA_ADMIN_TOKEN not set; generated a per-boot operator token. "
            "Set it explicitly for production. Token (this boot only): %s",
            operator_token,
        )
    registry = BrandRegistry()
    policy_packs = PolicyPackStore()
    firewall.policy_packs = policy_packs
    credential_authority = CredentialAuthority()
    mandate_registry = MandateRegistry()
    mandate_registry.register(Ap2MandateVerifier(brand_secrets={}))
    firewall.credential_authority = credential_authority
    firewall.mandate_registry = mandate_registry
    firewall.credential_mode = app_settings.credential_verification
    auth_dependency = build_auth_dependency(
        registry,
        auth_mode=app_settings.auth_mode,
        signing_required=app_settings.auth_signing_required,
        default_limit=app_settings.rate_limit_per_minute,
    )
    admin_dependency = build_auth_dependency(
        registry,
        auth_mode=app_settings.auth_mode,
        signing_required=app_settings.auth_signing_required,
        default_limit=app_settings.rate_limit_per_minute,
        require_admin=True,
        bootstrap_admin_token=operator_token,
    )
    outcome_store = open_outcome_store()
    idempotency_store = MemoryIdempotencyStore()
    recalibration = RecalibrationEngine(outcome_store)
    connector_service = ConnectorService(
        firewall,
        review_store,
        verifier=ExecutionVerifier(audit_store),
    )
    webhook_secrets: dict[str, str] = {}
    for pair in app_settings.webhook_secrets.split(","):
        pair = pair.strip()
        if pair and "=" in pair:
            name, _, secret = pair.partition("=")
            webhook_secrets[name.strip()] = secret.strip()
    usage_meter = UsageMeter()
    billing = StripeBilling(
        usage_meter,
        api_key=app_settings.stripe_api_key,
        dry_run=app_settings.billing_dry_run,
    )
    explainer = DecisionExplainer()

    # Seed only an empty store: on sqlite this survives restarts without
    # duplicating demo rows; on memory it runs fresh each boot.
    _, existing_total = audit_store.list(limit=1)
    if app_settings.seed_demo_data and existing_total == 0:
        from opsonara.demo_data import seed

        seed(audit_store, review_store, firewall)
        logger.info("seeded demo data for the dashboard")

    app.state.audit_store = audit_store
    app.state.review_store = review_store
    app.state.firewall = firewall
    app.state.brand_registry = registry
    app.state.policy_packs = policy_packs
    app.state.credential_authority = credential_authority
    app.state.mandate_registry = mandate_registry
    app.state.outcome_store = outcome_store
    app.state.idempotency_store = idempotency_store
    app.state.connector_service = connector_service
    app.state.usage_meter = usage_meter
    app.state.billing = billing

    @app.exception_handler(NotFoundError)
    async def _not_found(_: Any, exc: NotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Any, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default 422 echoes the offending input back to the
        # caller. A lone UTF-16 surrogate in that echo cannot be UTF-8
        # encoded, which turned *good* validation errors into 500s.
        # Replace every unencodable character instead.
        detail = json.loads(json.dumps(exc.errors(), default=str))
        for err in detail:
            if isinstance(err.get("input"), str):
                err["input"] = err["input"].encode("utf-8", "replace").decode("utf-8")
        return JSONResponse(status_code=422, content={"detail": detail})

    @app.exception_handler(AlreadyResolvedError)
    async def _resolved(_: Any, exc: AlreadyResolvedError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    # ------------------------------------------------------------------
    # meta
    # ------------------------------------------------------------------

    @app.get("/", tags=["meta"])
    async def root() -> dict[str, Any]:
        return {
            "service": app_settings.app_name,
            "version": app_settings.version,
            "tagline": "Don't make AI agents less autonomous. Make their autonomy controllable.",
            "docs": "/docs",
            "endpoints": [
                "POST /v1/evaluate",
                "GET  /v1/audit",
                "GET  /v1/audit/verify",
                "GET  /v1/reviews",
                "POST /v1/reviews/{id}/decision",
                "GET  /v1/stats",
            ],
        }

    @app.get("/health", tags=["meta"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": app_settings.app_name, "version": app_settings.version}

    # ------------------------------------------------------------------
    # firewall
    # ------------------------------------------------------------------

    @app.post("/v1/evaluate", tags=["firewall"])
    async def evaluate(
        request: FirewallRequest,
        brand: Any = Depends(auth_dependency),  # noqa: B008 — FastAPI idiom
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        """Evaluate a proposed agent action through the full pipeline.

        Send an ``Idempotency-Key`` header on consequential actions: the
        first call's verdict is cached and replayed verbatim for retries,
        so a network timeout can never cause a second refund. A duplicate
        while the first is still in flight gets 409; a same-key-different-
        body request gets 422 (client bug or tampering).

        Inconsistent context (e.g. action.customer_id not matching the
        order's customer) is a client error, so a raw ``ValueError`` from
        the context engine is surfaced as HTTP 422 — never a 500.
        """
        # -- idempotency gate (spec §24) -------------------------------------
        key = idempotency_key.strip() if idempotency_key else ""
        fp = ""
        if key:
            if len(key) > 256:
                raise HTTPException(status_code=422, detail="Idempotency-Key too long (max 256)")
            fp = fingerprint_payload(request.model_dump(mode="json"))
            cached = idempotency_store.get(key)
            if cached is not None:
                if cached["fingerprint"] != fp:
                    raise HTTPException(
                        status_code=422,
                        detail="Idempotency-Key was already used with a different request body",
                    )
                replay = dict(cached["response"])
                replay["idempotency_replayed"] = True
                return replay
            if not idempotency_store.claim(key, fp):
                # Same key, still processing elsewhere → caller must wait.
                raise HTTPException(status_code=409, detail="request with this Idempotency-Key is in flight")

        try:
            # Anonymous/dev calls (auth off → tenant "public") adopt the
            # request policy's own brand_id so learning data and audits
            # land under the brand the caller actually declared.
            effective_brand = (
                brand.brand_id
                if brand.brand_id != "public"
                else request.policy.brand_id or "public"
            )
            result = firewall.evaluate(request, auth=AuthContext(brand_id=effective_brand))
        except ValueError as exc:
            if key:
                idempotency_store.release(key)  # allow a clean retry
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        body = result.model_dump(mode="json")
        usage_meter.record(effective_brand, "/v1/evaluate", result.decision.value)
        if key:
            idempotency_store.complete(key, fp, body)
        return body

    # ------------------------------------------------------------------
    # audit trail
    # ------------------------------------------------------------------

    @app.get("/v1/audit/verify", tags=["audit"])
    async def verify_chain() -> dict[str, Any]:
        # force=True: the authoritative integrity endpoint must walk the
        # whole chain, not trust the incremental verified-prefix cache.
        return {
            "intact": audit_store.verify_chain(force=True),
            "scheme": "sha256 hash-chain (each record commits to its predecessor)",
        }

    @app.get("/v1/audit", tags=["audit"])
    async def list_audit(
        limit: int = Query(default=50, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        decision: Literal["ALLOW", "REVIEW", "BLOCK"] | None = None,
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        page, total = audit_store.list(
            limit=limit, offset=offset, decision=decision, agent_id=agent_id
        )
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": [s.to_dict() for s in page],
        }

    @app.get("/v1/audit/{audit_id}", tags=["audit"])
    async def get_audit(audit_id: str) -> dict[str, Any]:
        return audit_store.get(audit_id).to_dict()

    # ------------------------------------------------------------------
    # human review queue
    # ------------------------------------------------------------------

    @app.get("/v1/reviews", tags=["reviews"])
    async def list_reviews(
        status: Literal["pending", "approved", "rejected"] | None = None,
    ) -> dict[str, Any]:
        items = review_store.list(status=status)
        return {"total": len(items), "items": [i.to_dict() for i in items]}

    @app.get("/v1/reviews/{review_id}", tags=["reviews"])
    async def get_review(review_id: str) -> dict[str, Any]:
        return review_store.get(review_id).to_dict()

    @app.post("/v1/reviews/{review_id}/decision", tags=["reviews"])
    async def decide_review(
        review_id: str,
        body: ReviewDecisionRequest,
    ) -> dict[str, Any]:
        item, human_record, human_audit_id = review_store.decide(
            review_id, approved=body.approved, reviewer=body.reviewer.strip()
        )
        # Learning loop: pair the human verdict with the original signals so
        # per-brand recalibration can learn from real outcomes. A *partial*
        # first approval (two-person rule) is not a verdict — the outcome is
        # only recorded once the review actually resolves.
        resolved = item.status.value != "pending"
        if resolved:
            origin = audit_store.get(item.audit_id)
            outcome_store.record(
                audit_id=item.audit_id,
                brand_id=origin.record.brand_id or "default",  # legacy rows predate brand ids
                review_id=review_id,
                approved=body.approved,
                risk_score=str(origin.record.risk_score),
                signals={f.name: str(f.score) for f in origin.record.risk_factors},
            )
        return {
            "review": item.to_dict(),
            "human_audit_id": human_audit_id,
            "awaiting_approvals": (
                max(item.required_approvals - len(item.approvals), 0)
                if item.status.value == "pending"
                else 0
            ),
        }

    # ------------------------------------------------------------------
    # dashboard stats
    # ------------------------------------------------------------------

    @app.get("/v1/stats", tags=["meta"])
    async def stats() -> dict[str, Any]:
        # All components are O(1) per call (incremental counters), so the
        # endpoint stays correct and cheap at any volume. A page-limited
        # list would silently undercount past its cap.
        counts = audit_store.counts()
        return {
            "total_decisions": counts["total"],
            "by_decision": counts["by_decision"],
            "by_risk_band": counts["by_risk_band"],
            "pending_reviews": review_store.count_pending(),
            "audit_chain_intact": audit_store.verify_chain(),
        }

    # ------------------------------------------------------------------
    # multi-tenant gateway administration
    # ------------------------------------------------------------------

    @app.post("/v1/brands", tags=["gateway"])
    async def create_brand(
        body: CreateBrandRequest,
        _: Any = Depends(admin_dependency),  # noqa: B008
    ) -> dict[str, Any]:
        """Register a brand tenant; returns the API key exactly once.

        Operator-only (admin gate). The brand_id is random and independent
        of key material; the signing secret stays in the request body.
        """
        raw_key, prefix = issue_api_key()
        tenant = BrandTenant(
            brand_id=new_brand_id(),
            name=body.name,
            signing_secret=body.signing_secret,
            rate_limit_per_minute=body.rate_limit_per_minute,
        )
        register_key(tenant, raw_key)
        registry.upsert(tenant)
        return {"brand_id": tenant.brand_id, "name": body.name, "api_key": raw_key, "prefix": prefix}

    @app.get("/v1/brands", tags=["gateway"])
    async def list_brands() -> dict[str, Any]:
        return {
            "brands": [
                {
                    "brand_id": t.brand_id,
                    "name": t.name,
                    "keys": len(t.key_hashes),
                    "signing": t.signing_secret is not None,
                    "rate_limit": t.rate_limit_per_minute,
                }
                for t in registry.all()
                if t.brand_id != "public"
            ]
        }

    # ------------------------------------------------------------------
    # policy packs (multi-tenant rules-as-data)
    # ------------------------------------------------------------------

    @app.post("/v1/policy-packs", tags=["policy-packs"])
    async def create_policy_pack(
        brand_id: str,
        policy: BrandPolicy,
        created_by: str = "api",
    ) -> dict[str, Any]:
        pack = policy_packs.create(brand_id, policy, created_by=created_by)
        return {"pack_id": pack.pack_id, "version": pack.version, "state": pack.state}

    @app.get("/v1/policy-packs", tags=["policy-packs"])
    async def list_policy_packs(brand_id: str | None = None) -> dict[str, Any]:
        return {
            "packs": [
                {
                    "pack_id": p.pack_id,
                    "brand_id": p.brand_id,
                    "version": p.version,
                    "state": p.state,
                    "created_at": p.created_at.isoformat(),
                    "created_by": p.created_by,
                }
                for p in policy_packs.list(brand_id)
            ]
        }

    @app.post("/v1/policy-packs/{pack_id}/activate", tags=["policy-packs"])
    async def activate_policy_pack(pack_id: str) -> dict[str, Any]:
        try:
            pack = policy_packs.activate(pack_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"pack_id": pack.pack_id, "state": pack.state}

    @app.post("/v1/policy-packs/{pack_id}/simulate", tags=["policy-packs"])
    async def simulate_policy_pack(
        pack_id: str,
        limit: int = Query(default=500, ge=1, le=5000),
        brand_id: str | None = Query(default=None),
        _: Any = Depends(admin_dependency),  # noqa: B008
    ) -> dict[str, Any]:
        """Replay history under a candidate pack WITHOUT deploying it
        (spec §12). Reports the decision delta, newly reviewed/blocked
        exposure, and review reduction."""
        simulator = PolicySimulator(firewall, audit_store)
        try:
            return simulator.simulate_pack(
                pack_id=pack_id, brand_id=brand_id, limit=limit
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    # ------------------------------------------------------------------
    # agent identity: credentials & mandates
    # ------------------------------------------------------------------

    @app.post("/v1/credentials", tags=["identity"])
    async def issue_credential(
        body: IssueCredentialRequest,
        _: Any = Depends(admin_dependency),  # noqa: B008
    ) -> dict[str, Any]:
        """Issue a signed agent credential (operator-only)."""
        token, cred = credential_authority.issue(
            body.agent_id,
            body.brand_id,
            body.permission_level,
            ttl_seconds=body.ttl_seconds,
        )
        return {"token": token, "expires_at": cred.expires_at, "agent_id": body.agent_id}

    @app.post("/v1/credentials/{agent_id}/revoke", tags=["identity"])
    async def revoke_credential(
        agent_id: str,
        _: Any = Depends(admin_dependency),  # noqa: B008
    ) -> dict[str, Any]:
        credential_authority.revoke(agent_id)
        return {"agent_id": agent_id, "revoked": True}

    # -- agent lifecycle: kill switch & quarantine (spec §3, §28–§29) ------

    @app.get("/v1/agents", tags=["agents"])
    async def list_agents(
        _: Any = Depends(admin_dependency),  # noqa: B008
    ) -> dict[str, Any]:
        """Every known agent with its lifecycle state (dashboard AGENTS view)."""
        return {"agents": credential_authority.agents()}

    @app.post("/v1/agents/{agent_id}/pause", tags=["agents"])
    async def pause_agent(
        agent_id: str,
        _: Any = Depends(admin_dependency),  # noqa: B008
    ) -> dict[str, Any]:
        state = credential_authority.pause(agent_id)
        return {"agent_id": agent_id, "state": state, "known": credential_authority.is_known(agent_id)}

    @app.post("/v1/agents/{agent_id}/resume", tags=["agents"])
    async def resume_agent(
        agent_id: str,
        _: Any = Depends(admin_dependency),  # noqa: B008
    ) -> dict[str, Any]:
        state = credential_authority.resume(agent_id)
        return {"agent_id": agent_id, "state": state, "known": credential_authority.is_known(agent_id)}

    @app.post("/v1/agents/{agent_id}/quarantine", tags=["agents"])
    async def quarantine_agent(
        agent_id: str,
        _: Any = Depends(admin_dependency),  # noqa: B008
    ) -> dict[str, Any]:
        """Contain a suspect agent: reads continue, sensitive actions are
        forced to human review until an operator resumes it."""
        state = credential_authority.quarantine(agent_id)
        return {"agent_id": agent_id, "state": state, "known": credential_authority.is_known(agent_id)}

    @app.post("/v1/agents/kill-switch", tags=["agents"])
    async def kill_switch(
        _: Any = Depends(admin_dependency),  # noqa: B008
    ) -> dict[str, Any]:
        """PAUSE ALL AGENTS (the dashboard's big red button)."""
        paused = credential_authority.kill_switch()
        return {"paused": paused, "count": len(paused)}

    @app.post("/v1/agents/resume-all", tags=["agents"])
    async def resume_all_agents(
        _: Any = Depends(admin_dependency),  # noqa: B008
    ) -> dict[str, Any]:
        restored = credential_authority.resume_all()
        return {"resumed": restored, "count": len(restored)}

    @app.get("/v1/mandates/schemes", tags=["identity"])
    async def mandate_schemes() -> dict[str, Any]:
        return {"schemes": mandate_registry.schemes()}

    # ------------------------------------------------------------------
    # connectors (Shopify / WooCommerce / generic webhook)
    # ------------------------------------------------------------------

    @app.get("/v1/connectors", tags=["connectors"])
    async def list_connectors() -> dict[str, Any]:
        return {"connectors": connector_service.list()}

    @app.post("/v1/webhooks/shopify", tags=["connectors"])
    async def shopify_webhook_ingest(request: Request) -> dict[str, Any]:
        """Inbound Shopify webhook: verify signature, then evaluate the
        embedded action through the firewall.

        Configure the same secret in the Shopify app and in
        ``OPSONARA_WEBHOOK_SECRETS`` (comma-separated brand=secret pairs).
        Unauthenticated webhooks are rejected with 401 — never processed.
        """
        raw = await request.body()
        header_sig = request.headers.get("X-Shopify-Hmac-Sha256")
        verified = False
        for secret in webhook_secrets.values():
            if verify_shopify_webhook(raw, secret=secret, header_value=header_sig):
                verified = True
                break
        if not verified:
            raise HTTPException(status_code=401, detail="webhook signature invalid or missing")
        payload = await request.json()
        try:
            return connector_service.process(payload["connector_id"], payload["request"])
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/v1/webhooks/generic", tags=["connectors"])
    async def generic_webhook_ingest(request: Request) -> dict[str, Any]:
        """Inbound generic webhook (HMAC over ``{ts}.{raw_body}``, hex)."""
        raw = await request.body()
        verified = verify_generic_webhook(
            raw,
            secret=next(iter(webhook_secrets.values()), ""),
            timestamp=request.headers.get("X-Opsonara-Timestamp"),
            signature=request.headers.get("X-Opsonara-Signature"),
        )
        if not verified:
            raise HTTPException(status_code=401, detail="webhook signature invalid or missing")
        payload = await request.json()
        try:
            return connector_service.process(payload["connector_id"], payload["request"])
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/v1/connectors/{connector_id}/process", tags=["connectors"])
    async def process_connector(
        connector_id: str,
        body: ConnectorProcessRequest,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        """Evaluate via the connector's firewall, then execute/hold/refuse.

        This endpoint **executes real platform actions** — send an
        ``Idempotency-Key``: the first call's outcome is cached and retries
        replay it, so a timeout after execution can never cause the platform
        to be called twice.
        """
        key = idempotency_key.strip() if idempotency_key else ""
        if len(key) > 256:
            raise HTTPException(status_code=422, detail="Idempotency-Key too long (max 256)")
        fp = fingerprint_payload({"connector_id": connector_id, "request": body.request})
        if key:
            cached = idempotency_store.get(key)
            if cached is not None:
                if cached["fingerprint"] != fp:
                    raise HTTPException(
                        status_code=422,
                        detail="Idempotency-Key was already used with a different request body",
                    )
                replay = dict(cached["response"])
                replay["idempotency_replayed"] = True
                return replay
            if not idempotency_store.claim(key, fp):
                raise HTTPException(status_code=409, detail="request with this Idempotency-Key is in flight")
        try:
            result = connector_service.process(connector_id, body.request)
        except KeyError as exc:
            if key:
                idempotency_store.release(key)
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValidationError as exc:
            # Inner FirewallRequest validation (raw dict from the caller).
            # Without this, a malformed inner payload is a 500.
            if key:
                idempotency_store.release(key)
            raise HTTPException(status_code=422, detail=json.loads(exc.json())) from exc
        if key:
            idempotency_store.complete(key, fp, result)
        return result

    # ------------------------------------------------------------------
    # learning loop
    # ------------------------------------------------------------------

    @app.post("/v1/learning/recalibrate", tags=["learning"])
    async def recalibrate(
        body: RecalibrateRequest,
        _: Any = Depends(admin_dependency),  # noqa: B008
    ) -> dict[str, Any]:
        new_set, info = recalibration.recalibrate(
            body.brand_id, min_outcomes=body.min_outcomes
        )
        if new_set is None:
            return info
        return {**info, "weights": {k: str(v) for k, v in new_set.weights.items()}}

    @app.get("/v1/learning/weights", tags=["learning"])
    async def learning_weights(brand_id: str) -> dict[str, Any]:
        ws = outcome_store.weights_for(brand_id)
        return {
            "brand_id": brand_id,
            "version": ws.version,
            "state": ws.state,
            "weights": {k: str(v) for k, v in ws.weights.items()},
        }

    @app.post("/v1/learning/shadow", tags=["learning"])
    async def start_shadow(
        brand_id: str,
        body: ShadowWeightsRequest,
        _: Any = Depends(admin_dependency),  # noqa: B008
    ) -> dict[str, Any]:
        from decimal import Decimal

        shadow = outcome_store.start_shadow(
            brand_id, {k: Decimal(v) for k, v in body.weights.items()}
        )
        return {"brand_id": brand_id, "state": shadow.state}

    @app.get("/v1/learning/shadow/status", tags=["learning"])
    async def shadow_status(brand_id: str) -> dict[str, Any]:
        shadow = outcome_store.shadow_for(brand_id)
        if shadow is None:
            return {"brand_id": brand_id, "state": "none"}
        return {
            "brand_id": brand_id,
            "state": shadow.state,
            "samples": shadow.shadow_hits,
            "agreements": shadow.shadow_agrees,
            "promotable": outcome_store.shadow_promotable(
                brand_id,
                min_samples=app_settings.shadow_min_samples,
                min_win_rate=app_settings.shadow_min_win_rate,
            ),
        }

    # ------------------------------------------------------------------
    # metering, billing & customer explainer
    # ------------------------------------------------------------------

    @app.get("/v1/usage", tags=["commercial"])
    async def usage(brand_id: str | None = None) -> dict[str, Any]:
        return usage_meter.usage(brand_id=brand_id)

    @app.get("/v1/billing/preview", tags=["commercial"])
    async def billing_preview(brand_id: str) -> dict[str, Any]:
        return billing.invoice_preview(brand_id)

    @app.post("/v1/billing/report", tags=["commercial"])
    async def billing_report(brand_id: str) -> dict[str, Any]:
        return billing.report_period(brand_id)

    @app.post("/v1/explain", tags=["commercial"])
    async def explain_decision(audit_id: str) -> dict[str, Any]:
        """Customer-safe explanation of a decision (no internal details)."""
        try:
            stored = audit_store.get(audit_id)
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return explainer.explain(stored.record.to_audit_dict())

    # ------------------------------------------------------------------
    # console UI (served from /app so it never shadows API docs)
    # ------------------------------------------------------------------

    frontend_dir = Path(__file__).resolve().parent.parent.parent / "frontend"
    if frontend_dir.is_dir():
        app.mount("/app", StaticFiles(directory=str(frontend_dir), html=True), name="console")

    return app


app = create_app()
