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

import logging
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from opsonara.config import settings
from opsonara.core.exceptions import AlreadyResolvedError, NotFoundError
from opsonara.core.models import Decision
from opsonara.firewall import FirewallEngine, FirewallRequest
from opsonara.stores.audit_store import AuditStore
from opsonara.stores.review_store import ReviewStore

logger = logging.getLogger("opsonara.api")


# ---------------------------------------------------------------------------
# app factory
# ---------------------------------------------------------------------------


def create_app(overrides: dict[str, Any] | None = None) -> FastAPI:
    """Create the app; ``overrides`` lets tests override settings hermetically."""
    if overrides:
        app_settings = settings.model_copy(update=overrides)
    else:
        app_settings = settings
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

    audit_store = AuditStore()
    review_store = ReviewStore(audit_store)
    firewall = FirewallEngine(audit_store=audit_store, review_store=review_store)

    if app_settings.seed_demo_data:
        from opsonara.demo_data import seed

        seed(audit_store, review_store, firewall)
        logger.info("seeded demo data for the dashboard")

    app.state.audit_store = audit_store
    app.state.review_store = review_store
    app.state.firewall = firewall

    @app.exception_handler(NotFoundError)
    async def _not_found(_: Any, exc: NotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

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
    async def evaluate(request: FirewallRequest) -> dict[str, Any]:
        """Evaluate a proposed agent action through the full pipeline."""
        return firewall.evaluate(request).model_dump(mode="json")

    # ------------------------------------------------------------------
    # audit trail
    # ------------------------------------------------------------------

    @app.get("/v1/audit/verify", tags=["audit"])
    async def verify_chain() -> dict[str, Any]:
        return {
            "intact": audit_store.verify_chain(),
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
        body: dict[str, Any],
    ) -> dict[str, Any]:
        approved = body.get("approved")
        reviewer = body.get("reviewer")
        if not isinstance(approved, bool) or not isinstance(reviewer, str) or not reviewer.strip():
            raise HTTPException(
                status_code=422,
                detail="body must be {\"approved\": bool, \"reviewer\": str}",
            )
        item, _human_record, human_audit_id = review_store.decide(
            review_id, approved=approved, reviewer=reviewer.strip()
        )
        return {
            "review": item.to_dict(),
            "human_audit_id": human_audit_id,
        }

    # ------------------------------------------------------------------
    # dashboard stats
    # ------------------------------------------------------------------

    @app.get("/v1/stats", tags=["meta"])
    async def stats() -> dict[str, Any]:
        all_items, total = audit_store.list(limit=500)
        by_decision = {d.value: 0 for d in Decision}
        by_band: dict[str, int] = {}
        for s in all_items:
            by_decision[s.record.decision.value] += 1
            band = s.record.risk_band.value
            by_band[band] = by_band.get(band, 0) + 1
        pending = review_store.list(status="pending")
        return {
            "total_decisions": total,
            "by_decision": by_decision,
            "by_risk_band": by_band,
            "pending_reviews": len(pending),
            "audit_chain_intact": audit_store.verify_chain(),
        }

    # ------------------------------------------------------------------
    # console UI (served from /app so it never shadows API docs)
    # ------------------------------------------------------------------

    frontend_dir = Path(__file__).resolve().parent.parent.parent / "frontend"
    if frontend_dir.is_dir():
        app.mount("/app", StaticFiles(directory=str(frontend_dir), html=True), name="console")

    return app


app = create_app()
