"""Weekly recalibration job — runs the learning loop for every active brand.

Designed for cron / Kubernetes CronJob / GitHub Actions schedule:

    python -m opsonara.recalibrate_job                      # all brands
    python -m opsonara.recalibrate_job --brand brand_x      # one brand
    python -m opsonara.recalibrate_job --min-outcomes 25    # stricter gate
    python -m opsonara.recalibrate_job --dry-run            # report, no changes

Every promoted weight change is appended to the audit trail (as an
``adjust_authorization`` action with the weight diff as the reason), so the
model's own drift is tamper-evidently recorded — "who changed the risk
weights, when, and on what evidence" is answerable from the log.
"""

from __future__ import annotations

import argparse
import logging
import sys
from decimal import Decimal
from typing import Any

from opsonara.config import settings
from opsonara.core.models import AuditRecord, Decision, RiskBand
from opsonara.learning import RecalibrationEngine, open_outcome_store
from opsonara.stores import make_stores

logger = logging.getLogger("opsonara.recalibrate_job")


def build_weight_change_record(
    brand_id: str, change_info: dict[str, Any], *, reviewer: str = "recalibration-job"
) -> AuditRecord:
    """Audit record capturing one promoted weight change (itself chained)."""
    changes: dict[str, dict[str, str]] = change_info.get("changes", {}) or {}
    reasons = [
        f"{name}: {diff.get('from')} -> {diff.get('to')}"
        for name, diff in changes.items()
    ] or ["no effective weight change"]
    return AuditRecord(
        action="adjust_authorization",
        amount=Decimal("0"),
        currency="XXX",
        agent_id=reviewer,
        brand_id=brand_id,
        customer_risk=Decimal("0"),
        injection_risk=Decimal("0"),
        risk_score=Decimal("0"),
        risk_band=RiskBand.LOW,
        policy_status="allowed",
        authorization="granted",
        decision=Decision.ALLOW,
        reasons=[
            f"risk-weight recalibration v{change_info.get('version')} "
            f"from {change_info.get('outcomes_analyzed')} human outcomes",
            *reasons,
        ],
        policy_checks=[],
        risk_factors=[],
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--brand", help="recalibrate a single brand only")
    parser.add_argument(
        "--min-outcomes", type=int, default=10, help="new outcomes required per brand"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="report what would change; promote nothing"
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=settings.log_level, format="%(levelname)s %(name)s: %(message)s")

    audit_store, _review_store = make_stores(
        settings.store_backend, settings.db_path, pg_dsn=settings.pg_dsn
    )
    outcome_store = open_outcome_store()
    engine = RecalibrationEngine(outcome_store)

    brands = (
        [args.brand]
        if args.brand
        else sorted({o.brand_id for o in outcome_store.outcomes()})
    )
    if not brands:
        logger.info("no outcome data yet — nothing to recalibrate")
        return 0

    failures = 0
    for brand_id in brands:
        new_set, info = engine.recalibrate(brand_id, min_outcomes=args.min_outcomes)
        kind = info.get("kind")
        if kind == "recalibration_skipped":
            logger.info("[%s] skipped: %s", brand_id, info.get("reason"))
            continue
        if new_set is None:  # pragma: no cover - defensive
            failures += 1
            continue
        if args.dry_run:
            logger.info(
                "[%s] would promote v%s: %s",
                brand_id,
                info.get("version"),
                info.get("changes"),
            )
            continue
        audit_store.append(build_weight_change_record(brand_id, info))
        logger.info(
            "[%s] promoted weights v%s (%s outcomes analyzed, chain appended)",
            brand_id,
            info.get("version"),
            info.get("outcomes_analyzed"),
        )

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
