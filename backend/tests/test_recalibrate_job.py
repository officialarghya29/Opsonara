"""Tests for the weekly recalibration job (CLI)."""

from __future__ import annotations

import pytest

from opsonara.learning import DEFAULT_WEIGHTS, OutcomeStore, RecalibrationEngine
from opsonara.recalibrate_job import build_weight_change_record, main
from opsonara.stores.audit_store import AuditStore


def _seed_outcomes(store: OutcomeStore, brand_id: str, n: int = 10) -> None:
    for i in range(n):
        store.record(
            audit_id=f"aud_{brand_id}_{i}",
            brand_id=brand_id,
            review_id=None,
            approved=True,  # humans approve high-risk → weights step down
            risk_score="0.6",
            signals={"value_size": "0.9"},
        )


def test_weight_change_record_is_chainable_and_explains_itself() -> None:
    info = {
        "kind": "recalibrated",
        "brand_id": "brand_x",
        "version": 3,
        "outcomes_analyzed": 12,
        "changes": {"value_size": {"from": "0.3000", "to": "0.2800"}},
    }
    record = build_weight_change_record("brand_x", info)
    assert record.action == "adjust_authorization"
    assert record.brand_id == "brand_x"
    assert any("value_size: 0.3000 -> 0.2800" in r for r in record.reasons)
    # must satisfy the hash-chain invariants of the real store
    audit_store = AuditStore()
    audit_id = audit_store.append(record)
    assert audit_id.startswith("aud_")
    assert audit_store.verify_chain(force=True) is True


def test_job_promotes_and_writes_audit(capsys: pytest.CaptureFixture[str]) -> None:
    import opsonara.recalibrate_job as jobmod

    outcome_store = OutcomeStore()
    _seed_outcomes(outcome_store, "brand_job")

    class FakeStores:
        def __init__(self) -> None:
            self.appended: list[object] = []

        def append(self, record: object) -> str:
            self.appended.append(record)
            return "aud_fake"

    fake = FakeStores()

    original_make_stores = jobmod.make_stores
    original_engine_cls = jobmod.RecalibrationEngine

    def fake_make_stores(_backend: str, _path: str) -> tuple[FakeStores, object]:
        return fake, object()

    jobmod.make_stores = fake_make_stores  # type: ignore[assignment]
    # RecalibrationEngine should still work over the real outcome store —
    # patch its construction to use our seeded store.
    class PatchedEngine(RecalibrationEngine):
        def __init__(self, _store: object) -> None:
            super().__init__(outcome_store)

    jobmod.RecalibrationEngine = PatchedEngine  # type: ignore[assignment]
    try:
        rc = main(["--brand", "brand_job", "--min-outcomes", "10"])
    finally:
        jobmod.make_stores = original_make_stores  # type: ignore[assignment]
        jobmod.RecalibrationEngine = original_engine_cls

    assert rc == 0
    assert len(fake.appended) == 1
    record = fake.appended[0]
    assert record.brand_id == "brand_job"  # type: ignore[union-attr]
    new_weights = outcome_store.weights_for("brand_job").weights
    assert new_weights["value_size"] < DEFAULT_WEIGHTS["value_size"]


def test_job_dry_run_changes_nothing() -> None:
    import opsonara.recalibrate_job as jobmod

    outcome_store = OutcomeStore()
    _seed_outcomes(outcome_store, "brand_dry")

    appended: list[object] = []

    class FakeStores:
        def append(self, record: object) -> str:
            appended.append(record)
            return "aud_fake"

    original_make_stores = jobmod.make_stores
    original_engine_cls = jobmod.RecalibrationEngine

    def fake_make_stores(_backend: str, _path: str) -> tuple[FakeStores, object]:
        return FakeStores(), object()

    jobmod.make_stores = fake_make_stores  # type: ignore[assignment]

    class PatchedEngine(RecalibrationEngine):
        def __init__(self, _store: object) -> None:
            super().__init__(outcome_store)

    jobmod.RecalibrationEngine = PatchedEngine  # type: ignore[assignment]
    try:
        rc = main(["--brand", "brand_dry", "--min-outcomes", "10", "--dry-run"])
    finally:
        jobmod.make_stores = original_make_stores  # type: ignore[assignment]
        jobmod.RecalibrationEngine = original_engine_cls

    assert rc == 0
    assert appended == []  # nothing written
    # but the candidate weights were computed and stored as current
    assert (
        outcome_store.weights_for("brand_dry").weights["value_size"]
        < DEFAULT_WEIGHTS["value_size"]
    )
