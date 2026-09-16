# Opsonara Efficiency Benchmarks

Measurements of the decision pipeline and stores, plus the improvement
analysis that drove the current optimizations. Re-run everything with:

```bash
cd backend
python benchmarks/bench.py            # human-readable
python benchmarks/bench.py --markdown # paste-ready table
```

## Methodology

* Single-threaded `time.perf_counter` loops, ~1 s per measurement, warmup first —
  numbers are a conservative floor; uvicorn workers scale beyond this.
* Hardware: dev machine, Python 3.12. Treat deltas, not absolutes, as the signal.
* "Pipeline" = Context → Policy → Risk → Decision + audit write + review
  enqueue (the full work of one `evaluate()` call).
* Variance: cold-start runs (first execution after boot / cold caches) read
  ~2,500 ops/s; once warm, the same measurements plateau at ~5,000–7,000
  ops/s. Both are reported below — never compare a cold run to a warm one.

## Current results

| Metric | Cold run | Warm plateau |
|---|---|---|
| Pipeline ALLOW (ops/s) | ~2,500 | ~6,700–7,000 |
| Pipeline REVIEW (ops/s) | ~2,100 | ~5,100 |
| Pipeline BLOCK (ops/s) | ~2,300 | ~6,700–6,900 |
| ContextEngine.build (ops/s) | ~100,000 |
| PolicyEngine.evaluate (ops/s) | ~26,000 |
| RiskEngine.evaluate (ops/s) | ~13,000 |
| DecisionEngine.decide (ops/s) | ~250,000 |
| Injection scan, 2 turns (ops/s) | ~36,000 |
| Injection scan, 200 turns (ops/s) | ~500 |
| Audit append, in-memory (ops/s) | ~20,000 |
| Audit list page (ops/s) | ~325,000 |
| Chain verify (ops/s over 27k records) | ~15 |

## Optimizations applied (baseline → now)

| Area | Before | After | Change | What was done |
|---|---|---|---|---|
| Injection scan (1 customer msg) | 26,400 ops/s | 35,800 ops/s | **+36%** | single compiled alternation regex + O(1) keyword→weight dict instead of one regex per pattern |
| Injection scan (100 msgs) | 383 ops/s | 554 ops/s | **+45%** | same |
| DecisionEngine.decide | 7,600 ops/s* | 250,000 ops/s | **33×** | *bench bug: earlier run re-executed policy+risk inside the timed lambda; combiner itself is O(1) |
| Audit list (25 newest of N) | 8,900 ops/s | 325,000 ops/s | **37×** | reverse slice of the backing list instead of full copy + reverse per call |

## HTTP load tests (real server, concurrent clients)

Run with `backend/benchmarks/loadtest.py` (spawns uvicorn, drives it with a
threaded stdlib HTTP client, asserts chain integrity and decision totals
afterwards). All runs with zero errors; the hash chain verified intact under
load in every scenario.

| Scenario (populated store) | Before optimization | After | Notes |
|---|---|---|---|
| `/v1/evaluate` mixed traffic, 32 threads, SQLite | 394 req/s · p50 82 ms | **689 req/s · p50 46 ms** | `synchronous=NORMAL` under WAL |
| `/v1/evaluate` mixed traffic, 32 threads, memory | — | **1,158 req/s · p50 24 ms** | (2,458 req/s on an idle machine) |
| `/v1/stats`, 32 threads, SQLite @ ~4k records | 10–15 req/s · p50 up to 2.6 s | **~8,500 req/s · p50 3.7 ms** | see below |

The stats endpoint was the standout finding: `verify_chain()` ran O(N) on
every call and `counts()`/pending-review listing re-scanned the whole store.
Both are now incremental (O(1) counters + cached chain prefix, O(new-only)
after appends), with an authoritative `force=True` re-walk kept for
`/v1/audit/verify` and compliance exports. A bug in the first cut of the
cached verify (forced mode still trusting the cached prefix, missing
in-place tampering) was caught by the tamper regression tests and fixed —
forced verification always walks from genesis.

## Improvement scope (ranked next steps)

1. **Injection scan batching** — the remaining scan cost is linear in total
   customer text (~2 ms for a 200-turn chat). Pre-filtering messages with a
   cheap substring probe (first keyword word) before the regex would cut the
   200-turn case by roughly half. Estimated gain: 2× on long conversations.
2. **Audit store write-behind** — in-memory `append` at ~20k ops/s is fine,
   but batching SQLite commits (every N records or T ms) would lift durable
   mixed-traffic throughput beyond the current 689 req/s toward the memory
   backend's numbers.
3. **Risk engine allocation churn** — ~13k ops/s is dominated by Pydantic
   model construction (`RiskFactor`/`RiskResult`). Reusing frozen models or
   returning dataclasses internally would roughly double throughput.
4. **Multi-process scaling** — a single uvicorn worker is CPU-bound around
   ~1–2.5k req/s; multiple workers now scale cleanly since all shared state
   (counters, chain cache, review transitions) is either per-process or
   guarded by conditional SQL updates.

The pipeline sustains **≥2,000 evaluations/s per core even cold, and
~5,000–7,000/s warm** across all three decision paths — far above the
support-traffic scale of a D2C brand (a large store generates maybe a few
agent actions per second), so latency headroom, not throughput, is the
operative metric going forward.
