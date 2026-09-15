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

## Improvement scope (ranked next steps)

1. **Injection scan batching** — the remaining scan cost is linear in total
   customer text (~2 ms for a 200-turn chat). Pre-filtering messages with a
   cheap substring probe (first keyword word) before the regex would cut the
   200-turn case by roughly half. Estimated gain: 2× on long conversations.
2. **Audit store** — in-memory `append` at ~20k ops/s and `verify_chain` at
   O(N) are fine for review-queue workloads, but a write-behind buffer for
   the SQLite backend (batched commits every N records or T ms) would lift
   durable throughput 5–10×.
3. **Risk engine allocation churn** — ~13k ops/s is dominated by Pydantic
   model construction (`RiskFactor`/`RiskResult`). Reusing frozen models or
   returning dataclasses internally would roughly double throughput.
4. **HTTP overhead** — pipeline is ~0.4 ms of the ~1–2 ms per request that
   HTTP + JSON add; per-brand policy caching at the API layer is the next
   lever for end-to-end latency.

The pipeline sustains **≥2,000 evaluations/s per core even cold, and
~5,000–7,000/s warm** across all three decision paths — far above the
support-traffic scale of a D2C brand (a large store generates maybe a few
agent actions per second), so latency headroom, not throughput, is the
operative metric going forward.
