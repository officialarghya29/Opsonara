# Opsonara — Product Roadmap & Spec Coverage

This document maps the **master product specification** (the 98-section
blueprint: control plane for autonomous AI commerce) onto what the codebase
implements today, what is partially there, and what comes next. It is the
single source of truth for "what does Opsonara actually do right now?"

Status legend: ✅ shipped · 🟡 partial (foundation exists, needs depth) · ⬜ not started

## 1 · Core pipeline (spec §1–§20)

| Spec area | Status | Where | Notes |
|---|---|---|---|
| API gateway + evaluate endpoint | ✅ | `main.py`, `firewall.py` | `/v1/evaluate`, decision trace in every response |
| Agent identity | ✅ | `identity.py` | HS256 signed credentials, expiry, revocation, brand pinning |
| Agent registry | 🟡 | `firewall.py` | agents resolved from credentials/requests; no persistent agent objects yet |
| Credential service | ✅ | `identity.py`, `multitenant.py` | issue/rotate/revoke JWT credentials; hashed per-brand API keys |
| Fine-grained permissions | 🟡 | `engines/policy.py` | `permission_level` 0–3 + policy checks; per-action/per-resource conditions not yet |
| Context engine | ✅ | `engines/context.py` | customer, order, transaction, conversation, agent context |
| Policy engine | ✅ | `engines/policy.py`, `policy_store.py` | rules-as-data, per-brand policy packs, versioned + activatable |
| Policy builder (natural language) | ⬜ | — | spec §10; needs GENERATE→EXPLAIN→VALIDATE→SIMULATE→APPROVE→DEPLOY flow |
| Policy version control | 🟡 | `policy_store.py` | versioned packs with activation + history; no diff/rollback UI |
| Policy simulator (spec §12) | ⬜ | — | replay historical transactions against a candidate pack (the replay engine §33 shares machinery) |
| Shadow mode (policies & weights) | ✅ | `learning.py` | weight-set shadowing with samples/win-rate promotion gates |
| Risk engine | ✅ | `engines/risk.py` | deterministic signals → calibrated score → LOW/MEDIUM/HIGH/CRITICAL band, factor breakdown |
| Action risk profiles | 🟡 | `engines/risk.py` | sensitivity weighting exists; full 7-dimension profiles (§15) not yet |
| Behavioral analytics | 🟡 | `engines/risk.py` | behavioral factor + `metadata.recent_action_counts` input; no continuous per-agent profiles |
| Velocity engine (spec §18) | 🟡 | `engines/risk.py` | anomaly detection from action counts; no autonomous responses (pause/quarantine) yet |
| Fraud detection | 🟡 | `engines/risk.py` | risk-factor driven; no dedicated fraud model |
| Prompt-injection detection | ✅ | `core/injection.py` | versioned pattern catalogue, explainable, per-conversation scoring |
| Blast-radius engine (spec §19) | ⬜ | — | "max impact if wrong" — direct exposure × repetition potential |
| Authorization decision | ✅ | `firewall.py` | three-way ALLOW / REVIEW / BLOCK, policy + risk + injection combined |

## 2 · Execution & verification (spec §23–§25, §44)

| Spec area | Status | Where | Notes |
|---|---|---|---|
| Execution gateway (`ops.execute()`) | 🟡 | `connectors.py` | connectors execute ALLOW / hold REVIEW / refuse BLOCK on the platform; SDK-style one-call wrapper not yet |
| Shopify connector | ✅ | `connectors.py` | refund/cancel executors + HMAC webhook ingest |
| WooCommerce connector | ✅ | `connectors.py` | REST executors |
| Generic webhook connector | ✅ | `connectors.py` | signed outbound + verified inbound |
| Post-execution verification (spec §24) | ⬜ | — | compare requested vs actual result; detect "asked ₹1.5k, executed ₹15k" |
| Idempotency / replay protection | 🟡 | `connectors.py`, `multitenant.py` | webhook signature timestamps; no per-action idempotency keys on evaluate/execute |
| More platforms (§44) | ⬜ | — | Magento, BigCommerce, Stripe, CRM/security tools |

## 3 · Human oversight (spec §26–§32)

| Spec area | Status | Where | Notes |
|---|---|---|---|
| Human review queue | ✅ | `stores/review_store.py`, `main.py` | approve/reject, reviewer recorded, race-safe conditional updates |
| Review → learning feedback | ✅ | `learning.py`, `main.py` | verdicts pair with decision signals → bounded recalibration |
| Two-person approval (spec §27) | ⬜ | — | second approval for > ₹50k / bulk / data-export actions |
| Agent kill switch (spec §28) | 🟡 | `multitenant.py` | API-key revocation exists; one-click "pause all agents" not yet |
| Quarantine mode (spec §29) | ⬜ | — | read-only agent state: everything sensitive → human review |
| Incident management (spec §30–§31) | ⬜ | — | incident objects, timelines, auto-containment |
| Notification engine (spec §43) | ⬜ | — | Slack/PagerDuty/email on CRITICAL decisions |
| Attack lab (spec §32) | ⬜ | — | scripted attack simulations (major demo feature); today: `tests/test_injection.py` covers the detection layer |

## 4 · Audit, provenance & governance (spec §36–§41)

| Spec area | Status | Where | Notes |
|---|---|---|---|
| Immutable audit trail | ✅ | `stores/*` | SHA-256 hash chain, tamper-evident, memory/SQLite/Postgres |
| Chain verification | ✅ | `stores/*` | incremental O(new) verify + authoritative `force=True` full walk |
| Provenance (agent/credential/model) | ✅ | `identity.py`, `firewall.py` | credential, framework, version, level recorded per decision |
| Decision reproducibility (spec §37) | 🟡 | audit records | full inputs persisted; no "re-decide this request" tooling yet (replay engine) |
| Event timeline per transaction (spec §39) | 🟡 | audit records | decision + human outcome chained; tool-call/external-response steps not yet |
| Model governance (spec §36) | 🟡 | audit provenance | agent framework/version recorded; policy/risk engine versions not embedded per record |
| Risk-exposure analytics (spec §40) | ⬜ | — | "₹42.8L autonomous exposure" style dashboards |

## 5 · Learning loop (spec §34–§35)

| Spec area | Status | Where | Notes |
|---|---|---|---|
| Outcome logging | ✅ | `learning.py` | verdicts + decision-time signals |
| Weekly recalibration | ✅ | `recalibrate_job.py` | bounded (±0.10 clamp), idempotent cursor, audited weight changes; file-backed shared store (`OPSONARA_OUTCOME_STORE_PATH`) |
| A/B shadow mode | ✅ | `learning.py` | samples + win-rate gates before promotion |
| Policy recommendations (spec §35) | ⬜ | — | suggest policy changes from override patterns (weights only today) |
| Learning never silently deploys | ✅ | design principle | recalibration promotes bounded weights only; policy changes always human-approved |

## 6 · Platform & commercial (spec §51–§57, §74–§76)

| Spec area | Status | Where | Notes |
|---|---|---|---|
| REST API surface | ✅ | `main.py` | evaluate, reviews, audit, policy-packs, credentials, connectors, learning, billing, explain, webhooks (see README table) |
| Multi-tenancy | ✅ | `multitenant.py` | per-brand API keys, brand pinning, tenant derived server-side (never trusted from client) |
| Request signing | ✅ | `multitenant.py` | HMAC with replay-protected timestamps |
| Rate limiting | ✅ | `multitenant.py` | sliding-window per key |
| Admin/operator gate | ✅ | `multitenant.py`, `main.py` | bootstrap admin token; operator endpoints protected |
| Usage metering + billing | ✅ | `commercial.py` | incremental counters, Stripe meter events (dry-run default) |
| Customer explainer | ✅ | `commercial.py` | leak-filtered, customer-safe decision explanation (see README) |
| Store backends | ✅ | `stores/` | memory (dev), SQLite (single-node), Postgres 16 (multi-instance; verified under concurrency in CI) |
| RBAC (spec §75) | ⬜ | — | owner/admin/security-admin/operator/reviewer/analyst roles |
| Environments (spec §76) | ⬜ | — | dev/staging/prod-scoped policies and credentials |
| Enterprise SSO/SCIM/SIEM (spec §73) | ⬜ | — | |

## 7 · Developer experience (spec §45–§50, §90)

| Spec area | Status | Where | Notes |
|---|---|---|---|
| Python SDK (`pip install opsonara`) | ⬜ | — | thin client over `/v1/evaluate` + `/v1/execute` |
| TypeScript SDK | ⬜ | — | |
| MCP gateway (spec §45) | ⬜ | — | Opsonara as the tool-authorization layer for MCP servers |
| CLI (spec §49) | 🟡 | `recalibrate_job.py` | one operational CLI exists; `opsonara init/dev/simulate/replay` not yet |
| Local dev mode | 🟡 | defaults | memory store + seeded demo data + open auth = instant start; no dedicated simulator UI |
| Console UI | ✅ | `frontend/` | evaluate console, audit viewer, policy-pack authoring panel |

## 8 · Quality engineering (spec §58–§62, §77–§80)

| Spec area | Status | Where | Notes |
|---|---|---|---|
| Test suite | ✅ | `backend/tests/` | 199 tests: unit, API, security, connectors, stores, learning, webhooks, tamper regression |
| Postgres integration tests | ✅ | `tests/test_pg_store.py` | CI service container + DSN-gated locally |
| Load/performance benchmarks | ✅ | `benchmarks/`, `docs/BENCHMARKS.md` | p50/p95/p99, per-engine breakdown, HTTP load tests, chain integrity asserted post-load |
| Security benchmarks (spec §59) | ⬜ | — | precision/recall for injection & fraud detection on a labelled set |
| Public benchmark dataset (spec §62) | ⬜ | — | |
| Threat model doc (spec §58) | ⬜ | — | T1–T14 table; much of the detection/mitigation already implemented |
| Observability (spec §77) | 🟡 | logging | structured logs; no metrics/traces export yet |
| Chaos/failure injection (spec §78) | ⬜ | — | graceful degradation rules are coded (fail-closed on high-impact) but not chaos-tested |

## 9 · Suggested build order (from the spec, adjusted to current state)

1. **Post-execution verification + idempotency keys** (§24–§25) — closes the
   biggest remaining trust gap: Opsonara currently controls *before* the
   platform call, not *after*.
2. **Agent registry + quarantine/kill switch** (§3, §28–§29) — mostly wiring:
   statuses over existing credentials + a `BLOCK`-all override.
3. **Policy simulator & replay engine** (§12, §33) — historical decisions are
   already fully persisted with inputs; replaying candidate packs is the
   unlock for safe policy iteration (and the NL policy builder later).
4. **Blast radius + exposure analytics** (§19, §40) — derivable from existing
   risk factors + policy limits; powers the Command Center.
5. **Python SDK + MCP gateway** (§45–§46) — the wedge into developer adoption.
6. **Incident management + notifications** (§30–§31, §43) — needed for
   on-call-grade operations before enterprise deals.

## 10 · Design principles already enforced in code

- Never trust the agent: every evaluate authenticates/authorizes (spec §94.1–3).
- Fail closed: high-impact unevaluable actions never silently bypass (§78).
- Explainable decisions: reasons, policy checks, risk factors on every record (§22).
- Tamper-evident audit: hash chain + verification endpoints (§38).
- Learning suggests, never silently deploys policies (§34, §94.14).
- Policies are versioned data, activation is explicit (§11, §94.15).
- Money is `Decimal` end-to-end; floats are rejected at the boundary.
