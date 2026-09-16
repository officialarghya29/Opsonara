# Deploying Opsonara

Opsonara ships as a **single container** that serves both the API and the
operator console. This guide covers local Docker, a persistent SQLite store,
and production notes.

## 1 · Run with Docker Compose (recommended)

```bash
git clone https://github.com/officialarghya29/Opsonara.git
cd Opsonara
docker compose up --build -d
```

* API + docs → `http://localhost:8000/docs`
* Console UI → `http://localhost:8000/app/`

## 2 · Pull the prebuilt image from GHCR

Every push to `main` publishes an image automatically (`.github/workflows/publish.yml`):

```bash
docker run -d -p 8000:8000 \
  -e OPSONARA_SEED_DEMO_DATA=false \
  -e OPSONARA_STORE_BACKEND=sqlite \
  -e OPSONARA_DB_PATH=/data/opsonara.db \
  -v opsonara-data:/data \
  ghcr.io/officialarghya29/opsonara:latest
```

Tags: `latest` (main), `sha-<commit>`, and `vX.Y.Z` for release tags.

## 3 · Configuration

| Variable | Default | Notes |
|---|---|---|
| `OPSONARA_STORE_BACKEND` | `memory` | `sqlite` (single node) or `postgres` (multi-instance) for production |
| `OPSONARA_DB_PATH` | `opsonara.db` | SQLite file (mount a volume in production) |
| `OPSONARA_PG_DSN` | — | `postgresql://user:pass@host:5432/db` when backend is `postgres` |
| `OPSONARA_SEED_DEMO_DATA` | `true` | Set `false` in production |
| `OPSONARA_LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR` |
| `OPSONARA_CORS_ORIGINS` | `*` | Comma-separated origins for browser clients |
| `OPSONARA_AUTH_MODE` | `off` | Set `api_key` in production — per-brand keys, optional HMAC signing |
| `OPSONARA_RATE_LIMIT_PER_MINUTE` | `120` | Per-key budget for protected endpoints |
| `OPSONARA_CREDENTIAL_VERIFICATION` | `optional` | `strict` requires valid signed agent credentials |
| `OPSONARA_STRIPE_API_KEY` | — | Enable Stripe meter-event reporting |
| `OPSONARA_BILLING_DRY_RUN` | `true` | Keep `true` until Stripe is verified |

> **Important:** with the default `memory` backend the audit trail lives only
> for the process lifetime. In production always use
> `OPSONARA_STORE_BACKEND=sqlite` with a mounted volume — the hash chain is
> preserved across restarts, so tamper evidence is never lost.

## 4 · Production checklist

- [ ] `OPSONARA_SEED_DEMO_DATA=false`
- [ ] `OPSONARA_STORE_BACKEND=postgres` (multi-instance) or `sqlite` + mounted volume (single node)
- [ ] `OPSONARA_AUTH_MODE=api_key` — register each brand via `POST /v1/brands` and
      distribute keys over a secret channel; enable per-tenant signing secrets
      and set `OPSONARA_RATE_LIMIT_PER_MINUTE` to your budget
- [ ] `OPSONARA_CORS_ORIGINS` pinned to your console origin(s)
- [ ] `OPSONARA_ADMIN_TOKEN` set to a long random value — operator endpoints
      (create brands, issue credentials, recalibrate) reject everyone else
- [ ] `OPSONARA_WEBHOOK_SECRETS` configured before exposing
      `/v1/webhooks/*` — unsigned webhooks are rejected with 401
- [ ] TLS termination in front (nginx/Caddy/ALB); the app is plain HTTP
- [ ] Reverse proxy example:

```nginx
server {
  listen 443 ssl;
  server_name opsonara.yourbrand.com;

  location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

- [ ] Monitor `GET /health` (liveness) and `GET /v1/audit/verify`
      (chain integrity — alert if `intact` is ever `false`)
- [ ] Schedule the learning loop weekly:
      `python -m opsonara.recalibrate_job --min-outcomes 25` (Kubernetes
      CronJob or crontab); every weight change lands in the audit trail
- [ ] Restrict network access to the AI-agent callers that need
      `POST /v1/evaluate`; review decisions (`POST /v1/reviews/{id}/decision`)
      should only be reachable from your ops network / VPN

## 5 · Scaling

The app is stateless except for its stores. For multi-instance deployments
run with `OPSONARA_STORE_BACKEND=postgres` and `pip install pg8000` (or the
`requirements-pg.txt` extra) — every worker then shares the audit chain and
review queue, review decisions use conditional updates so two workers can
never both resolve one review, and the hash chain stays verifiable across
instances.
