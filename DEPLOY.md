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
| `OPSONARA_STORE_BACKEND` | `memory` | `sqlite` persists audit + reviews across restarts |
| `OPSONARA_DB_PATH` | `opsonara.db` | SQLite file (mount a volume in production) |
| `OPSONARA_SEED_DEMO_DATA` | `true` | Set `false` in production |
| `OPSONARA_LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR` |
| `OPSONARA_CORS_ORIGINS` | `*` | Comma-separated origins for browser clients |

> **Important:** with the default `memory` backend the audit trail lives only
> for the process lifetime. In production always use
> `OPSONARA_STORE_BACKEND=sqlite` with a mounted volume — the hash chain is
> preserved across restarts, so tamper evidence is never lost.

## 4 · Production checklist

- [ ] `OPSONARA_SEED_DEMO_DATA=false`
- [ ] `OPSONARA_STORE_BACKEND=sqlite` + mounted volume for `OPSONARA_DB_PATH`
- [ ] `OPSONARA_CORS_ORIGINS` pinned to your console origin(s)
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
- [ ] Restrict network access to the AI-agent callers that need
      `POST /v1/evaluate`; review decisions (`POST /v1/reviews/{id}/decision`)
      should only be reachable from your ops network / VPN

## 5 · Scaling

The app is stateless except for the SQLite file. For multi-instance
deployments, run one writer instance against the volume, or wire the same
store interfaces to Postgres (the interfaces in
`backend/opsonara/stores/audit_store.py` are the contract — see the roadmap
in the README).
