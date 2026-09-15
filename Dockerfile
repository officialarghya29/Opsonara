# Opsonara — Agent Transaction Firewall (single container: API + console UI)
FROM python:3.12-slim

WORKDIR /srv

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

ENV OPSONARA_SEED_DEMO_DATA=true \
    OPSONARA_STORE_BACKEND=sqlite \
    OPSONARA_DB_PATH=/data/opsonara.db \
    PYTHONUNBUFFERED=1

# Dedicated non-root user; /data is the only writable path (SQLite volume).
RUN groupadd -r opsonara && useradd -r -g opsonara opsonara \
    && mkdir -p /data && chown -R opsonara:opsonara /data
USER opsonara

VOLUME ["/data"]

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)" || exit 1

CMD ["uvicorn", "opsonara.main:app", "--host", "0.0.0.0", "--port", "8000"]
