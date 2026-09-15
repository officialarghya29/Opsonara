# Opsonara — Agent Transaction Firewall (single container: API + console UI)
FROM python:3.12-slim

WORKDIR /srv

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

ENV OPSONARA_SEED_DEMO_DATA=true \
    PYTHONUNBUFFERED=1

WORKDIR /srv/backend

EXPOSE 8000
CMD ["uvicorn", "opsonara.main:app", "--host", "0.0.0.0", "--port", "8000"]
