FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir -U pip setuptools wheel \
  && pip install --no-cache-dir \
     "structlog>=24.1" \
     "pyyaml>=6.0" \
     "sqlalchemy>=2.0" \
     "alembic>=1.13" \
     "psycopg[binary]>=3.2" \
     "pydantic-settings>=2.2"

# Copy backend code (so worker can import app.*)
COPY apps/backend /app/apps/backend

# Copy worker code
COPY apps/worker /app/apps/worker

# Copy rules into image for /app/rules
COPY rules /app/rules

ENV PYTHONPATH=/app/apps/backend

CMD ["python", "/app/apps/worker/worker.py"]
