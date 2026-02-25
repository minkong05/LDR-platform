FROM python:3.12-slim

# dont write .pyc files and force Python to print logs immediately.
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# System deps (keep minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
  && rm -rf /var/lib/apt/lists/*

# Copy only metadata first for better caching
COPY pyproject.toml /app/pyproject.toml
# Copy backend code
COPY apps/backend /app/apps/backend

# Install deps (no editable install inside container)
RUN pip install --no-cache-dir -U pip setuptools wheel \
  && pip install --no-cache-dir .




EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--app-dir", "apps/backend", "--host", "0.0.0.0", "--port", "8000"]
