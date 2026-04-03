# apps/dashboard/Dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/apps/dashboard

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
  && rm -rf /var/lib/apt/lists/*

COPY apps/dashboard/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -U pip \
  && pip install --no-cache-dir -r requirements.txt

COPY apps/dashboard /app/apps/dashboard

EXPOSE 5001

CMD ["python", "-m", "gunicorn", "apps.dashboard.dashboard.app:create_app()", \
     "--bind", "0.0.0.0:5001", "--workers", "2", "--timeout", "30"]