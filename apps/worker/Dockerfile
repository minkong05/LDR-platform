FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir -U pip setuptools wheel

# Worker dependencies will be added in Week 2 (celery/redis/sqlalchemy).
CMD ["python", "-c", "print('worker placeholder: OK')"]
