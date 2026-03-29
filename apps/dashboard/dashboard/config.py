# apps/dashboard/dashboard/config.py
import os


class Config:
    SECRET_KEY = os.environ.get("DASHBOARD_SECRET_KEY", "dev-secret-change-me")
    LDR_API_BASE = os.environ.get("LDR_API_BASE", "http://localhost:8000")
    # How long (seconds) requests to the backend API should wait before timing out
    API_TIMEOUT = int(os.environ.get("API_TIMEOUT", "10"))
