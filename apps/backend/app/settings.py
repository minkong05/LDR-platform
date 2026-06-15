# 📄 apps/backend/app/settings.py
# Full updated file — add the email block to your existing settings

from __future__ import annotations

from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── Existing fields (keep as-is) ───────────────────────────
    ENV: str = "development"
    DATABASE_URL: str = "sqlite:///./ldr.db"
    AGENT_TOKEN: str = "dev-token"
    INGEST_RATE_LIMIT: int = 1000

    EVENT_RETENTION_DAYS: int = 14

    # ── Email notifications ────────────────────────────────────
    SMTP_ENABLED: bool = True
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "ldr@localhost"
    SMTP_TO: str = ""  # single recipient for now
    ALERT_EMAIL_SEVERITIES: str = "high,critical"

    @field_validator("ALERT_EMAIL_SEVERITIES")
    @classmethod
    def parse_severities(cls, v: str) -> str:
        # Validate the values are known severity strings
        allowed = {"low", "medium", "high", "critical"}
        given = {s.strip().lower() for s in v.split(",")}
        unknown = given - allowed
        if unknown:
            raise ValueError(f"Unknown severities in ALERT_EMAIL_SEVERITIES: {unknown}")
        return v

    @property
    def alert_severity_set(self) -> frozenset[str]:
        """Parsed frozenset of severities that trigger email."""
        return frozenset(s.strip().lower() for s in self.ALERT_EMAIL_SEVERITIES.split(","))

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
