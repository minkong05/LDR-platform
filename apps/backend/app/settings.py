from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# settings.py is at: <repo>/apps/backend/app/settings.py
# repo root is 3 levels up from /app:
REPO_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(REPO_ROOT / ".env"),
        extra="ignore",
    )

    ENV: str = "local"
    EVENT_RETENTION_DAYS: int = 14
    DATABASE_URL: str
    AGENT_TOKEN: str


settings = Settings()
