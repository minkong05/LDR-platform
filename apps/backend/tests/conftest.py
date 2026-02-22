import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from dotenv import load_dotenv

load_dotenv()


@pytest.fixture(scope="session", autouse=True)
def apply_migrations_once():
    """
    When RUN_INTEGRATION_TESTS=1, ensure the DB schema exists by running:
      alembic upgrade head

    This prevents 'relation "events" does not exist' when the Postgres container
    starts with an empty database.
    """
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        return

    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL must be set for integration tests")

    repo_root = Path(__file__).resolve().parents[3]
    migrations_dir = repo_root / "apps" / "backend" / "app" / "db" / "migrations"

    cfg = Config()
    cfg.set_main_option("script_location", str(migrations_dir))
    cfg.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(cfg, "head")
