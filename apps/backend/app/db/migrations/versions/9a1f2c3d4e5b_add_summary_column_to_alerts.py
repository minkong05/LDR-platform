"""add summary column to alerts

Revision ID: 9a1f2c3d4e5b
Revises: 14380779d31f
Create Date: 2026-07-24 12:45:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "9a1f2c3d4e5b"
down_revision: Union[str, Sequence[str], None] = "14380779d31f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("alerts", sa.Column("summary", sa.Text(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("alerts", "summary")
