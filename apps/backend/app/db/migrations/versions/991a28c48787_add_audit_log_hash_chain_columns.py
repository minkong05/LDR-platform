"""add audit log hash chain columns

Revision ID: 991a28c48787
Revises: 9a1f2c3d4e5b
Create Date: 2026-07-27 19:25:16.793813

Adds prev_hash/entry_hash to audit_log for tamper-evidence (see
app/services/response/audit_chain.py). Both columns are nullable and there
is no backfill: the hash chain starts fresh at deploy of this migration.
Existing rows keep prev_hash=entry_hash=NULL and are treated as legacy by
verify_chain(), which skips leading NULL rows and starts checking from the
first row with a non-null entry_hash.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "991a28c48787"
down_revision: Union[str, Sequence[str], None] = "9a1f2c3d4e5b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("audit_log", sa.Column("prev_hash", sa.String(length=64), nullable=True))
    op.add_column("audit_log", sa.Column("entry_hash", sa.String(length=64), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("audit_log", "entry_hash")
    op.drop_column("audit_log", "prev_hash")
