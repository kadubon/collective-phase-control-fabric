# SPDX-License-Identifier: Apache-2.0
"""Create the v0.6 control-plane schema with forced tenant RLS."""

from alembic import op
from cpcf_api.db import Base, rls_statements

revision = "0001_v6_control_plane"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    Base.metadata.create_all(connection)
    for statement in rls_statements():
        op.execute(statement)


def downgrade() -> None:
    # Production rollback uses restore/forward-fix. This destructive path exists for disposable
    # integration databases only and requires an explicit Alembic downgrade command.
    connection = op.get_bind()
    Base.metadata.drop_all(connection)
