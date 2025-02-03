"""init

Revision ID: 380b77abd479
Revises: 
Create Date: 2025-02-03 16:15:52.235674

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '380b77abd479'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'handles',
        sa.Column('did', sa.String(512), primary_key=True),
        sa.Column('handle', sa.String(512), nullable=False),
        sa.Column('pds', sa.String(512), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('handles')
