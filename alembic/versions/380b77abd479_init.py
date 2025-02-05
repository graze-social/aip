"""init

Revision ID: 380b77abd479
Revises:
Create Date: 2025-02-03 16:15:52.235674

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "380b77abd479"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "handles",
        sa.Column("guid", sa.String(512), primary_key=True),
        sa.Column("did", sa.String(512), nullable=False),
        sa.Column("handle", sa.String(512), nullable=False),
        sa.Column("pds", sa.String(512), nullable=False),
    )
    op.create_index("idx_handles_did", "handles", ["did"], unique=True)
    op.create_index("idx_handles_handle", "handles", ["handle"])

    op.create_table(
        "oauth_requests",
        sa.Column("oauth_state", sa.String(64), primary_key=True),
        sa.Column("issuer", sa.String(512), nullable=False),
        sa.Column("guid", sa.String(512), nullable=False),
        sa.Column("pkce_verifier", sa.String(128), nullable=False),
        sa.Column("secret_jwk_id", sa.String(32), nullable=False),
        sa.Column("dpop_jwk", sa.JSON, nullable=False),
        sa.Column("destination", sa.String(512), nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("expires_at", sa.DateTime, nullable=False),
    )
    op.create_index("idx_oauth_requests_guid", "oauth_requests", ["guid"])
    op.create_index("idx_oauth_requests_expires", "oauth_requests", ["expires_at"])

    op.create_table(
        "oauth_sessions",
        sa.Column("session_group", sa.String(64), primary_key=True),
        sa.Column("access_token", sa.String(512), nullable=False),
        sa.Column("guid", sa.String(512), nullable=False),
        sa.Column("refresh_token", sa.String(512), nullable=False),
        sa.Column("issuer", sa.String(512), nullable=False),
        sa.Column("secret_jwk_id", sa.String(32), nullable=False),
        sa.Column("dpop_jwk", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("access_token_expires_at", sa.DateTime, nullable=False),
        sa.Column("hard_expires_at", sa.DateTime, nullable=False),
    )
    op.create_index("idx_oauth_sessions_guid", "oauth_sessions", ["guid"])
    op.create_index(
        "idx_oauth_sessions_expires", "oauth_sessions", ["access_token_expires_at"]
    )


def downgrade() -> None:
    op.drop_table("handles")
    op.drop_table("oauth_requests")
