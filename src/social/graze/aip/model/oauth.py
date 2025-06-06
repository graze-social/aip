"""OAuth 2.0 data models for AT Protocol authentication service.

Provides SQLAlchemy models for OAuth authorization flow state, active sessions,
and user permission management.
"""
from typing import Any
from datetime import datetime
from sqlalchemy import Integer, String, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import JSON, insert

from social.graze.aip.model.base import Base, str512, str1024


class OAuthRequest(Base):
    """OAuth authorization request state with PKCE and DPoP parameters.
    
    Stores temporary authorization state during OAuth flow including
    PKCE verifier, DPoP key, and request metadata.
    """
    __tablename__ = "oauth_requests"

    oauth_state: Mapped[str] = mapped_column(String(64), primary_key=True)
    issuer: Mapped[str512]
    guid: Mapped[str512]
    pkce_verifier: Mapped[str] = mapped_column(String(128), nullable=False)
    secret_jwk_id: Mapped[str] = mapped_column(String(32), nullable=False)
    dpop_jwk: Mapped[Any] = mapped_column(JSON, nullable=False)
    destination: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class OAuthSession(Base):
    """Active OAuth session with access and refresh tokens.
    
    Represents authenticated user session with AT Protocol tokens
    and associated cryptographic material for secure API access.
    """
    __tablename__ = "oauth_sessions"

    session_group: Mapped[str] = mapped_column(String(64), primary_key=True)
    issuer: Mapped[str512]
    guid: Mapped[str512]
    access_token: Mapped[str1024]
    refresh_token: Mapped[str512]
    secret_jwk_id: Mapped[str] = mapped_column(String(32), nullable=False)
    dpop_jwk: Mapped[Any] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    access_token_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    hard_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class Permission(Base):
    """User permission mapping between GUIDs.
    
    Defines access control relationships where one GUID
    has specific permissions over another GUID.
    """
    __tablename__ = "guid_permissions"

    guid: Mapped[str] = mapped_column(String(512), primary_key=True)
    target_guid: Mapped[str] = mapped_column(String(512), primary_key=True)
    permission: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


def upsert_permission_stmt(
    guid: str, target_guid: str, permission: int, created_at: datetime
):
    """Create PostgreSQL upsert statement for permission records.
    
    Updates existing permission or inserts new one if the
    guid/target_guid pair doesn't exist.
    """
    return (
        insert(Permission)
        .values(
            [
                {
                    "guid": guid,
                    "target_guid": target_guid,
                    "permission": permission,
                    "created_at": created_at,
                }
            ]
        )
        .on_conflict_do_update(
            index_elements=["guid", "target_guid"],
            set_={
                "permission": permission,
            },
        )
    )
