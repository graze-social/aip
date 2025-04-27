from typing import Any
from datetime import datetime
from sqlalchemy import Integer, String, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import JSON, insert

from social.graze.aip.model.base import Base, str512, str1024


class OAuthRequest(Base):
    __tablename__ = "oauth_requests"

    oauth_state: Mapped[str] = mapped_column(String(64), primary_key=True)
    issuer: Mapped[str512]
    guid: Mapped[str512]
    pkce_verifier: Mapped[str]
    secret_jwk_id: Mapped[str]
    dpop_jwk: Mapped[Any] = mapped_column(JSON, nullable=False)
    destination: Mapped[str]
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class OAuthSession(Base):
    __tablename__ = "oauth_sessions"

    session_group: Mapped[str] = mapped_column(String(64), primary_key=True)
    issuer: Mapped[str512]
    guid: Mapped[str512]
    access_token: Mapped[str1024]
    refresh_token: Mapped[str512]
    secret_jwk_id: Mapped[str512]
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
