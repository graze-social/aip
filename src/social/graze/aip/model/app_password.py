"""AT Protocol app password data models for third-party authentication.

Provides SQLAlchemy models for app password credentials and active sessions,
enabling alternative authentication method for AT Protocol applications.
"""
from datetime import datetime
from sqlalchemy import String, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from social.graze.aip.model.base import Base, str1024


class AppPassword(Base):
    """AT Protocol app password credentials for third-party authentication.
    
    Stores app password credentials that allow applications to authenticate
    with AT Protocol services without full OAuth flow.
    """
    __tablename__ = "atproto_app_passwords"

    guid: Mapped[str] = mapped_column(String(512), primary_key=True)
    app_password: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class AppPasswordSession(Base):
    """Active app password session with access and refresh tokens.
    
    Represents authenticated session using app password credentials
    with token lifecycle management for AT Protocol access.
    """
    __tablename__ = "atproto_app_password_sessions"

    guid: Mapped[str] = mapped_column(String(512), primary_key=True)
    access_token: Mapped[str1024]
    access_token_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    refresh_token: Mapped[str] = mapped_column(String(512), nullable=False)
    refresh_token_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
