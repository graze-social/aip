from datetime import datetime
from sqlalchemy import String, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from social.graze.aip.model.base import Base


class AppPassword(Base):
    __tablename__ = "atproto_app_passwords"

    guid: Mapped[str] = mapped_column(String(64), primary_key=True)
    app_password: Mapped[str]
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class AppPasswordSession(Base):
    __tablename__ = "atproto_app_password_sessions"

    guid: Mapped[str] = mapped_column(String(64), primary_key=True)
    access_token: Mapped[str]
    access_token_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    refresh_token: Mapped[str]
    refresh_token_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
