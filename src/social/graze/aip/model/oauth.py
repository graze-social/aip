import datetime
from sqlalchemy import String, Column, DateTime
from sqlalchemy.dialects.postgresql import JSON
from social.graze.aip.model.base import Base


class OAuthRequest(Base):
    __tablename__ = "oauth_requests"

    oauth_state = Column(String(64), primary_key=True)
    issuer = Column(String(512), nullable=False)
    guid = Column(String(512), nullable=False)
    nonce = Column(String(64), nullable=False)
    pkce_verifier = Column(String(128), nullable=False)
    secret_jwk_id = Column(String(32), nullable=False)
    dpop_jwk = Column(JSON, nullable=False)
    destination = Column(String(512), nullable=False)
    created_at = Column(
        DateTime, nullable=False
    )  # default=datetime.datetime.now(tz=datetime.UTC)
    expires_at = Column(DateTime, nullable=False)
