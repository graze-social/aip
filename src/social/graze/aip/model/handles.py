"""AT Protocol handle resolution data models.

Provides SQLAlchemy models for mapping AT Protocol handles to DIDs and
Personal Data Server locations for identity resolution.
"""

from sqlalchemy.orm import Mapped
from sqlalchemy import Index
from sqlalchemy.dialects.postgresql import insert
from ulid import ULID

from social.graze.aip.model.base import Base, str512, guidpk


class Handle(Base):
    """AT Protocol handle to DID mapping with PDS location.

    Maps human-readable handles to DIDs and tracks the Personal Data Server
    hosting the user's data for AT Protocol identity resolution.
    """

    __tablename__ = "handles"

    guid: Mapped[guidpk]
    did: Mapped[str512]
    handle: Mapped[str512]
    pds: Mapped[str512]

    __table_args__ = (
        Index("idx_handles_did", "did", unique=True),
        Index("idx_handles_handle", "handle"),
    )


def upsert_handle_stmt(did: str, handle: str, pds: str):
    """Create PostgreSQL upsert statement for handle records.

    Updates handle and PDS for existing DID or inserts new record,
    returning the GUID for the handle mapping.
    """
    return (
        insert(Handle)
        .values(
            [
                {
                    "guid": str(ULID()),
                    "did": did,
                    "handle": handle,
                    "pds": pds,
                }
            ]
        )
        .on_conflict_do_update(
            index_elements=["did"],
            set_={
                "handle": handle,
                "pds": pds,
            },
        )
        .returning(Handle.guid)
    )
