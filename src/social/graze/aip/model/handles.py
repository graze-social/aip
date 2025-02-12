from typing import Any
from sqlalchemy.orm import Mapped
from sqlalchemy.dialects.postgresql import insert
from ulid import ULID

from social.graze.aip.model.base import Base, str512, guidpk


class Handle(Base):
    __tablename__ = "handles"

    guid: Mapped[guidpk]
    did: Mapped[str512]
    handle: Mapped[str512]
    pds: Mapped[str512]


def upsert_handle_stmt(did: str, handle: str, pds: str):
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
