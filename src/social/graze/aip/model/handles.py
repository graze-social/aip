from sqlalchemy import String, Column
from sqlalchemy.dialects.postgresql import insert
from ulid import ULID
from social.graze.aip.model.base import Base


class Handle(Base):
    __tablename__ = "handles"

    guid = Column(String(512), primary_key=True)
    did = Column(String(512))
    handle = Column(String(512), nullable=False)
    pds = Column(String(512), nullable=False)


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
    )
