from sqlalchemy import String, orm
from sqlalchemy.orm import mapped_column

from typing_extensions import Annotated

str512 = Annotated[str, 512]
guidpk = Annotated[str, mapped_column(String(512), primary_key=True)]


class Base(orm.DeclarativeBase):
    type_annotation_map = {
        str512: String(512),
        guidpk: String(512),
    }
