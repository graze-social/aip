from typing import List
import logging
from jwcrypto import jwk
from typing_extensions import Annotated
from pydantic import (
    field_validator,
    PostgresDsn,
    RedisDsn,
)
from pydantic_settings import BaseSettings, NoDecode
from aiohttp import web


logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    http_port: int = 5100

    external_hostname: str = "localhost:5100"

    plc_hostname: str = "plc.directory"

    redis_dsn: RedisDsn = RedisDsn("redis://localhost:6379/1")

    pg_dsn: PostgresDsn = PostgresDsn(
        "postgresql+asyncpg://postgres:password@postgres/aip"
    )

    json_web_keys: Annotated[jwk.JWKSet, NoDecode] = jwk.JWKSet()

    active_signing_keys: List[str] = list()

    @field_validator("json_web_keys", mode="before")
    @classmethod
    def decode_json_web_keys(cls, v: str) -> jwk.JWKSet:
        with open(v) as fd:
            data = fd.read()
            return jwk.JWKSet.from_json(data)


SettingsAppKey = web.AppKey("settings", Settings)
