from typing import Set
import logging
from jwcrypto import jwk
from typing_extensions import Annotated
from pydantic import (
    field_validator,
    PostgresDsn,
    RedisDsn,
    Field,
)
from pydantic_settings import BaseSettings, NoDecode
from aiohttp import web
import json


logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    http_port: int = 5100

    external_hostname: str = "localhost:5100"

    redis_dsn: RedisDsn = Field("redis://localhost:6379/1")

    pg_dsn: PostgresDsn = "postgresql+asyncpg://postgres:password@postgres/aip"

    json_web_keys: Annotated[jwk.JWKSet, NoDecode] = []

    active_signing_keys: Set[str] = set()

    @field_validator("json_web_keys", mode="before")
    @classmethod
    def decode_json_web_keys(cls, v: str) -> jwk.JWKSet:
        with open(v) as fd:
            data = fd.read()
            return jwk.JWKSet.from_json(data)


SettingsAppKey = web.AppKey("settings", Settings)
