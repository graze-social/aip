from typing import List
import logging
import os
import json
from logging.config import dictConfig
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


logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    http_port: int = 5100

    external_hostname: str = "localhost:5100"

    redis_dsn: RedisDsn = Field("redis://localhost:6379/1")

    pg_dsn: PostgresDsn = "postgresql+asyncpg://postgres:password@postgres/aip"

    json_web_keys: Annotated[List[jwk.JWK], NoDecode] = []

    @field_validator("json_web_keys", mode="before")
    @classmethod
    def decode_json_web_keys(cls, v: str) -> List[jwk.JWK]:
        logger.debug("Parsing json_web_keys", extra={"json_web_keys": v})
        return []

SettingsAppKey = web.AppKey("settings", Settings)
