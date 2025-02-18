from typing import List
import logging
from jwcrypto import jwk
from typing_extensions import Annotated
from pydantic import (
    field_validator,
    PostgresDsn,
    RedisDsn,
)
import base64
from pydantic_settings import BaseSettings, NoDecode
from aiohttp import web
from cryptography.fernet import Fernet


logger = logging.getLogger(__name__)


class Settings(BaseSettings):

    debug: bool = False

    http_port: int = 5100

    external_hostname: str = "localhost:5100"

    plc_hostname: str = "plc.directory"

    redis_dsn: RedisDsn = RedisDsn("redis://valkey:6379/1?decode_responses=True")

    pg_dsn: PostgresDsn = PostgresDsn(
        "postgresql+asyncpg://postgres:password@postgres/aip"
    )

    json_web_keys: Annotated[jwk.JWKSet, NoDecode] = jwk.JWKSet()

    active_signing_keys: List[str] = list()

    service_auth_keys: List[str] = list()

    encryption_key: Fernet = Fernet(Fernet.generate_key())

    worker_id: str

    refresh_queue_oauth: str = "refresh_queue:oauth"

    refresh_queue_app_password: str = "refresh_queue:app_password"

    @field_validator("json_web_keys", mode="before")
    @classmethod
    def decode_json_web_keys(cls, v: str) -> jwk.JWKSet:
        with open(v) as fd:
            data = fd.read()
            return jwk.JWKSet.from_json(data)

    @field_validator("encryption_key", mode="before")
    @classmethod
    def decode_encryption_key(cls, v: str) -> Fernet:
        key_data = base64.b64decode(v)
        return Fernet(key_data)


SettingsAppKey = web.AppKey("settings", Settings)
