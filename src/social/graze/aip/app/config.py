import asyncio
from typing import Annotated, Final, List
import logging
from aio_statsd import TelegrafStatsdClient
from jwcrypto import jwk
from pydantic import (
    field_validator,
    PostgresDsn,
    RedisDsn,
)
import base64
from pydantic_settings import BaseSettings, NoDecode
from aiohttp import web
from cryptography.fernet import Fernet
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    async_sessionmaker,
    AsyncSession,
)
from aiohttp import ClientSession
from redis import asyncio as redis

from social.graze.aip.model.health import HealthGauge


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

    statsd_host: str = "telegraf"
    statsd_port: int = 8125
    statsd_prefix: str = "aip"

    @field_validator("json_web_keys", mode="before")
    @classmethod
    def decode_json_web_keys(cls, v) -> jwk.JWKSet:
        if isinstance(v, jwk.JWKSet):  # If it's already a JWKSet, return it directly
            return v
        elif isinstance(v, str):  # If it's a file path, load from file
            with open(v) as fd:
                data = fd.read()
                return jwk.JWKSet.from_json(data)
        raise ValueError("json_web_keys must be a JWKSet object or a valid JSON file path")

    @field_validator("encryption_key", mode="before")
    @classmethod
    def decode_encryption_key(cls, v) -> Fernet:
        if isinstance(v, Fernet):  # Already a Fernet instance, return it
            return v
        elif isinstance(v, str):  # Decode from a base64-encoded string
            key_data = base64.b64decode(v)
            return Fernet(key_data)
        raise ValueError("encryption_key must be a Fernet object or a base64-encoded key string")


OAUTH_REFRESH_QUEUE = "auth_session:oauth:refresh"

APP_PASSWORD_REFRESH_QUEUE = "auth_session:app-password:refresh"

SettingsAppKey: Final = web.AppKey("settings", Settings)
DatabaseAppKey: Final = web.AppKey("database", AsyncEngine)
DatabaseSessionMakerAppKey: Final = web.AppKey(
    "database_session_maker", async_sessionmaker[AsyncSession]
)
SessionAppKey: Final = web.AppKey("http_session", ClientSession)
RedisPoolAppKey: Final = web.AppKey("redis_pool", redis.ConnectionPool)
RedisClientAppKey: Final = web.AppKey("redis_client", redis.Redis)
HealthGaugeAppKey: Final = web.AppKey("health_gauge", HealthGauge)
OAuthRefreshTaskAppKey: Final = web.AppKey("oauth_refresh_task", asyncio.Task[None])
AppPasswordRefreshTaskAppKey: Final = web.AppKey(
    "app_password_refresh_task", asyncio.Task[None]
)
TickHealthTaskAppKey: Final = web.AppKey("tick_health_task", asyncio.Task[None])
TelegrafStatsdClientAppKey: Final = web.AppKey(
    "telegraf_statsd_client", TelegrafStatsdClient
)
