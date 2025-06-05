"""
Configuration Module for AIP Service

This module defines the configuration system for the AIP (AT Protocol Identity Provider) service,
using Pydantic for settings validation and dependency injection through AppKeys.

The configuration follows these principles:
1. Environment-based configuration with sensible defaults
2. Strong validation and typing through Pydantic
3. Dependency injection pattern using aiohttp's app context
4. Secure handling of cryptographic materials

The Settings class serves as the central configuration point, loaded from environment variables
with defaults suitable for development environments. All application components access settings
and shared resources through typed AppKeys to maintain clean dependency injection.

Key configuration areas include:
- Service identification and networking
- Database and cache connections
- Cryptographic materials (signing keys, encryption)
- Background processing configuration
- UI customization
"""

import os
import asyncio
from typing import Annotated, Final, List, Optional
import logging
from aio_statsd import TelegrafStatsdClient
from jwcrypto import jwk
from pydantic import (
    AliasChoices,
    Field,
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
    """
    Application settings for the AIP service.
    
    This class uses Pydantic's BaseSettings to automatically load values from environment
    variables, with sensible defaults for development environments. It handles validation,
    type conversion, and provides centralized configuration management.
    
    Settings are organized into the following categories:
    - Environment and debugging
    - Network and service identification
    - Database and cache connections
    - Security and cryptography
    - Background task configuration
    - Monitoring and observability
    - UI customization
    
    Environment variables are automatically mapped to settings fields, with aliases
    provided for backward compatibility. For example, the database connection string
    can be set with either PG_DSN or DATABASE_URL environment variables.
    """

    # Environment and debugging settings
    debug: bool = False
    """
    Enable debug mode for verbose logging and development features.
    Set with DEBUG=true environment variable.
    """
    
    allowed_domains: str = "https://www.graze.social, https://sky-feeder-git-astro-graze.vercel.app"
    """
    Comma-separated list of domains allowed for CORS.
    Set with ALLOWED_DOMAINS environment variable.
    """

    # Network and service identification settings
    http_port: int = Field(alias="port", default=5100)
    """
    HTTP port for the service to listen on.
    Set with PORT environment variable.
    """

    external_hostname: str = "aip_service"
    """
    Public hostname for the service, used for generating callback URLs.
    Set with EXTERNAL_HOSTNAME environment variable.
    """

    plc_hostname: str = "plc.directory"
    """
    Hostname for the PLC directory service for DID resolution.
    Set with PLC_HOSTNAME environment variable.
    """

    # Monitoring and error reporting
    sentry_dsn: Optional[str] = None
    """
    Sentry DSN for error reporting. Optional, no error reporting if not set.
    Set with SENTRY_DSN environment variable.
    """

    # Database and cache connections
    redis_dsn: RedisDsn = Field(
        "redis://valkey:6379/1?decode_responses=True",
        validation_alias=AliasChoices("redis_dsn", "redis_url"),
    )  # type: ignore
    """
    Redis connection string for caching and background tasks.
    Set with REDIS_DSN or REDIS_URL environment variables.
    Default: redis://valkey:6379/1?decode_responses=True
    """

    pg_dsn: PostgresDsn = Field(
        "postgresql+asyncpg://postgres:password@db/aip",
        validation_alias=AliasChoices("pg_dsn", "database_url"),
    )  # type: ignore
    """
    PostgreSQL connection string for database access.
    Set with PG_DSN or DATABASE_URL environment variables.
    Default: postgresql+asyncpg://postgres:password@db/aip
    """

    # Security and cryptography settings
    json_web_keys: Annotated[jwk.JWKSet, NoDecode] = jwk.JWKSet()
    """
    JSON Web Key Set containing signing keys for JWT operations.
    Can be set to a JWKSet object or path to a JSON file containing keys.
    Set with JSON_WEB_KEYS environment variable.
    """

    active_signing_keys: List[str] = list()
    """
    List of key IDs (kid) from json_web_keys that should be used for signing.
    Set with ACTIVE_SIGNING_KEYS environment variable as comma-separated values.
    """

    service_auth_keys: List[str] = list()
    """
    List of key IDs (kid) from json_web_keys used for service-to-service auth.
    Set with SERVICE_AUTH_KEYS environment variable as comma-separated values.
    """

    encryption_key: Fernet = Fernet(Fernet.generate_key())
    """
    Fernet symmetric encryption key for sensitive data.
    Can be set to a Fernet object or base64-encoded key string.
    Set with ENCRYPTION_KEY environment variable.
    """

    # Worker identification
    worker_id: str
    """
    Unique identifier for this worker instance (required, no default).
    Used to distribute work among multiple instances.
    Set with WORKER_ID environment variable.
    """

    # Background processing configuration
    refresh_queue_oauth: str = "refresh_queue:oauth"
    """
    Redis queue name for OAuth token refresh tasks.
    Set with REFRESH_QUEUE_OAUTH environment variable.
    """

    refresh_queue_app_password: str = "refresh_queue:app_password"
    """
    Redis queue name for App Password refresh tasks.
    Set with REFRESH_QUEUE_APP_PASSWORD environment variable.
    """
    
    # Token expiration settings
    app_password_access_token_expiry: int = 720  # 12 minutes
    """
    Expiration time in seconds for app password access tokens.
    Set with APP_PASSWORD_ACCESS_TOKEN_EXPIRY environment variable.
    Default: 720 (12 minutes)
    """
    
    app_password_refresh_token_expiry: int = 7776000  # 90 days
    """
    Expiration time in seconds for app password refresh tokens.
    Set with APP_PASSWORD_REFRESH_TOKEN_EXPIRY environment variable.
    Default: 7776000 (90 days)
    """
    
    token_refresh_before_expiry_ratio: float = 0.8
    """
    Ratio of token lifetime to wait before refreshing.
    For example, 0.8 means tokens are refreshed after 80% of their lifetime.
    Set with TOKEN_REFRESH_BEFORE_EXPIRY_RATIO environment variable.
    Default: 0.8
    """
    
    oauth_refresh_max_retries: int = 3
    """
    Maximum number of retry attempts for failed OAuth refresh operations.
    Set with OAUTH_REFRESH_MAX_RETRIES environment variable.
    Default: 3
    """
    
    oauth_refresh_retry_base_delay: int = 300
    """
    Base delay in seconds for OAuth refresh retry attempts (exponential backoff).
    Actual delay = base_delay * (2 ^ retry_attempt)
    Set with OAUTH_REFRESH_RETRY_BASE_DELAY environment variable.
    Default: 300 (5 minutes)
    """

    default_destination: str = "https://localhost:5100/auth/atproto/debug"
    """
    Default redirect destination after authentication if none specified.
    Set with DEFAULT_DESTINATION environment variable.
    """

    # Monitoring and observability settings
    statsd_host: str = Field(alias="TELEGRAF_HOST", default="telegraf")
    """
    StatsD/Telegraf host for metrics collection.
    Set with TELEGRAF_HOST environment variable.
    """
    
    statsd_port: int = Field(alias="TELEGRAF_PORT", default=8125)
    """
    StatsD/Telegraf port for metrics collection.
    Set with TELEGRAF_PORT environment variable.
    """
    
    statsd_prefix: str = "aip"
    """
    Prefix for all StatsD metrics from this service.
    Set with STATSD_PREFIX environment variable.
    """

    # UI customization settings for login page
    svg_logo: str = "https://www.graze.social/logo.svg"
    """URL for the logo displayed on the login page"""
    
    brand_name: str = "Graze"
    """Brand name displayed on the login page"""
    
    destination: str = "https://graze.social/app/auth/callback"
    """Default destination URL after authentication"""
    
    background_from: str = "#0588f0"
    """Starting gradient color for login page background"""
    
    background_to: str = "#5eb1ef"
    """Ending gradient color for login page background"""
    
    text_color: str = "#FFFFFF"
    """Text color for login page"""
    
    form_color: str = "#FFFFFF"
    """Form background color for login page"""

    @field_validator("json_web_keys", mode="before")
    @classmethod
    def decode_json_web_keys(cls, v) -> jwk.JWKSet:
        """
        Validate and process the json_web_keys setting.
        
        This validator accepts either:
        - An existing JWKSet object (for programmatic configuration)
        - A file path to a JSON file containing a JWK Set
        
        Args:
            v: The input value to validate
            
        Returns:
            jwk.JWKSet: A valid JWKSet object
            
        Raises:
            ValueError: If the input is neither a JWKSet nor a valid file path
        """
        if isinstance(v, jwk.JWKSet):  # If it's already a JWKSet, return it directly
            return v
        elif isinstance(v, str):  # If it's a file path, load from file
            with open(v) as fd:
                data = fd.read()
                return jwk.JWKSet.from_json(data)
        raise ValueError(
            "json_web_keys must be a JWKSet object or a valid JSON file path"
        )

    @field_validator("encryption_key", mode="before")
    @classmethod
    def decode_encryption_key(cls, v) -> Fernet:
        """
        Validate and process the encryption_key setting.
        
        This validator accepts either:
        - An existing Fernet object (for programmatic configuration)
        - A base64-encoded string containing a Fernet key
        
        Args:
            v: The input value to validate
            
        Returns:
            Fernet: A valid Fernet encryption object
            
        Raises:
            ValueError: If the input is neither a Fernet object nor a valid base64 key
        """
        if isinstance(v, Fernet):  # Already a Fernet instance, return it
            return v
        elif isinstance(v, str):  # Decode from a base64-encoded string
            key_data = base64.b64decode(v)
            return Fernet(key_data)
        raise ValueError(
            "encryption_key must be a Fernet object or a base64-encoded key string"
        )


# Background task queue constants
OAUTH_REFRESH_QUEUE = "auth_session:oauth:refresh"
"""
Redis sorted set key for scheduling OAuth token refresh operations.
Contains session_group IDs with refresh timestamps as scores.
"""

OAUTH_REFRESH_RETRY_QUEUE = "auth_session:oauth:refresh:retry"
"""
Redis hash key for tracking OAuth refresh retry attempts.
Keys are session_group IDs, values are retry counts.
"""

APP_PASSWORD_REFRESH_QUEUE = "auth_session:app-password:refresh"
"""
Redis sorted set key for scheduling App Password refresh operations.
Contains user GUIDs with refresh timestamps as scores.
"""

# Application context keys for dependency injection
SettingsAppKey: Final = web.AppKey("settings", Settings)
"""AppKey for accessing the application settings"""

DatabaseAppKey: Final = web.AppKey("database", AsyncEngine)
"""AppKey for accessing the SQLAlchemy async database engine"""

DatabaseSessionMakerAppKey: Final = web.AppKey(
    "database_session_maker", async_sessionmaker[AsyncSession]
)
"""AppKey for accessing the SQLAlchemy async session factory"""

SessionAppKey: Final = web.AppKey("http_session", ClientSession)
"""AppKey for accessing the shared aiohttp client session"""

RedisPoolAppKey: Final = web.AppKey("redis_pool", redis.ConnectionPool)
"""AppKey for accessing the Redis connection pool"""

RedisClientAppKey: Final = web.AppKey("redis_client", redis.Redis)
"""AppKey for accessing the Redis client"""

HealthGaugeAppKey: Final = web.AppKey("health_gauge", HealthGauge)
"""AppKey for accessing the health monitoring gauge"""

OAuthRefreshTaskAppKey: Final = web.AppKey("oauth_refresh_task", asyncio.Task[None])
"""AppKey for the background task that refreshes OAuth tokens"""

AppPasswordRefreshTaskAppKey: Final = web.AppKey(
    "app_password_refresh_task", asyncio.Task[None]
)
"""AppKey for the background task that refreshes App Passwords"""

TickHealthTaskAppKey: Final = web.AppKey("tick_health_task", asyncio.Task[None])
"""AppKey for the background task that monitors service health"""

TelegrafStatsdClientAppKey: Final = web.AppKey(
    "telegraf_statsd_client", TelegrafStatsdClient
)
"""AppKey for the Telegraf/StatsD metrics client"""