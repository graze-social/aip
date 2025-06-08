"""
Shared test configuration and fixtures for AIP model tests.

Provides common database setup, session management, and testing utilities
used across all model test files.
"""

import os
import uuid
import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from social.graze.aip.model.base import Base

# Try to import Redis testing dependencies
try:
    import redis.asyncio as redis
    import fakeredis.aioredis

    REDIS_AVAILABLE = True
except ImportError:
    redis = None
    fakeredis = None
    REDIS_AVAILABLE = False


# Test database configuration
TEST_DB_HOST = os.getenv("TEST_DB_HOST", "postgres")
TEST_DB_PORT = os.getenv("TEST_DB_PORT", "5432")
TEST_DB_USER = os.getenv("TEST_DB_USER", "postgres")
TEST_DB_PASSWORD = os.getenv("TEST_DB_PASSWORD", "password")
TEST_DB_NAME = os.getenv("TEST_DB_NAME", "aip_test_db")

# Admin URL for database creation/deletion (connects to postgres database)
ADMIN_DATABASE_URL = f"postgresql+asyncpg://{TEST_DB_USER}:{TEST_DB_PASSWORD}@{TEST_DB_HOST}:{TEST_DB_PORT}/postgres"


async def check_postgres_available():
    """Check if PostgreSQL is available for testing."""
    try:
        admin_engine = create_async_engine(ADMIN_DATABASE_URL, echo=False)
        async with admin_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        await admin_engine.dispose()
        return True
    except Exception:
        return False


@pytest_asyncio.fixture(scope="function")
async def test_database():
    """Create and clean up test database for each test function."""
    # Skip if PostgreSQL is not available
    if not await check_postgres_available():
        pytest.skip("PostgreSQL database not available for testing")

    # Use a unique database name for each test to avoid conflicts
    unique_db_name = f"aip_test_{uuid.uuid4().hex[:8]}"
    unique_db_url = (
        f"postgresql+asyncpg://{TEST_DB_USER}:{TEST_DB_PASSWORD}@"
        f"{TEST_DB_HOST}:{TEST_DB_PORT}/{unique_db_name}"
    )

    # Create admin engine to manage database creation/deletion
    admin_engine = create_async_engine(
        ADMIN_DATABASE_URL, echo=False, isolation_level="AUTOCOMMIT"
    )

    try:
        # Create test database
        async with admin_engine.connect() as conn:
            await conn.execute(text(f"CREATE DATABASE {unique_db_name}"))

        yield unique_db_url

    finally:
        # Clean up: drop test database
        async with admin_engine.connect() as conn:
            await conn.execute(text(f"DROP DATABASE IF EXISTS {unique_db_name}"))
        await admin_engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def engine(test_database):
    """Create async SQLAlchemy engine for testing with PostgreSQL."""
    engine = create_async_engine(
        test_database,
        echo=False,
    )

    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def session(engine):
    """Create async database session for testing."""
    async_session = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async with async_session() as session:
        yield session


# Redis test configuration and fixtures
TEST_REDIS_HOST = os.getenv("TEST_REDIS_HOST", "valkey")
TEST_REDIS_PORT = int(os.getenv("TEST_REDIS_PORT", "6379"))
TEST_REDIS_DB = int(os.getenv("TEST_REDIS_DB", "15"))  # Use a separate test DB


async def check_redis_available():
    """Check if Redis is available for testing."""
    if not REDIS_AVAILABLE or redis is None:
        return False

    try:
        redis_client = redis.Redis(
            host=TEST_REDIS_HOST,
            port=TEST_REDIS_PORT,
            db=TEST_REDIS_DB,
            decode_responses=False,
        )
        await redis_client.ping()
        await redis_client.aclose()
        return True
    except Exception:
        return False


@pytest_asyncio.fixture
async def redis_client():
    """Provide real Redis client for integration tests."""
    if not await check_redis_available():
        pytest.skip("Redis server not available for testing")

    assert redis is not None, "Redis should be available after check"
    client = redis.Redis(
        host=TEST_REDIS_HOST,
        port=TEST_REDIS_PORT,
        db=TEST_REDIS_DB,
        decode_responses=False,
    )

    # Clean up test database before test
    await client.flushdb()

    yield client

    # Clean up test database after test
    await client.flushdb()
    await client.aclose()


@pytest_asyncio.fixture
async def fake_redis_client():
    """Provide fake Redis client for unit tests."""
    if not REDIS_AVAILABLE or fakeredis is None:
        pytest.skip("fakeredis not available")

    assert fakeredis is not None, "fakeredis should be available after check"
    client = fakeredis.aioredis.FakeRedis(decode_responses=False)
    yield client
    await client.flushall()
    await client.aclose()
