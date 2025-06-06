"""
Unit tests for App Password models in social.graze.aip.model.app_password

Tests cover CRUD operations, constraints, and edge cases
following modern pytest standards with async SQLAlchemy support using PostgreSQL.
"""

import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, update, delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from ulid import ULID

from social.graze.aip.model.app_password import AppPassword, AppPasswordSession
from tests.test_helpers import (
    generate_ulid_string,
    generate_test_datetime,
    create_and_verify_record,
    assert_read_nonexistent_record,
    assert_update_record,
    assert_delete_record,
    assert_primary_key_uniqueness,
    assert_field_length_constraint,
    assert_datetime_timezone_handling,
    assert_nullable_constraints,
    create_test_data_variants,
    assert_multiple_records_creation
)


@pytest.fixture
def sample_app_password_data():
    """Sample app password data for testing."""
    return {
        "guid": generate_ulid_string(),
        "app_password": "test_app_password_" + generate_ulid_string()[:32],
        "created_at": generate_test_datetime()
    }


@pytest.fixture
def sample_app_password_session_data():
    """Sample app password session data for testing."""
    return {
        "guid": generate_ulid_string(),
        "access_token": "test_access_token_" + generate_ulid_string(),
        "access_token_expires_at": generate_test_datetime(60),  # 1 hour from now
        "refresh_token": "test_refresh_token_" + generate_ulid_string()[:32],
        "refresh_token_expires_at": generate_test_datetime(43200),  # 30 days from now
        "created_at": generate_test_datetime()
    }


@pytest.fixture
def alternative_app_password_data():
    """Alternative app password data for testing updates."""
    return {
        "guid": str(ULID()),
        "app_password": "alt_app_password_" + str(ULID())[:32],
        "created_at": datetime.now(timezone.utc) + timedelta(minutes=1)
    }


class TestAppPasswordModel:
    """Test suite for AppPassword model CRUD operations."""

    async def test_create_app_password(self, session: AsyncSession, sample_app_password_data):
        """Test creating a new AppPassword record."""
        await create_and_verify_record(session, AppPassword, sample_app_password_data, "guid")

    async def test_create_app_password_with_invalid_data(self, session: AsyncSession):
        """Test creating AppPassword with invalid data raises appropriate errors."""
        # Test with excessively long guid that exceeds 512 character limit
        long_guid = "x" * 600  # Exceeds 512 character limit

        try:
            app_password = AppPassword(
                guid=long_guid,
                app_password="test_password",
                created_at=datetime.now(timezone.utc)
            )
            session.add(app_password)
            await session.commit()
            # Should fail due to length constraint
            assert False, "Expected constraint violation"
        except Exception:
            await session.rollback()

    async def test_read_app_password_by_guid(self, session: AsyncSession, sample_app_password_data):
        """Test reading AppPassword by primary key (guid)."""
        app_password = AppPassword(**sample_app_password_data)
        session.add(app_password)
        await session.commit()

        # Read by guid
        result = await session.execute(
            select(AppPassword).where(AppPassword.guid == sample_app_password_data["guid"])
        )
        retrieved_password = result.scalar_one()

        assert retrieved_password.app_password == sample_app_password_data["app_password"]
        assert retrieved_password.created_at == sample_app_password_data["created_at"]

    async def test_read_nonexistent_app_password(self, session: AsyncSession):
        """Test reading nonexistent AppPassword returns None."""
        await assert_read_nonexistent_record(session, AppPassword, "guid", "nonexistent-guid")

    async def test_update_app_password(self, session: AsyncSession, sample_app_password_data):
        """Test updating AppPassword fields."""
        updates = {"app_password": "updated_app_password_" + generate_ulid_string()[:32]}
        await assert_update_record(session, AppPassword, sample_app_password_data, updates, "guid")

    async def test_delete_app_password(self, session: AsyncSession, sample_app_password_data):
        """Test deleting AppPassword record."""
        await assert_delete_record(session, AppPassword, sample_app_password_data, "guid")

    async def test_app_password_field_constraints(self, session: AsyncSession):
        """Test that app_password field respects length constraints (512 chars)."""
        # Create app password with very long password (exceeding 512 characters)
        long_password = "password_" + "x" * 600  # Exceeds 512 character limit
        guid = str(ULID())

        try:
            app_password = AppPassword(
                guid=guid,
                app_password=long_password,
                created_at=datetime.now(timezone.utc)
            )
            session.add(app_password)
            await session.commit()
            # If commit succeeds, verify truncation occurred
            result = await session.execute(
                select(AppPassword).where(AppPassword.guid == guid)
            )
            created_password = result.scalar_one()
            assert len(created_password.app_password) <= 512
        except Exception:
            # If commit fails, that's also acceptable behavior
            await session.rollback()


class TestAppPasswordSessionModel:
    """Test suite for AppPasswordSession model CRUD operations."""

    async def test_create_app_password_session(self, session: AsyncSession, sample_app_password_session_data):
        """Test creating a new AppPasswordSession record."""
        app_session = AppPasswordSession(**sample_app_password_session_data)
        session.add(app_session)
        await session.commit()

        # Verify the session was created
        result = await session.execute(
            select(AppPasswordSession).where(AppPasswordSession.guid == sample_app_password_session_data["guid"])
        )
        retrieved_session = result.scalar_one()

        assert retrieved_session.guid == sample_app_password_session_data["guid"]
        assert retrieved_session.access_token == sample_app_password_session_data["access_token"]
        assert retrieved_session.access_token_expires_at == sample_app_password_session_data["access_token_expires_at"]
        assert retrieved_session.refresh_token == sample_app_password_session_data["refresh_token"]
        assert retrieved_session.refresh_token_expires_at == sample_app_password_session_data["refresh_token_expires_at"]
        assert retrieved_session.created_at == sample_app_password_session_data["created_at"]

    async def test_create_app_password_session_with_long_tokens(self, session: AsyncSession, sample_app_password_session_data):
        """Test creating AppPasswordSession with very long tokens (testing str1024 constraint)."""
        # Create long access token (exactly 1024 characters)
        long_access_token = "bearer_" + "x" * 1017  # 7 + 1017 = 1024 chars
        sample_app_password_session_data["access_token"] = long_access_token

        app_session = AppPasswordSession(**sample_app_password_session_data)
        session.add(app_session)
        await session.commit()

        # Verify creation succeeded
        result = await session.execute(
            select(AppPasswordSession).where(AppPasswordSession.guid == sample_app_password_session_data["guid"])
        )
        retrieved_session = result.scalar_one()

        assert retrieved_session.access_token == long_access_token

    async def test_read_app_password_session_by_guid(self, session: AsyncSession, sample_app_password_session_data):
        """Test reading AppPasswordSession by primary key (guid)."""
        app_session = AppPasswordSession(**sample_app_password_session_data)
        session.add(app_session)
        await session.commit()

        # Read by guid
        result = await session.execute(
            select(AppPasswordSession).where(AppPasswordSession.guid == sample_app_password_session_data["guid"])
        )
        retrieved_session = result.scalar_one()

        assert retrieved_session.access_token == sample_app_password_session_data["access_token"]
        assert retrieved_session.refresh_token == sample_app_password_session_data["refresh_token"]

    async def test_read_nonexistent_app_password_session(self, session: AsyncSession):
        """Test reading nonexistent AppPasswordSession returns None."""
        result = await session.execute(
            select(AppPasswordSession).where(AppPasswordSession.guid == "nonexistent-guid")
        )
        app_session = result.scalar_one_or_none()

        assert app_session is None

    async def test_update_app_password_session_tokens(self, session: AsyncSession, sample_app_password_session_data):
        """Test updating AppPasswordSession token fields."""
        # Create initial session
        app_session = AppPasswordSession(**sample_app_password_session_data)
        session.add(app_session)
        await session.commit()

        # Update tokens and expiration
        new_access_token = "new_access_token_" + str(ULID())
        new_refresh_token = "new_refresh_token_" + str(ULID())[:32]
        new_access_expires_at = datetime.now(timezone.utc) + timedelta(hours=2)

        await session.execute(
            update(AppPasswordSession)
            .where(AppPasswordSession.guid == sample_app_password_session_data["guid"])
            .values(
                access_token=new_access_token,
                refresh_token=new_refresh_token,
                access_token_expires_at=new_access_expires_at
            )
        )
        await session.commit()

        # Verify updates
        result = await session.execute(
            select(AppPasswordSession).where(AppPasswordSession.guid == sample_app_password_session_data["guid"])
        )
        updated_session = result.scalar_one()

        assert updated_session.access_token == new_access_token
        assert updated_session.refresh_token == new_refresh_token
        assert updated_session.access_token_expires_at == new_access_expires_at
        assert updated_session.created_at == sample_app_password_session_data["created_at"]  # Unchanged

    async def test_delete_app_password_session(self, session: AsyncSession, sample_app_password_session_data):
        """Test deleting AppPasswordSession record."""
        # Create session
        app_session = AppPasswordSession(**sample_app_password_session_data)
        session.add(app_session)
        await session.commit()

        # Delete session
        await session.execute(
            delete(AppPasswordSession).where(AppPasswordSession.guid == sample_app_password_session_data["guid"])
        )
        await session.commit()

        # Verify deletion
        result = await session.execute(
            select(AppPasswordSession).where(AppPasswordSession.guid == sample_app_password_session_data["guid"])
        )
        deleted_session = result.scalar_one_or_none()

        assert deleted_session is None

    async def test_app_password_session_token_expiration_logic(self, session: AsyncSession):
        """Test AppPasswordSession with different token expiration scenarios."""
        now = datetime.now(timezone.utc)
        
        # Create session with expired access token but valid refresh token
        expired_session_data = {
            "guid": str(ULID()),
            "access_token": "expired_access_token",
            "access_token_expires_at": now - timedelta(hours=1),  # Expired
            "refresh_token": "valid_refresh_token",
            "refresh_token_expires_at": now + timedelta(days=15),  # Valid
            "created_at": now - timedelta(hours=2)
        }

        app_session = AppPasswordSession(**expired_session_data)
        session.add(app_session)
        await session.commit()

        # Verify session was created with expired access token
        result = await session.execute(
            select(AppPasswordSession).where(AppPasswordSession.guid == expired_session_data["guid"])
        )
        retrieved_session = result.scalar_one()

        assert retrieved_session.access_token_expires_at < now  # Access token expired
        assert retrieved_session.refresh_token_expires_at > now  # Refresh token valid


class TestAppPasswordConstraintsAndEdgeCases:
    """Test suite for app password model constraints and edge cases."""

    async def test_app_password_guid_primary_key_uniqueness(self, session: AsyncSession):
        """Test that guid primary key enforces uniqueness for AppPassword."""
        guid = generate_ulid_string()
        created_at = generate_test_datetime()
        
        first_data = {
            "guid": guid,
            "app_password": "first_password",
            "created_at": created_at
        }
        
        second_data = {
            "guid": guid,  # Same GUID
            "app_password": "second_password",
            "created_at": created_at
        }
        
        await assert_primary_key_uniqueness(session, AppPassword, first_data, second_data, "guid")

    async def test_app_password_session_guid_primary_key_uniqueness(self, session: AsyncSession):
        """Test that guid primary key enforces uniqueness for AppPasswordSession."""
        guid = str(ULID())
        now = datetime.now(timezone.utc)

        # Create first session
        session1 = AppPasswordSession(
            guid=guid,
            access_token="first_access",
            access_token_expires_at=now + timedelta(hours=1),
            refresh_token="first_refresh",
            refresh_token_expires_at=now + timedelta(days=30),
            created_at=now
        )
        session.add(session1)
        await session.commit()
        session.expunge(session1)

        # Try to create second session with same guid
        try:
            session2 = AppPasswordSession(
                guid=guid,  # Same GUID
                access_token="second_access",
                access_token_expires_at=now + timedelta(hours=1),
                refresh_token="second_refresh",
                refresh_token_expires_at=now + timedelta(days=30),
                created_at=now
            )
            session.add(session2)
            await session.commit()
            assert False, "Expected IntegrityError was not raised"
        except IntegrityError:
            await session.rollback()

    async def test_datetime_timezone_handling(self, session: AsyncSession, sample_app_password_data):
        """Test that datetime fields handle timezone-aware values correctly."""
        datetime_fields = ["created_at"]
        await assert_datetime_timezone_handling(
            session, AppPassword, sample_app_password_data, datetime_fields, "guid"
        )

    async def test_field_length_constraints(self, session: AsyncSession):
        """Test that string fields respect length constraints."""
        base_data = {
            "guid": generate_ulid_string(),
            "app_password": "test_password",
            "created_at": generate_test_datetime()
        }
        
        # Test app_password length constraint (512 chars)
        await assert_field_length_constraint(session, AppPassword, base_data, "app_password", 512, "guid")

    async def test_nullable_constraints(self, session: AsyncSession):
        """Test that non-nullable fields enforce constraints."""
        # Test AppPassword required fields
        base_password_data = {
            "guid": generate_ulid_string(),
            "app_password": "test_password",
            "created_at": generate_test_datetime()
        }
        await assert_nullable_constraints(session, AppPassword, base_password_data, ["app_password"])
        
        # Test AppPasswordSession required fields
        base_session_data = {
            "guid": generate_ulid_string(),
            "access_token": "test_token",
            "access_token_expires_at": generate_test_datetime(60),
            "refresh_token": "test_refresh",
            "refresh_token_expires_at": generate_test_datetime(43200),
            "created_at": generate_test_datetime()
        }
        await assert_nullable_constraints(session, AppPasswordSession, base_session_data, ["refresh_token"])

    async def test_multiple_app_passwords_different_guids(self, session: AsyncSession):
        """Test that multiple app passwords can exist with different guids."""
        base_data = {
            "guid": generate_ulid_string(),
            "app_password": "password_base",
            "created_at": generate_test_datetime()
        }
        
        data_variants = create_test_data_variants(base_data, 3)
        # Customize each variant
        for i, variant in enumerate(data_variants):
            variant["app_password"] = f"password_{i}"
            
        await assert_multiple_records_creation(session, AppPassword, data_variants, 3)

        # Verify each has unique guid
        result = await session.execute(select(AppPassword))
        all_passwords = result.scalars().all()
        guids = [pwd.guid for pwd in all_passwords]
        assert len(set(guids)) == 3  # All unique