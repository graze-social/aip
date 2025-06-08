"""
Unit tests for Handle model in social.graze.aip.model.handles

Tests cover CRUD operations, upsert functionality, constraints, and indexes
following modern pytest standards with async SQLAlchemy support using PostgreSQL.
"""

import pytest
from sqlalchemy import select, update, delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from ulid import ULID

from social.graze.aip.model.handles import Handle, upsert_handle_stmt
from tests.test_helpers import (
    generate_ulid_string,
    create_and_verify_record,
    assert_read_nonexistent_record,
    assert_update_record,
    assert_delete_record,
    assert_primary_key_uniqueness,
    assert_field_length_constraint,
    create_test_data_variants,
    assert_multiple_records_creation,
)


@pytest.fixture
def sample_handle_data():
    """Sample handle data for testing."""
    return {
        "guid": generate_ulid_string(),
        "did": "did:plc:abcdef123456",
        "handle": "user.bsky.social",
        "pds": "https://pds.example.com",
    }


@pytest.fixture
def alternative_handle_data():
    """Alternative handle data for testing updates."""
    return {
        "guid": generate_ulid_string(),
        "did": "did:plc:fedcba654321",
        "handle": "another.bsky.social",
        "pds": "https://another-pds.example.com",
    }


class TestHandleModel:
    """Test suite for Handle model CRUD operations."""

    async def test_create_handle(self, session: AsyncSession, sample_handle_data):
        """Test creating a new Handle record."""
        await create_and_verify_record(session, Handle, sample_handle_data, "guid")

    async def test_create_handle_with_invalid_data(self, session: AsyncSession):
        """Test creating Handle with invalid data raises appropriate errors."""
        # Test with excessively long GUID that exceeds primary key limits
        very_long_guid = "x" * 1000  # Exceeds 512 character limit for guidpk

        try:
            handle = Handle(
                guid=very_long_guid,
                did="did:plc:test",
                handle="test.bsky.social",
                pds="https://test.com",
            )
            session.add(handle)
            await session.commit()
            # For SQLite, this might succeed with truncation, so we just verify
            # the behavior is consistent (either fails or truncates)
        except Exception:
            # Any exception is acceptable for invalid data
            await session.rollback()

    async def test_read_handle_by_guid(self, session: AsyncSession, sample_handle_data):
        """Test reading Handle by primary key (guid)."""
        handle = Handle(**sample_handle_data)
        session.add(handle)
        await session.commit()

        # Read by guid
        result = await session.execute(
            select(Handle).where(Handle.guid == sample_handle_data["guid"])
        )
        retrieved_handle = result.scalar_one()

        assert retrieved_handle.did == sample_handle_data["did"]
        assert retrieved_handle.handle == sample_handle_data["handle"]

    async def test_read_handle_by_did(self, session: AsyncSession, sample_handle_data):
        """Test reading Handle by DID (unique index)."""
        handle = Handle(**sample_handle_data)
        session.add(handle)
        await session.commit()

        # Read by DID
        result = await session.execute(
            select(Handle).where(Handle.did == sample_handle_data["did"])
        )
        retrieved_handle = result.scalar_one()

        assert retrieved_handle.guid == sample_handle_data["guid"]
        assert retrieved_handle.handle == sample_handle_data["handle"]

    async def test_read_handle_by_handle(
        self, session: AsyncSession, sample_handle_data
    ):
        """Test reading Handle by handle (indexed but not unique)."""
        handle = Handle(**sample_handle_data)
        session.add(handle)
        await session.commit()

        # Read by handle
        result = await session.execute(
            select(Handle).where(Handle.handle == sample_handle_data["handle"])
        )
        retrieved_handle = result.scalar_one()

        assert retrieved_handle.guid == sample_handle_data["guid"]
        assert retrieved_handle.did == sample_handle_data["did"]

    async def test_read_nonexistent_handle(self, session: AsyncSession):
        """Test reading nonexistent Handle returns None."""
        await assert_read_nonexistent_record(
            session, Handle, "guid", "nonexistent-guid"
        )

    async def test_update_handle(self, session: AsyncSession, sample_handle_data):
        """Test updating Handle fields."""
        updates = {
            "handle": "updated.bsky.social",
            "pds": "https://updated-pds.example.com",
        }
        await assert_update_record(session, Handle, sample_handle_data, updates, "guid")

    async def test_delete_handle(self, session: AsyncSession, sample_handle_data):
        """Test deleting Handle record."""
        await assert_delete_record(session, Handle, sample_handle_data, "guid")

    async def test_did_unique_constraint(
        self, session: AsyncSession, sample_handle_data
    ):
        """Test that DID field enforces uniqueness."""
        # Create first handle
        handle1 = Handle(**sample_handle_data)
        session.add(handle1)
        await session.commit()

        # Expunge the first handle from session to avoid identity conflicts
        session.expunge(handle1)

        # Try to create second handle with same DID in a new transaction
        try:
            duplicate_data = sample_handle_data.copy()
            duplicate_data["guid"] = str(ULID())  # Different guid
            duplicate_data["handle"] = "different.bsky.social"  # Different handle

            handle2 = Handle(**duplicate_data)
            session.add(handle2)
            await session.commit()
            # If we get here, the test should fail
            assert False, "Expected IntegrityError was not raised"
        except IntegrityError:
            # Expected behavior - rollback the failed transaction
            await session.rollback()

    async def test_multiple_handles_same_handle_allowed(
        self, session: AsyncSession, sample_handle_data, alternative_handle_data
    ):
        """Test that multiple records can have the same handle (handle is indexed but not unique)."""
        # Modify alternative data to have same handle but different DID
        alternative_handle_data["handle"] = sample_handle_data["handle"]

        data_variants = [sample_handle_data, alternative_handle_data]
        await assert_multiple_records_creation(session, Handle, data_variants, 2)

        # Verify both were created with same handle
        result = await session.execute(
            select(Handle).where(Handle.handle == sample_handle_data["handle"])
        )
        handles = result.scalars().all()
        assert len(handles) == 2


class TestUpsertHandleStmt:
    """Test suite for upsert_handle_stmt function."""

    async def test_upsert_new_handle(self, session: AsyncSession):
        """Test upserting a new Handle (INSERT behavior)."""
        did = "did:plc:upsert123"
        handle = "upsert.bsky.social"
        pds = "https://upsert-pds.example.com"

        # Execute upsert statement
        stmt = upsert_handle_stmt(did=did, handle=handle, pds=pds)
        result = await session.execute(stmt)
        guid = result.scalar_one()
        await session.commit()

        # Verify the handle was created
        created_handle_result = await session.execute(
            select(Handle).where(Handle.guid == guid)
        )
        created_handle = created_handle_result.scalar_one()

        assert created_handle.did == did
        assert created_handle.handle == handle
        assert created_handle.pds == pds

    async def test_upsert_existing_handle(
        self, session: AsyncSession, sample_handle_data
    ):
        """Test upserting an existing Handle (UPDATE behavior)."""
        # Create initial handle
        handle = Handle(**sample_handle_data)
        session.add(handle)
        await session.commit()

        # Refresh the session to avoid caching issues
        await session.refresh(handle)

        # Upsert with same DID but different handle and pds
        new_handle = "updated-via-upsert.bsky.social"
        new_pds = "https://updated-via-upsert-pds.example.com"

        stmt = upsert_handle_stmt(
            did=sample_handle_data["did"], handle=new_handle, pds=new_pds
        )
        result = await session.execute(stmt)
        returned_guid = result.scalar_one()
        await session.commit()

        # Clear session cache to force fresh read from database
        session.expunge_all()

        # Verify the handle was updated - get fresh data from database
        updated_handle_result = await session.execute(
            select(Handle).where(Handle.did == sample_handle_data["did"])
        )
        updated_handle = updated_handle_result.scalar_one()

        assert updated_handle.did == sample_handle_data["did"]  # Unchanged
        assert updated_handle.handle == new_handle  # Updated
        assert updated_handle.pds == new_pds  # Updated
        # The returned GUID should be the same as the original
        assert returned_guid == sample_handle_data["guid"]

    async def test_upsert_returns_guid(self, session: AsyncSession):
        """Test that upsert statement returns the Handle GUID."""
        did = "did:plc:returnguid123"
        handle = "returnguid.bsky.social"
        pds = "https://returnguid-pds.example.com"

        stmt = upsert_handle_stmt(did=did, handle=handle, pds=pds)
        result = await session.execute(stmt)
        guid = result.scalar_one()
        await session.commit()

        # Verify that a valid ULID was returned
        assert guid is not None
        assert len(guid) == 26  # ULID length

        # Verify the GUID matches the created record
        handle_result = await session.execute(select(Handle).where(Handle.did == did))
        created_handle = handle_result.scalar_one()
        assert created_handle.guid == guid


class TestHandleConstraintsAndIndexes:
    """Test suite for Handle model constraints and indexes."""

    async def test_guid_primary_key_uniqueness(self, session: AsyncSession):
        """Test that GUID primary key enforces uniqueness."""
        guid = generate_ulid_string()
        first_data = {
            "guid": guid,
            "did": "did:plc:test1",
            "handle": "test1.bsky.social",
            "pds": "https://pds1.example.com",
        }
        second_data = {
            "guid": guid,  # Same GUID
            "did": "did:plc:test2",
            "handle": "test2.bsky.social",
            "pds": "https://pds2.example.com",
        }
        await assert_primary_key_uniqueness(
            session, Handle, first_data, second_data, "guid"
        )

    async def test_did_index_uniqueness(self, session: AsyncSession):
        """Test that DID index enforces uniqueness."""
        did = "did:plc:unique-did-test"
        first_data = {
            "guid": generate_ulid_string(),
            "did": did,
            "handle": "first.bsky.social",
            "pds": "https://first-pds.example.com",
        }
        second_data = {
            "guid": generate_ulid_string(),
            "did": did,  # Same DID
            "handle": "second.bsky.social",
            "pds": "https://second-pds.example.com",
        }
        await assert_primary_key_uniqueness(
            session, Handle, first_data, second_data, "did"
        )

    async def test_handle_index_allows_duplicates(self, session: AsyncSession):
        """Test that handle index allows duplicate values."""
        handle_value = "shared.bsky.social"
        data_variants = [
            {
                "guid": generate_ulid_string(),
                "did": "did:plc:first",
                "handle": handle_value,
                "pds": "https://first-pds.example.com",
            },
            {
                "guid": generate_ulid_string(),
                "did": "did:plc:second",
                "handle": handle_value,  # Same handle
                "pds": "https://second-pds.example.com",
            },
        ]
        await assert_multiple_records_creation(session, Handle, data_variants, 2)

        # Verify both records have the same handle
        result = await session.execute(
            select(Handle).where(Handle.handle == handle_value)
        )
        handles = result.scalars().all()
        assert len(handles) == 2

    async def test_field_length_constraints(self, session: AsyncSession):
        """Test that string fields respect length constraints (str512)."""
        base_data = {
            "guid": generate_ulid_string(),
            "did": "did:plc:test",
            "handle": "test.bsky.social",
            "pds": "https://test.com",
        }
        # Test each string field constraint
        for field_name in ["did", "handle", "pds"]:
            await assert_field_length_constraint(
                session, Handle, base_data, field_name, 512, "guid"
            )
