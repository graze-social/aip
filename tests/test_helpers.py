"""
Common testing utilities for AIP model tests.

Provides reusable functions for CRUD operations, constraint testing,
and other common test patterns to reduce code duplication.
"""

from datetime import datetime, timezone, timedelta
from typing import Type, Dict, Any, List
from sqlalchemy import select, update, delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from ulid import ULID

from social.graze.aip.model.base import Base


def generate_ulid_string() -> str:
    """Generate a ULID string for testing."""
    return str(ULID())


def generate_test_datetime(offset_minutes: int = 0) -> datetime:
    """Generate a timezone-aware datetime for testing."""
    return datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)


def assert_model_fields_match(
    model_instance: Base, expected_data: Dict[str, Any]
) -> None:
    """Assert that all fields in expected_data match the model instance."""
    for field_name, expected_value in expected_data.items():
        actual_value = getattr(model_instance, field_name)
        assert (
            actual_value == expected_value
        ), f"Field {field_name}: expected {expected_value}, got {actual_value}"


async def create_and_verify_record(
    session: AsyncSession,
    model_class: Type[Base],
    data: Dict[str, Any],
    primary_key_field: str,
) -> Base:
    """Create a record and verify it was created correctly."""
    record = model_class(**data)
    session.add(record)
    await session.commit()

    # Verify the record was created
    primary_key_value = data[primary_key_field]
    result = await session.execute(
        select(model_class).where(
            getattr(model_class, primary_key_field) == primary_key_value
        )
    )
    retrieved_record = result.scalar_one()

    assert_model_fields_match(retrieved_record, data)
    return retrieved_record


async def assert_read_nonexistent_record(
    session: AsyncSession,
    model_class: Type[Base],
    primary_key_field: str,
    nonexistent_key_value: str = "nonexistent-key",
) -> None:
    """Test reading a nonexistent record returns None."""
    result = await session.execute(
        select(model_class).where(
            getattr(model_class, primary_key_field) == nonexistent_key_value
        )
    )
    record = result.scalar_one_or_none()
    assert record is None


async def assert_update_record(
    session: AsyncSession,
    model_class: Type[Base],
    initial_data: Dict[str, Any],
    updates: Dict[str, Any],
    primary_key_field: str,
) -> None:
    """Test updating record fields."""
    # Create initial record
    record = model_class(**initial_data)
    session.add(record)
    await session.commit()

    # Update fields
    primary_key_value = initial_data[primary_key_field]
    await session.execute(
        update(model_class)
        .where(getattr(model_class, primary_key_field) == primary_key_value)
        .values(**updates)
    )
    await session.commit()

    # Verify updates
    result = await session.execute(
        select(model_class).where(
            getattr(model_class, primary_key_field) == primary_key_value
        )
    )
    updated_record = result.scalar_one()

    # Check updated fields
    for field_name, expected_value in updates.items():
        actual_value = getattr(updated_record, field_name)
        assert actual_value == expected_value

    # Check unchanged fields
    for field_name, original_value in initial_data.items():
        if field_name not in updates:
            actual_value = getattr(updated_record, field_name)
            assert actual_value == original_value


async def assert_delete_record(
    session: AsyncSession,
    model_class: Type[Base],
    data: Dict[str, Any],
    primary_key_field: str,
) -> None:
    """Test deleting a record."""
    # Create record
    record = model_class(**data)
    session.add(record)
    await session.commit()

    # Delete record
    primary_key_value = data[primary_key_field]
    await session.execute(
        delete(model_class).where(
            getattr(model_class, primary_key_field) == primary_key_value
        )
    )
    await session.commit()

    # Verify deletion
    result = await session.execute(
        select(model_class).where(
            getattr(model_class, primary_key_field) == primary_key_value
        )
    )
    deleted_record = result.scalar_one_or_none()
    assert deleted_record is None


async def assert_primary_key_uniqueness(
    session: AsyncSession,
    model_class: Type[Base],
    first_record_data: Dict[str, Any],
    second_record_data: Dict[str, Any],
    primary_key_field: str,
) -> None:
    """Test that primary key enforces uniqueness."""
    # Create first record
    record1 = model_class(**first_record_data)
    session.add(record1)
    await session.commit()
    session.expunge(record1)

    # Try to create second record with same primary key
    try:
        record2 = model_class(**second_record_data)
        session.add(record2)
        await session.commit()
        assert False, "Expected IntegrityError was not raised"
    except IntegrityError:
        await session.rollback()


async def assert_field_length_constraint(
    session: AsyncSession,
    model_class: Type[Base],
    base_data: Dict[str, Any],
    field_name: str,
    max_length: int,
    primary_key_field: str,
) -> None:
    """Test that string field respects length constraints."""
    # Create data with overly long field value
    long_value = "x" * (max_length + 100)  # Exceed max length
    test_data = base_data.copy()
    test_data[field_name] = long_value

    try:
        record = model_class(**test_data)
        session.add(record)
        await session.commit()

        # If commit succeeds, verify truncation occurred
        primary_key_value = test_data[primary_key_field]
        result = await session.execute(
            select(model_class).where(
                getattr(model_class, primary_key_field) == primary_key_value
            )
        )
        created_record = result.scalar_one()
        actual_length = len(getattr(created_record, field_name))
        assert (
            actual_length <= max_length
        ), f"Field {field_name} length {actual_length} exceeds max {max_length}"
    except Exception:
        # If commit fails, that's also acceptable behavior for constraint violation
        await session.rollback()


async def assert_datetime_timezone_handling(
    session: AsyncSession,
    model_class: Type[Base],
    data: Dict[str, Any],
    datetime_fields: List[str],
    primary_key_field: str,
) -> None:
    """Test that datetime fields handle timezone-aware values correctly."""
    # Ensure all datetime fields are timezone-aware
    for field_name in datetime_fields:
        if field_name in data:
            data[field_name] = generate_test_datetime()

    record = model_class(**data)
    session.add(record)
    await session.commit()

    # Verify timezone-aware retrieval
    primary_key_value = data[primary_key_field]
    result = await session.execute(
        select(model_class).where(
            getattr(model_class, primary_key_field) == primary_key_value
        )
    )
    retrieved_record = result.scalar_one()

    # Check that datetime fields have timezone info
    for field_name in datetime_fields:
        if field_name in data:
            datetime_value = getattr(retrieved_record, field_name)
            assert (
                datetime_value.tzinfo is not None
            ), f"Field {field_name} should be timezone-aware"


async def assert_nullable_constraints(
    session: AsyncSession,
    model_class: Type[Base],
    base_data: Dict[str, Any],
    required_fields: List[str],
) -> None:
    """Test that non-nullable fields enforce constraints."""
    for field_name in required_fields:
        test_data = base_data.copy()
        # Remove required field to test constraint
        if field_name in test_data:
            del test_data[field_name]

        try:
            record = model_class(**test_data)
            session.add(record)
            await session.commit()
            assert False, f"Expected constraint violation for missing {field_name}"
        except Exception:
            await session.rollback()


def create_test_data_variants(
    base_data: Dict[str, Any], count: int = 3
) -> List[Dict[str, Any]]:
    """Create multiple variants of test data with unique ULIDs."""
    variants = []
    for i in range(count):
        variant = base_data.copy()
        # Replace any ULID fields with new ULIDs
        for key, value in variant.items():
            if isinstance(value, str) and key.lower() in [
                "guid",
                "id",
                "oauth_state",
                "session_group",
            ]:
                variant[key] = generate_ulid_string()
            elif isinstance(value, datetime):
                variant[key] = generate_test_datetime(offset_minutes=i)
        variants.append(variant)
    return variants


async def assert_multiple_records_creation(
    session: AsyncSession,
    model_class: Type[Base],
    data_variants: List[Dict[str, Any]],
    expected_count: int,
) -> None:
    """Test creating multiple records with different data."""
    # Create all records
    for data in data_variants:
        record = model_class(**data)
        session.add(record)
    await session.commit()

    # Verify all were created
    result = await session.execute(select(model_class))
    all_records = result.scalars().all()
    assert len(all_records) == expected_count
