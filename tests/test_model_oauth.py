"""
Unit tests for OAuth models in social.graze.aip.model.oauth

Tests cover CRUD operations, upsert functionality, constraints, and indexes
following modern pytest standards with async SQLAlchemy support using PostgreSQL.
"""

import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, update, delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from ulid import ULID

from social.graze.aip.model.oauth import (
    OAuthRequest, 
    OAuthSession, 
    Permission, 
    upsert_permission_stmt
)
from tests.test_helpers import (
    generate_ulid_string,
    generate_test_datetime,
    create_and_verify_record,
    assert_read_nonexistent_record,
    assert_update_record,
    assert_delete_record,
    assert_primary_key_uniqueness,
    assert_field_length_constraint,
    assert_datetime_timezone_handling
)


@pytest.fixture
def sample_oauth_request_data():
    """Sample OAuth request data for testing."""
    return {
        "oauth_state": "test_state_" + generate_ulid_string()[:16],
        "issuer": "https://example.bsky.social",
        "guid": generate_ulid_string(),
        "pkce_verifier": "test_pkce_verifier_" + generate_ulid_string()[:32],
        "secret_jwk_id": "test_jwk_id_" + generate_ulid_string()[:16],
        "dpop_jwk": {"kty": "EC", "crv": "P-256", "x": "test_x", "y": "test_y"},
        "destination": "https://client.example.com/callback",
        "created_at": generate_test_datetime(),
        "expires_at": generate_test_datetime(10)  # 10 minutes from now
    }


@pytest.fixture
def sample_oauth_session_data():
    """Sample OAuth session data for testing."""
    return {
        "session_group": "session_" + generate_ulid_string()[:16],
        "issuer": "https://example.bsky.social",
        "guid": generate_ulid_string(),
        "access_token": "test_access_token_" + generate_ulid_string(),
        "refresh_token": "test_refresh_token_" + generate_ulid_string()[:32],
        "secret_jwk_id": "test_jwk_id_" + generate_ulid_string()[:16],
        "dpop_jwk": {"kty": "EC", "crv": "P-256", "x": "test_x", "y": "test_y"},
        "created_at": generate_test_datetime(),
        "access_token_expires_at": generate_test_datetime(60),  # 1 hour from now
        "hard_expires_at": generate_test_datetime(43200)  # 30 days from now
    }


@pytest.fixture
def sample_permission_data():
    """Sample permission data for testing."""
    return {
        "guid": generate_ulid_string(),
        "target_guid": generate_ulid_string(),
        "permission": 1,
        "created_at": generate_test_datetime()
    }


@pytest.fixture
def alternative_oauth_request_data():
    """Alternative OAuth request data for testing updates."""
    return {
        "oauth_state": "alt_state_" + str(ULID())[:16],
        "issuer": "https://alternative.bsky.social",
        "guid": str(ULID()),
        "pkce_verifier": "alt_pkce_verifier_" + str(ULID())[:32],
        "secret_jwk_id": "alt_jwk_id_" + str(ULID())[:16],
        "dpop_jwk": {"kty": "RSA", "n": "test_n", "e": "AQAB"},
        "destination": "https://alt-client.example.com/callback",
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=15)
    }


class TestOAuthRequestModel:
    """Test suite for OAuthRequest model CRUD operations."""

    async def test_create_oauth_request(self, session: AsyncSession, sample_oauth_request_data):
        """Test creating a new OAuthRequest record."""
        await create_and_verify_record(session, OAuthRequest, sample_oauth_request_data, "oauth_state")

    async def test_create_oauth_request_with_invalid_data(self, session: AsyncSession):
        """Test creating OAuthRequest with invalid data raises appropriate errors."""
        # Test with excessively long oauth_state that exceeds 64 character limit
        long_state = "x" * 100  # Exceeds 64 character limit

        try:
            oauth_request = OAuthRequest(
                oauth_state=long_state,
                issuer="https://test.bsky.social",
                guid=str(ULID()),
                pkce_verifier="test_verifier",
                secret_jwk_id="test_jwk",
                dpop_jwk={"kty": "EC"},
                destination="https://test.com/callback",
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
            )
            session.add(oauth_request)
            await session.commit()
            # Should fail due to length constraint
            assert False, "Expected constraint violation"
        except Exception:
            await session.rollback()

    async def test_read_oauth_request_by_state(self, session: AsyncSession, sample_oauth_request_data):
        """Test reading OAuthRequest by primary key (oauth_state)."""
        oauth_request = OAuthRequest(**sample_oauth_request_data)
        session.add(oauth_request)
        await session.commit()

        # Read by oauth_state
        result = await session.execute(
            select(OAuthRequest).where(OAuthRequest.oauth_state == sample_oauth_request_data["oauth_state"])
        )
        retrieved_request = result.scalar_one()

        assert retrieved_request.issuer == sample_oauth_request_data["issuer"]
        assert retrieved_request.guid == sample_oauth_request_data["guid"]

    async def test_read_nonexistent_oauth_request(self, session: AsyncSession):
        """Test reading nonexistent OAuthRequest returns None."""
        await assert_read_nonexistent_record(session, OAuthRequest, "oauth_state", "nonexistent-state")

    async def test_update_oauth_request(self, session: AsyncSession, sample_oauth_request_data):
        """Test updating OAuthRequest fields."""
        updates = {
            "destination": "https://updated.example.com/callback",
            "issuer": "https://updated.bsky.social"
        }
        await assert_update_record(session, OAuthRequest, sample_oauth_request_data, updates, "oauth_state")

    async def test_delete_oauth_request(self, session: AsyncSession, sample_oauth_request_data):
        """Test deleting OAuthRequest record."""
        await assert_delete_record(session, OAuthRequest, sample_oauth_request_data, "oauth_state")

    async def test_oauth_request_json_field(self, session: AsyncSession, sample_oauth_request_data):
        """Test that dpop_jwk JSON field stores and retrieves complex data correctly."""
        complex_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGHwHitJBcBmXdmqhDShAhOLdElvPUm7T-",
            "y": "ECYw_Z1cKRHfIJYLnp3yBFnjAzTejXm6FeNwpOxdQ3k",
            "use": "sig",
            "kid": "test-key-id"
        }
        sample_oauth_request_data["dpop_jwk"] = complex_jwk

        oauth_request = OAuthRequest(**sample_oauth_request_data)
        session.add(oauth_request)
        await session.commit()

        # Verify JSON field retrieval
        result = await session.execute(
            select(OAuthRequest).where(OAuthRequest.oauth_state == sample_oauth_request_data["oauth_state"])
        )
        retrieved_request = result.scalar_one()

        assert retrieved_request.dpop_jwk == complex_jwk
        assert retrieved_request.dpop_jwk["kty"] == "EC"
        assert retrieved_request.dpop_jwk["kid"] == "test-key-id"


class TestOAuthSessionModel:
    """Test suite for OAuthSession model CRUD operations."""

    async def test_create_oauth_session(self, session: AsyncSession, sample_oauth_session_data):
        """Test creating a new OAuthSession record."""
        oauth_session = OAuthSession(**sample_oauth_session_data)
        session.add(oauth_session)
        await session.commit()

        # Verify the session was created
        result = await session.execute(
            select(OAuthSession).where(OAuthSession.session_group == sample_oauth_session_data["session_group"])
        )
        retrieved_session = result.scalar_one()

        assert retrieved_session.session_group == sample_oauth_session_data["session_group"]
        assert retrieved_session.issuer == sample_oauth_session_data["issuer"]
        assert retrieved_session.guid == sample_oauth_session_data["guid"]
        assert retrieved_session.access_token == sample_oauth_session_data["access_token"]
        assert retrieved_session.refresh_token == sample_oauth_session_data["refresh_token"]
        assert retrieved_session.secret_jwk_id == sample_oauth_session_data["secret_jwk_id"]
        assert retrieved_session.dpop_jwk == sample_oauth_session_data["dpop_jwk"]

    async def test_create_oauth_session_with_long_tokens(self, session: AsyncSession, sample_oauth_session_data):
        """Test creating OAuthSession with very long tokens (testing str1024 constraint)."""
        # Create long access token (exactly 1024 characters)
        long_access_token = "bearer_" + "x" * 1017  # 7 + 1017 = 1024 chars
        sample_oauth_session_data["access_token"] = long_access_token

        oauth_session = OAuthSession(**sample_oauth_session_data)
        session.add(oauth_session)
        await session.commit()

        # Verify creation succeeded
        result = await session.execute(
            select(OAuthSession).where(OAuthSession.session_group == sample_oauth_session_data["session_group"])
        )
        retrieved_session = result.scalar_one()

        assert retrieved_session.access_token == long_access_token

    async def test_read_oauth_session_by_group(self, session: AsyncSession, sample_oauth_session_data):
        """Test reading OAuthSession by primary key (session_group)."""
        oauth_session = OAuthSession(**sample_oauth_session_data)
        session.add(oauth_session)
        await session.commit()

        # Read by session_group
        result = await session.execute(
            select(OAuthSession).where(OAuthSession.session_group == sample_oauth_session_data["session_group"])
        )
        retrieved_session = result.scalar_one()

        assert retrieved_session.issuer == sample_oauth_session_data["issuer"]
        assert retrieved_session.guid == sample_oauth_session_data["guid"]

    async def test_update_oauth_session_tokens(self, session: AsyncSession, sample_oauth_session_data):
        """Test updating OAuthSession token fields."""
        # Create initial session
        oauth_session = OAuthSession(**sample_oauth_session_data)
        session.add(oauth_session)
        await session.commit()

        # Update tokens and expiration
        new_access_token = "new_access_token_" + str(ULID())
        new_refresh_token = "new_refresh_token_" + str(ULID())[:32]
        new_expires_at = datetime.now(timezone.utc) + timedelta(hours=2)

        await session.execute(
            update(OAuthSession)
            .where(OAuthSession.session_group == sample_oauth_session_data["session_group"])
            .values(
                access_token=new_access_token,
                refresh_token=new_refresh_token,
                access_token_expires_at=new_expires_at
            )
        )
        await session.commit()

        # Verify updates
        result = await session.execute(
            select(OAuthSession).where(OAuthSession.session_group == sample_oauth_session_data["session_group"])
        )
        updated_session = result.scalar_one()

        assert updated_session.access_token == new_access_token
        assert updated_session.refresh_token == new_refresh_token
        assert updated_session.access_token_expires_at == new_expires_at
        assert updated_session.guid == sample_oauth_session_data["guid"]  # Unchanged

    async def test_delete_oauth_session(self, session: AsyncSession, sample_oauth_session_data):
        """Test deleting OAuthSession record."""
        # Create session
        oauth_session = OAuthSession(**sample_oauth_session_data)
        session.add(oauth_session)
        await session.commit()

        # Delete session
        await session.execute(
            delete(OAuthSession).where(OAuthSession.session_group == sample_oauth_session_data["session_group"])
        )
        await session.commit()

        # Verify deletion
        result = await session.execute(
            select(OAuthSession).where(OAuthSession.session_group == sample_oauth_session_data["session_group"])
        )
        deleted_session = result.scalar_one_or_none()

        assert deleted_session is None


class TestPermissionModel:
    """Test suite for Permission model CRUD operations."""

    async def test_create_permission(self, session: AsyncSession, sample_permission_data):
        """Test creating a new Permission record."""
        permission = Permission(**sample_permission_data)
        session.add(permission)
        await session.commit()

        # Verify the permission was created
        result = await session.execute(
            select(Permission).where(
                (Permission.guid == sample_permission_data["guid"]) &
                (Permission.target_guid == sample_permission_data["target_guid"])
            )
        )
        retrieved_permission = result.scalar_one()

        assert retrieved_permission.guid == sample_permission_data["guid"]
        assert retrieved_permission.target_guid == sample_permission_data["target_guid"]
        assert retrieved_permission.permission == sample_permission_data["permission"]
        assert retrieved_permission.created_at == sample_permission_data["created_at"]

    async def test_read_permission_by_composite_key(self, session: AsyncSession, sample_permission_data):
        """Test reading Permission by composite primary key (guid + target_guid)."""
        permission = Permission(**sample_permission_data)
        session.add(permission)
        await session.commit()

        # Read by composite key
        result = await session.execute(
            select(Permission).where(
                (Permission.guid == sample_permission_data["guid"]) &
                (Permission.target_guid == sample_permission_data["target_guid"])
            )
        )
        retrieved_permission = result.scalar_one()

        assert retrieved_permission.permission == sample_permission_data["permission"]

    async def test_read_permissions_by_guid(self, session: AsyncSession, sample_permission_data):
        """Test reading all permissions for a specific guid."""
        # Create multiple permissions for the same guid
        guid = sample_permission_data["guid"]
        permissions_data = [
            {**sample_permission_data, "target_guid": str(ULID()), "permission": 1},
            {**sample_permission_data, "target_guid": str(ULID()), "permission": 2},
            {**sample_permission_data, "target_guid": str(ULID()), "permission": 4},
        ]

        for perm_data in permissions_data:
            permission = Permission(**perm_data)
            session.add(permission)
        await session.commit()

        # Read all permissions for the guid
        result = await session.execute(
            select(Permission).where(Permission.guid == guid)
        )
        retrieved_permissions = result.scalars().all()

        assert len(retrieved_permissions) == 3
        permission_values = [p.permission for p in retrieved_permissions]
        assert set(permission_values) == {1, 2, 4}

    async def test_update_permission_value(self, session: AsyncSession, sample_permission_data):
        """Test updating Permission value."""
        # Create initial permission
        permission = Permission(**sample_permission_data)
        session.add(permission)
        await session.commit()

        # Update permission value
        new_permission_value = 8

        await session.execute(
            update(Permission)
            .where(
                (Permission.guid == sample_permission_data["guid"]) &
                (Permission.target_guid == sample_permission_data["target_guid"])
            )
            .values(permission=new_permission_value)
        )
        await session.commit()

        # Verify update
        result = await session.execute(
            select(Permission).where(
                (Permission.guid == sample_permission_data["guid"]) &
                (Permission.target_guid == sample_permission_data["target_guid"])
            )
        )
        updated_permission = result.scalar_one()

        assert updated_permission.permission == new_permission_value

    async def test_delete_permission(self, session: AsyncSession, sample_permission_data):
        """Test deleting Permission record."""
        # Create permission
        permission = Permission(**sample_permission_data)
        session.add(permission)
        await session.commit()

        # Delete permission
        await session.execute(
            delete(Permission).where(
                (Permission.guid == sample_permission_data["guid"]) &
                (Permission.target_guid == sample_permission_data["target_guid"])
            )
        )
        await session.commit()

        # Verify deletion
        result = await session.execute(
            select(Permission).where(
                (Permission.guid == sample_permission_data["guid"]) &
                (Permission.target_guid == sample_permission_data["target_guid"])
            )
        )
        deleted_permission = result.scalar_one_or_none()

        assert deleted_permission is None

    async def test_permission_composite_primary_key(self, session: AsyncSession):
        """Test that composite primary key (guid + target_guid) enforces uniqueness."""
        guid = str(ULID())
        target_guid = str(ULID())
        created_at = datetime.now(timezone.utc)

        # Create first permission
        permission1 = Permission(
            guid=guid,
            target_guid=target_guid,
            permission=1,
            created_at=created_at
        )
        session.add(permission1)
        await session.commit()

        # Expunge to avoid identity conflicts
        session.expunge(permission1)

        # Try to create second permission with same composite key
        try:
            permission2 = Permission(
                guid=guid,  # Same guid
                target_guid=target_guid,  # Same target_guid
                permission=2,  # Different permission value
                created_at=created_at
            )
            session.add(permission2)
            await session.commit()
            assert False, "Expected IntegrityError was not raised"
        except IntegrityError:
            await session.rollback()


class TestUpsertPermissionStmt:
    """Test suite for upsert_permission_stmt function."""

    async def test_upsert_new_permission(self, session: AsyncSession):
        """Test upserting a new Permission (INSERT behavior)."""
        guid = str(ULID())
        target_guid = str(ULID())
        permission = 4
        created_at = datetime.now(timezone.utc)

        # Execute upsert statement
        stmt = upsert_permission_stmt(
            guid=guid,
            target_guid=target_guid,
            permission=permission,
            created_at=created_at
        )
        await session.execute(stmt)
        await session.commit()

        # Verify the permission was created
        result = await session.execute(
            select(Permission).where(
                (Permission.guid == guid) &
                (Permission.target_guid == target_guid)
            )
        )
        created_permission = result.scalar_one()

        assert created_permission.guid == guid
        assert created_permission.target_guid == target_guid
        assert created_permission.permission == permission
        assert created_permission.created_at == created_at

    async def test_upsert_existing_permission(self, session: AsyncSession, sample_permission_data):
        """Test upserting an existing Permission (UPDATE behavior)."""
        # Create initial permission
        permission = Permission(**sample_permission_data)
        session.add(permission)
        await session.commit()

        # Upsert with same composite key but different permission value
        new_permission_value = 16
        new_created_at = datetime.now(timezone.utc) + timedelta(minutes=1)

        stmt = upsert_permission_stmt(
            guid=sample_permission_data["guid"],
            target_guid=sample_permission_data["target_guid"],
            permission=new_permission_value,
            created_at=new_created_at
        )
        await session.execute(stmt)
        await session.commit()

        # Clear session cache to force fresh read
        session.expunge_all()

        # Verify the permission was updated
        result = await session.execute(
            select(Permission).where(
                (Permission.guid == sample_permission_data["guid"]) &
                (Permission.target_guid == sample_permission_data["target_guid"])
            )
        )
        updated_permission = result.scalar_one()

        assert updated_permission.guid == sample_permission_data["guid"]
        assert updated_permission.target_guid == sample_permission_data["target_guid"]
        assert updated_permission.permission == new_permission_value  # Updated
        # created_at should remain original (not updated in upsert)
        assert updated_permission.created_at == sample_permission_data["created_at"]

    async def test_upsert_multiple_permissions_same_guid(self, session: AsyncSession):
        """Test upserting multiple permissions for the same guid."""
        guid = str(ULID())
        target_guids = [str(ULID()) for _ in range(3)]
        permissions = [1, 2, 4]
        created_at = datetime.now(timezone.utc)

        # Upsert multiple permissions
        for target_guid, perm in zip(target_guids, permissions):
            stmt = upsert_permission_stmt(
                guid=guid,
                target_guid=target_guid,
                permission=perm,
                created_at=created_at
            )
            await session.execute(stmt)
        await session.commit()

        # Verify all permissions were created
        result = await session.execute(
            select(Permission).where(Permission.guid == guid).order_by(Permission.permission)
        )
        created_permissions = result.scalars().all()

        assert len(created_permissions) == 3
        for i, perm in enumerate(created_permissions):
            assert perm.permission == permissions[i]
            assert perm.target_guid == target_guids[i]


class TestOAuthConstraintsAndEdgeCases:
    """Test suite for OAuth model constraints and edge cases."""

    async def test_oauth_state_primary_key_uniqueness(self, session: AsyncSession):
        """Test that oauth_state primary key enforces uniqueness."""
        oauth_state = "unique_state_test"
        created_at = generate_test_datetime()
        expires_at = generate_test_datetime(10)
        
        first_data = {
            "oauth_state": oauth_state,
            "issuer": "https://first.bsky.social",
            "guid": generate_ulid_string(),
            "pkce_verifier": "first_verifier",
            "secret_jwk_id": "first_jwk",
            "dpop_jwk": {"kty": "EC"},
            "destination": "https://first.example.com",
            "created_at": created_at,
            "expires_at": expires_at
        }
        
        second_data = {
            "oauth_state": oauth_state,  # Same state
            "issuer": "https://second.bsky.social",
            "guid": generate_ulid_string(),
            "pkce_verifier": "second_verifier",
            "secret_jwk_id": "second_jwk",
            "dpop_jwk": {"kty": "RSA"},
            "destination": "https://second.example.com",
            "created_at": created_at,
            "expires_at": expires_at
        }
        
        await assert_primary_key_uniqueness(session, OAuthRequest, first_data, second_data, "oauth_state")

    async def test_session_group_primary_key_uniqueness(self, session: AsyncSession):
        """Test that session_group primary key enforces uniqueness."""
        session_group = "unique_session_test"
        created_at = datetime.now(timezone.utc)

        # Create first session
        session1 = OAuthSession(
            session_group=session_group,
            issuer="https://first.bsky.social",
            guid=str(ULID()),
            access_token="first_access",
            refresh_token="first_refresh",
            secret_jwk_id="first_jwk",
            dpop_jwk={"kty": "EC"},
            created_at=created_at,
            access_token_expires_at=created_at + timedelta(hours=1),
            hard_expires_at=created_at + timedelta(days=30)
        )
        session.add(session1)
        await session.commit()
        session.expunge(session1)

        # Try to create second session with same session_group
        try:
            session2 = OAuthSession(
                session_group=session_group,  # Same session group
                issuer="https://second.bsky.social",
                guid=str(ULID()),
                access_token="second_access",
                refresh_token="second_refresh",
                secret_jwk_id="second_jwk",
                dpop_jwk={"kty": "RSA"},
                created_at=created_at,
                access_token_expires_at=created_at + timedelta(hours=1),
                hard_expires_at=created_at + timedelta(days=30)
            )
            session.add(session2)
            await session.commit()
            assert False, "Expected IntegrityError was not raised"
        except IntegrityError:
            await session.rollback()

    async def test_field_length_constraints(self, session: AsyncSession):
        """Test that string fields respect length constraints."""
        base_data = {
            "oauth_state": "test_state",
            "issuer": "https://test.bsky.social",
            "guid": generate_ulid_string(),
            "pkce_verifier": "test_verifier",
            "secret_jwk_id": "test_jwk",
            "dpop_jwk": {"kty": "EC"},
            "destination": "https://test.com",
            "created_at": generate_test_datetime(),
            "expires_at": generate_test_datetime(10)
        }
        
        # Test oauth_state length constraint (64 chars)
        await assert_field_length_constraint(session, OAuthRequest, base_data, "oauth_state", 64, "oauth_state")

    async def test_datetime_timezone_handling(self, session: AsyncSession, sample_oauth_request_data):
        """Test that datetime fields handle timezone-aware values correctly."""
        datetime_fields = ["created_at", "expires_at"]
        await assert_datetime_timezone_handling(
            session, OAuthRequest, sample_oauth_request_data, datetime_fields, "oauth_state"
        )

    async def test_json_field_edge_cases(self, session: AsyncSession, sample_oauth_request_data):
        """Test JSON field with various edge cases."""
        # Test empty dict
        sample_oauth_request_data["dpop_jwk"] = {}
        request1 = OAuthRequest(**sample_oauth_request_data)
        sample_oauth_request_data["oauth_state"] = "empty_json_test"
        session.add(request1)

        # Test nested JSON
        sample_oauth_request_data["dpop_jwk"] = {
            "kty": "EC",
            "nested": {"deep": {"value": 42}, "array": [1, 2, 3]}
        }
        sample_oauth_request_data["oauth_state"] = "nested_json_test"
        request2 = OAuthRequest(**sample_oauth_request_data)
        session.add(request2)

        await session.commit()

        # Verify both were stored correctly
        result = await session.execute(select(OAuthRequest))
        requests = result.scalars().all()
        assert len(requests) == 2