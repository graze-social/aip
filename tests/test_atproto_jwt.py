"""
Comprehensive unit tests for AT Protocol JWT utilities.

Tests cover DPoP JWT creation, key generation, and RFC compliance to ensure
secure and correct JWT handling for OAuth 2.0 flows.
"""

import json
import secrets
from datetime import datetime, timezone, timedelta

import pytest
from jwcrypto import jwt, jwk

from social.graze.aip.atproto.jwt import (
    generate_dpop_key,
    create_dpop_header,
    create_dpop_claims,
    create_dpop_jwt,
    create_dpop_header_and_claims,
    create_client_assertion_header,
    create_client_assertion_claims,
    create_client_assertion_jwt,
    create_client_assertion_header_and_claims,
)


class TestGenerateDpopKey:
    """Test DPoP key generation functionality."""

    def test_generate_dpop_key_returns_tuple(self):
        """Test that generate_dpop_key returns a tuple with JWK and dict."""
        result = generate_dpop_key()
        assert isinstance(result, tuple)
        assert len(result) == 2

        dpop_key, public_key_dict = result
        assert isinstance(dpop_key, jwk.JWK)
        assert isinstance(public_key_dict, dict)

    def test_generate_dpop_key_uses_correct_algorithm(self):
        """Test that generated key uses ECDSA P-256 (ES256)."""
        dpop_key, public_key_dict = generate_dpop_key()

        # Check JWK properties via export
        key_dict = dpop_key.export(as_dict=True)
        assert key_dict["kty"] == "EC"
        assert key_dict["crv"] == "P-256"
        assert key_dict["alg"] == "ES256"

        # Check public key dict properties
        assert public_key_dict["kty"] == "EC"
        assert public_key_dict["crv"] == "P-256"
        assert public_key_dict["alg"] == "ES256"

    def test_generate_dpop_key_has_unique_kid(self):
        """Test that each generated key has a unique key identifier."""
        key1, _ = generate_dpop_key()
        key2, _ = generate_dpop_key()

        key1_dict = key1.export(as_dict=True)
        key2_dict = key2.export(as_dict=True)

        assert key1_dict["kid"] != key2_dict["kid"]
        # Verify kid format is ULID
        assert len(key1_dict["kid"]) == 26  # ULID length
        assert len(key2_dict["kid"]) == 26

    def test_generate_dpop_key_public_private_consistency(self):
        """Test that public key dict matches JWK public portion."""
        dpop_key, public_key_dict = generate_dpop_key()

        # Export public key from JWK
        jwk_public_dict = dpop_key.export_public(as_dict=True)

        # Should match the returned public key dict
        assert public_key_dict == jwk_public_dict

    def test_generate_dpop_key_has_private_key(self):
        """Test that generated JWK includes private key material."""
        dpop_key, public_key_dict = generate_dpop_key()

        # Private key should be in JWK
        full_key_dict = dpop_key.export(private_key=True, as_dict=True)
        assert "d" in full_key_dict  # Private key parameter for EC

        # But not in public key dict
        assert "d" not in public_key_dict

    def test_generate_dpop_key_multiple_calls_unique(self):
        """Test that multiple calls generate different keys."""
        keys = [generate_dpop_key() for _ in range(5)]

        # All key IDs should be unique
        key_ids = [key[0].export(as_dict=True)["kid"] for key in keys]
        assert len(set(key_ids)) == 5

        # All public keys should be different
        public_keys = [json.dumps(key[1], sort_keys=True) for key in keys]
        assert len(set(public_keys)) == 5


class TestCreateDpopHeader:
    """Test DPoP JWT header creation."""

    def test_create_dpop_header_structure(self):
        """Test that DPoP header has correct structure."""
        _, public_key_dict = generate_dpop_key()
        header = create_dpop_header(public_key_dict)

        assert isinstance(header, dict)
        assert len(header) == 3
        assert "alg" in header
        assert "jwk" in header
        assert "typ" in header

    def test_create_dpop_header_values(self):
        """Test that DPoP header has correct values."""
        _, public_key_dict = generate_dpop_key()
        header = create_dpop_header(public_key_dict)

        assert header["alg"] == "ES256"
        assert header["typ"] == "dpop+jwt"
        assert header["jwk"] == public_key_dict

    def test_create_dpop_header_embeds_public_key(self):
        """Test that header properly embeds the public key."""
        _, public_key_dict = generate_dpop_key()
        header = create_dpop_header(public_key_dict)

        embedded_key = header["jwk"]
        assert embedded_key["kty"] == "EC"
        assert embedded_key["crv"] == "P-256"
        assert embedded_key["alg"] == "ES256"
        assert "kid" in embedded_key
        assert "x" in embedded_key  # EC public key x coordinate
        assert "y" in embedded_key  # EC public key y coordinate

        # Should not contain private key material
        assert "d" not in embedded_key

    def test_create_dpop_header_immutable_input(self):
        """Test that function doesn't modify input public key dict."""
        _, public_key_dict = generate_dpop_key()
        original_dict = public_key_dict.copy()

        header = create_dpop_header(public_key_dict)

        # Original dict should be unchanged
        assert public_key_dict == original_dict
        # Header should reference the same dict
        assert header["jwk"] is public_key_dict


class TestCreateDpopClaims:
    """Test DPoP JWT claims creation."""

    def test_create_dpop_claims_basic_structure(self):
        """Test basic DPoP claims structure."""
        now = datetime.now(timezone.utc)
        claims = create_dpop_claims("POST", "https://example.com/token", now)

        assert isinstance(claims, dict)
        assert "htm" in claims
        assert "htu" in claims
        assert "iat" in claims
        assert "exp" in claims

    def test_create_dpop_claims_http_method_uppercase(self):
        """Test that HTTP method is converted to uppercase."""
        now = datetime.now(timezone.utc)

        claims_lower = create_dpop_claims("post", "https://example.com/token", now)
        claims_upper = create_dpop_claims("POST", "https://example.com/token", now)
        claims_mixed = create_dpop_claims("PoSt", "https://example.com/token", now)

        assert claims_lower["htm"] == "POST"
        assert claims_upper["htm"] == "POST"
        assert claims_mixed["htm"] == "POST"

    def test_create_dpop_claims_timestamps(self):
        """Test that timestamps are correct integers."""
        now = datetime.now(timezone.utc)
        expires_in = 60

        claims = create_dpop_claims(
            "POST", "https://example.com/token", now, expires_in
        )

        assert isinstance(claims["iat"], int)
        assert isinstance(claims["exp"], int)
        assert claims["iat"] == int(now.timestamp())
        assert claims["exp"] == int(now.timestamp()) + expires_in

    def test_create_dpop_claims_default_issued_at(self):
        """Test that default issued_at is current time."""
        before = datetime.now(timezone.utc).replace(microsecond=0)
        claims = create_dpop_claims("POST", "https://example.com/token")
        after = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=1)

        iat_time = datetime.fromtimestamp(claims["iat"], tz=timezone.utc)
        assert before <= iat_time <= after

    def test_create_dpop_claims_default_expires_in(self):
        """Test that default expires_in is 30 seconds."""
        now = datetime.now(timezone.utc)
        claims = create_dpop_claims("POST", "https://example.com/token", now)

        expected_exp = int(now.timestamp()) + 30
        assert claims["exp"] == expected_exp

    def test_create_dpop_claims_custom_expires_in(self):
        """Test custom expires_in values."""
        now = datetime.now(timezone.utc)

        for expires_in in [10, 60, 300, 3600]:
            claims = create_dpop_claims(
                "POST", "https://example.com/token", now, expires_in
            )
            expected_exp = int(now.timestamp()) + expires_in
            assert claims["exp"] == expected_exp

    def test_create_dpop_claims_with_nonce(self):
        """Test claims with nonce parameter."""
        now = datetime.now(timezone.utc)
        nonce = "test-nonce-value"

        claims = create_dpop_claims(
            "POST", "https://example.com/token", now, nonce=nonce
        )

        assert "nonce" in claims
        assert claims["nonce"] == nonce

    def test_create_dpop_claims_without_nonce(self):
        """Test claims without nonce parameter."""
        now = datetime.now(timezone.utc)

        claims = create_dpop_claims("POST", "https://example.com/token", now)

        assert "nonce" not in claims

    def test_create_dpop_claims_uri_handling(self):
        """Test that URI is stored correctly."""
        now = datetime.now(timezone.utc)
        test_uris = [
            "https://example.com/token",
            "https://auth.bsky.social/oauth/token",
            "https://pds.example.com/oauth/pushed_authorization_request",
        ]

        for uri in test_uris:
            claims = create_dpop_claims("POST", uri, now)
            assert claims["htu"] == uri

    def test_create_dpop_claims_various_methods(self):
        """Test various HTTP methods."""
        now = datetime.now(timezone.utc)
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]

        for method in methods:
            claims = create_dpop_claims(method, "https://example.com/api", now)
            assert claims["htm"] == method

    def test_create_dpop_claims_with_issuer(self):
        """Test claims with issuer parameter."""
        now = datetime.now(timezone.utc)
        issuer = "https://example.com/issuer"

        claims = create_dpop_claims(
            "POST", "https://example.com/token", now, issuer=issuer
        )

        assert "iss" in claims
        assert claims["iss"] == issuer

    def test_create_dpop_claims_without_issuer(self):
        """Test claims without issuer parameter."""
        now = datetime.now(timezone.utc)

        claims = create_dpop_claims("POST", "https://example.com/token", now)

        assert "iss" not in claims

    def test_create_dpop_claims_with_all_optional_parameters(self):
        """Test claims with all optional parameters including issuer."""
        now = datetime.now(timezone.utc)
        nonce = "test-nonce"
        issuer = "https://auth.example.com"
        expires_in = 120

        claims = create_dpop_claims(
            "PUT", "https://api.example.com/resource", now, expires_in, nonce, issuer
        )

        assert claims["htm"] == "PUT"
        assert claims["htu"] == "https://api.example.com/resource"
        assert claims["iat"] == int(now.timestamp())
        assert claims["exp"] == int(now.timestamp()) + expires_in
        assert claims["nonce"] == nonce
        assert claims["iss"] == issuer

    def test_create_dpop_claims_issuer_empty_string(self):
        """Test behavior with empty string issuer."""
        now = datetime.now(timezone.utc)

        claims = create_dpop_claims("POST", "https://example.com/token", now, issuer="")

        assert "iss" in claims
        assert claims["iss"] == ""


class TestCreateDpopJwt:
    """Test complete DPoP JWT creation."""

    def test_create_dpop_jwt_returns_string(self):
        """Test that create_dpop_jwt returns a JWT string."""
        dpop_key, _ = generate_dpop_key()
        jwt_string = create_dpop_jwt(dpop_key, "POST", "https://example.com/token")

        assert isinstance(jwt_string, str)
        # JWT should have 3 parts separated by dots
        parts = jwt_string.split(".")
        assert len(parts) == 3

    def test_create_dpop_jwt_valid_structure(self):
        """Test that created JWT has valid structure and can be parsed."""
        dpop_key, public_key_dict = generate_dpop_key()
        jwt_string = create_dpop_jwt(dpop_key, "POST", "https://example.com/token")

        # Parse JWT
        parsed_jwt = jwt.JWT(jwt=jwt_string, key=dpop_key)

        # Verify header
        header = json.loads(parsed_jwt.header)
        assert header["alg"] == "ES256"
        assert header["typ"] == "dpop+jwt"
        assert header["jwk"] == public_key_dict

        # Verify claims
        claims = json.loads(parsed_jwt.claims)
        assert claims["htm"] == "POST"
        assert claims["htu"] == "https://example.com/token"
        assert "iat" in claims
        assert "exp" in claims
        assert "jti" in claims

    def test_create_dpop_jwt_signature_verification(self):
        """Test that JWT signature can be verified with the key."""
        dpop_key, _ = generate_dpop_key()
        jwt_string = create_dpop_jwt(dpop_key, "POST", "https://example.com/token")

        # Verification should succeed with the correct key
        try:
            jwt.JWT(jwt=jwt_string, key=dpop_key)
        except Exception as e:
            pytest.fail(f"JWT verification failed: {e}")

    def test_create_dpop_jwt_signature_verification_fails_wrong_key(self):
        """Test that JWT signature verification fails with wrong key."""
        dpop_key, _ = generate_dpop_key()
        wrong_key, _ = generate_dpop_key()
        jwt_string = create_dpop_jwt(dpop_key, "POST", "https://example.com/token")

        # Verification should fail with wrong key
        with pytest.raises(Exception):
            jwt.JWT(jwt=jwt_string, key=wrong_key)

    def test_create_dpop_jwt_unique_jti(self):
        """Test that each JWT has a unique jti (JWT ID)."""
        dpop_key, _ = generate_dpop_key()

        jwt_strings = [
            create_dpop_jwt(dpop_key, "POST", "https://example.com/token")
            for _ in range(5)
        ]

        jtis = []
        for jwt_string in jwt_strings:
            parsed_jwt = jwt.JWT(jwt=jwt_string, key=dpop_key)
            claims = json.loads(parsed_jwt.claims)
            jtis.append(claims["jti"])

        # All JTIs should be unique
        assert len(set(jtis)) == 5

        # JTIs should be URL-safe strings
        for jti in jtis:
            assert isinstance(jti, str)
            assert len(jti) > 0

    def test_create_dpop_jwt_auto_extract_public_key(self):
        """Test that public key is auto-extracted when not provided."""
        dpop_key, expected_public_key = generate_dpop_key()

        # Don't provide public_key_dict parameter
        jwt_string = create_dpop_jwt(dpop_key, "POST", "https://example.com/token")

        parsed_jwt = jwt.JWT(jwt=jwt_string, key=dpop_key)
        header = json.loads(parsed_jwt.header)

        assert header["jwk"] == expected_public_key

    def test_create_dpop_jwt_custom_parameters(self):
        """Test JWT creation with custom parameters."""
        dpop_key, public_key_dict = generate_dpop_key()
        # Use a recent time to avoid expiration issues
        issued_at = datetime.now(timezone.utc) - timedelta(seconds=5)
        expires_in = 120
        nonce = "custom-nonce"

        jwt_string = create_dpop_jwt(
            dpop_key,
            "GET",
            "https://custom.example.com/api",
            public_key_dict,
            issued_at,
            expires_in,
            nonce,
        )

        # Parse without expiration validation for this test
        parsed_jwt = jwt.JWT()
        parsed_jwt.deserialize(jwt_string, key=dpop_key)

        header = json.loads(parsed_jwt.header)
        claims = json.loads(parsed_jwt.claims)

        assert header["jwk"] == public_key_dict
        assert claims["htm"] == "GET"
        assert claims["htu"] == "https://custom.example.com/api"
        assert claims["iat"] == int(issued_at.timestamp())
        assert claims["exp"] == int(issued_at.timestamp()) + expires_in
        assert claims["nonce"] == nonce

    def test_create_dpop_jwt_expiration_validation(self):
        """Test that JWT expiration is reasonable for current time."""
        dpop_key, _ = generate_dpop_key()
        before = datetime.now(timezone.utc).replace(microsecond=0)
        jwt_string = create_dpop_jwt(dpop_key, "POST", "https://example.com/token")
        after = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=1)

        parsed_jwt = jwt.JWT(jwt=jwt_string, key=dpop_key)
        claims = json.loads(parsed_jwt.claims)

        iat_time = datetime.fromtimestamp(claims["iat"], tz=timezone.utc)
        exp_time = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)

        # iat should be between before and after
        assert before <= iat_time <= after

        # exp should be 30 seconds after iat (default)
        expected_exp = iat_time + timedelta(seconds=30)
        assert exp_time == expected_exp

    def test_create_dpop_jwt_with_issuer(self):
        """Test JWT creation with issuer parameter."""
        dpop_key, _ = generate_dpop_key()
        issuer = "https://auth.example.com"

        jwt_string = create_dpop_jwt(
            dpop_key, "POST", "https://example.com/token", issuer=issuer
        )

        parsed_jwt = jwt.JWT(jwt=jwt_string, key=dpop_key)
        claims = json.loads(parsed_jwt.claims)

        assert "iss" in claims
        assert claims["iss"] == issuer

    def test_create_dpop_jwt_without_issuer(self):
        """Test JWT creation without issuer parameter."""
        dpop_key, _ = generate_dpop_key()

        jwt_string = create_dpop_jwt(dpop_key, "POST", "https://example.com/token")

        parsed_jwt = jwt.JWT(jwt=jwt_string, key=dpop_key)
        claims = json.loads(parsed_jwt.claims)

        assert "iss" not in claims

    def test_create_dpop_jwt_with_all_parameters_including_issuer(self):
        """Test JWT creation with all parameters including issuer."""
        dpop_key, public_key_dict = generate_dpop_key()
        issued_at = datetime.now(timezone.utc) - timedelta(seconds=5)
        expires_in = 120
        nonce = "test-nonce"
        issuer = "https://auth.example.com"

        jwt_string = create_dpop_jwt(
            dpop_key,
            "DELETE",
            "https://api.example.com/resource",
            public_key_dict,
            issued_at,
            expires_in,
            nonce,
            issuer,
        )

        # Parse without expiration validation for this test
        parsed_jwt = jwt.JWT()
        parsed_jwt.deserialize(jwt_string, key=dpop_key)

        header = json.loads(parsed_jwt.header)
        claims = json.loads(parsed_jwt.claims)

        assert header["jwk"] == public_key_dict
        assert claims["htm"] == "DELETE"
        assert claims["htu"] == "https://api.example.com/resource"
        assert claims["iat"] == int(issued_at.timestamp())
        assert claims["exp"] == int(issued_at.timestamp()) + expires_in
        assert claims["nonce"] == nonce
        assert claims["iss"] == issuer
        assert "jti" in claims


class TestCreateDpopHeaderAndClaims:
    """Test separate header and claims creation for middleware."""

    def test_create_dpop_header_and_claims_returns_tuple(self):
        """Test that function returns tuple of header and claims."""
        _, public_key_dict = generate_dpop_key()
        now = datetime.now(timezone.utc)

        result = create_dpop_header_and_claims(
            "POST", "https://example.com/token", public_key_dict, now
        )

        assert isinstance(result, tuple)
        assert len(result) == 2

        header, claims = result
        assert isinstance(header, dict)
        assert isinstance(claims, dict)

    def test_create_dpop_header_and_claims_consistency(self):
        """Test that components match individual function outputs."""
        _, public_key_dict = generate_dpop_key()
        now = datetime.now(timezone.utc)
        expires_in = 60
        nonce = "test-nonce"

        # Get components separately
        expected_header = create_dpop_header(public_key_dict)
        expected_claims = create_dpop_claims(
            "POST", "https://example.com/token", now, expires_in, nonce
        )

        # Get components together
        header, claims = create_dpop_header_and_claims(
            "POST", "https://example.com/token", public_key_dict, now, expires_in, nonce
        )

        assert header == expected_header
        assert claims == expected_claims

    def test_create_dpop_header_and_claims_middleware_usage(self):
        """Test usage pattern for middleware (components used separately)."""
        dpop_key, public_key_dict = generate_dpop_key()
        now = datetime.now(timezone.utc)

        header, claims = create_dpop_header_and_claims(
            "POST", "https://example.com/token", public_key_dict, now
        )

        # Middleware would typically add jti to claims
        claims["jti"] = secrets.token_urlsafe(32)

        # Then create JWT manually
        test_jwt = jwt.JWT(header=header, claims=claims)
        test_jwt.make_signed_token(dpop_key)

        # Should be valid structure and signable
        assert test_jwt.header is not None
        assert test_jwt.claims is not None
        assert test_jwt.token is not None

    def test_create_dpop_header_and_claims_all_parameters(self):
        """Test with all optional parameters."""
        _, public_key_dict = generate_dpop_key()
        now = datetime.now(timezone.utc)

        header, claims = create_dpop_header_and_claims(
            "PUT",
            "https://test.example.com/api",
            public_key_dict,
            now,
            expires_in_seconds=300,
            nonce="middleware-nonce",
        )

        # Verify header
        assert header["alg"] == "ES256"
        assert header["typ"] == "dpop+jwt"
        assert header["jwk"] == public_key_dict

        # Verify claims
        assert claims["htm"] == "PUT"
        assert claims["htu"] == "https://test.example.com/api"
        assert claims["iat"] == int(now.timestamp())
        assert claims["exp"] == int(now.timestamp()) + 300
        assert claims["nonce"] == "middleware-nonce"

    def test_create_dpop_header_and_claims_with_issuer(self):
        """Test with issuer parameter."""
        _, public_key_dict = generate_dpop_key()
        now = datetime.now(timezone.utc)
        issuer = "https://auth.example.com"

        header, claims = create_dpop_header_and_claims(
            "POST", "https://example.com/token", public_key_dict, now, issuer=issuer
        )

        # Verify header
        assert header["alg"] == "ES256"
        assert header["typ"] == "dpop+jwt"
        assert header["jwk"] == public_key_dict

        # Verify claims
        assert claims["htm"] == "POST"
        assert claims["htu"] == "https://example.com/token"
        assert claims["iat"] == int(now.timestamp())
        assert claims["exp"] == int(now.timestamp()) + 30
        assert claims["iss"] == issuer

    def test_create_dpop_header_and_claims_all_parameters_including_issuer(self):
        """Test with all optional parameters including issuer."""
        _, public_key_dict = generate_dpop_key()
        now = datetime.now(timezone.utc)
        issuer = "https://middleware.example.com"

        header, claims = create_dpop_header_and_claims(
            "PATCH",
            "https://api.example.com/update",
            public_key_dict,
            now,
            expires_in_seconds=180,
            nonce="middleware-nonce-123",
            issuer=issuer,
        )

        # Verify header
        assert header["alg"] == "ES256"
        assert header["typ"] == "dpop+jwt"
        assert header["jwk"] == public_key_dict

        # Verify claims
        assert claims["htm"] == "PATCH"
        assert claims["htu"] == "https://api.example.com/update"
        assert claims["iat"] == int(now.timestamp())
        assert claims["exp"] == int(now.timestamp()) + 180
        assert claims["nonce"] == "middleware-nonce-123"
        assert claims["iss"] == issuer


class TestCreateClientAssertionHeader:
    """Test client assertion JWT header creation."""

    def test_create_client_assertion_header_structure(self):
        """Test that client assertion header has correct structure."""
        key_id = "test-key-123"
        header = create_client_assertion_header(key_id)

        assert isinstance(header, dict)
        assert len(header) == 2
        assert "alg" in header
        assert "kid" in header

    def test_create_client_assertion_header_values(self):
        """Test that client assertion header has correct values."""
        key_id = "signing-key-456"
        header = create_client_assertion_header(key_id)

        assert header["alg"] == "ES256"
        assert header["kid"] == key_id

    def test_create_client_assertion_header_various_key_ids(self):
        """Test header creation with various key ID formats."""
        key_ids = [
            "simple-key",
            "01234567-89ab-cdef-0123-456789abcdef",
            "key_with_underscores",
            "key-with-dashes",
            "01HGW2E9Q8X9J5K7M3N4P6R8S2T4V6W8",  # ULID format
        ]

        for key_id in key_ids:
            header = create_client_assertion_header(key_id)
            assert header["alg"] == "ES256"
            assert header["kid"] == key_id

    def test_create_client_assertion_header_empty_key_id(self):
        """Test behavior with empty key ID."""
        header = create_client_assertion_header("")

        assert header["alg"] == "ES256"
        assert header["kid"] == ""


class TestCreateClientAssertionClaims:
    """Test client assertion JWT claims creation."""

    def test_create_client_assertion_claims_basic_structure(self):
        """Test basic client assertion claims structure."""
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        now = datetime.now(timezone.utc)

        claims = create_client_assertion_claims(client_id, audience, now)

        assert isinstance(claims, dict)
        assert "iss" in claims
        assert "sub" in claims
        assert "aud" in claims
        assert "iat" in claims

    def test_create_client_assertion_claims_rfc7523_compliance(self):
        """Test that claims comply with RFC 7523 requirements."""
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        now = datetime.now(timezone.utc)

        claims = create_client_assertion_claims(client_id, audience, now)

        # RFC 7523: iss and sub MUST be the client_id
        assert claims["iss"] == client_id
        assert claims["sub"] == client_id
        # aud MUST be the authorization server
        assert claims["aud"] == audience
        # iat MUST be present
        assert claims["iat"] == int(now.timestamp())

    def test_create_client_assertion_claims_timestamps(self):
        """Test that timestamps are correct integers."""
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        now = datetime.now(timezone.utc)

        claims = create_client_assertion_claims(client_id, audience, now)

        assert isinstance(claims["iat"], int)
        assert claims["iat"] == int(now.timestamp())

    def test_create_client_assertion_claims_default_issued_at(self):
        """Test that default issued_at is current time."""
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"

        before = datetime.now(timezone.utc).replace(microsecond=0)
        claims = create_client_assertion_claims(client_id, audience)
        after = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=1)

        iat_time = datetime.fromtimestamp(claims["iat"], tz=timezone.utc)
        assert before <= iat_time <= after

    def test_create_client_assertion_claims_without_jti(self):
        """Test claims without JTI (default behavior)."""
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        now = datetime.now(timezone.utc)

        claims = create_client_assertion_claims(client_id, audience, now)

        assert "jti" not in claims

    def test_create_client_assertion_claims_with_jti(self):
        """Test claims with JTI included."""
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        now = datetime.now(timezone.utc)

        claims = create_client_assertion_claims(
            client_id, audience, now, include_jti=True
        )

        assert "jti" in claims
        assert isinstance(claims["jti"], str)
        assert len(claims["jti"]) > 0

    def test_create_client_assertion_claims_jti_uniqueness(self):
        """Test that JTI values are unique across calls."""
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        now = datetime.now(timezone.utc)

        jtis = []
        for _ in range(10):
            claims = create_client_assertion_claims(
                client_id, audience, now, include_jti=True
            )
            jtis.append(claims["jti"])

        # All JTIs should be unique
        assert len(set(jtis)) == 10

    def test_create_client_assertion_claims_various_client_ids(self):
        """Test claims with various client ID formats."""
        client_ids = [
            "https://client.example.com/client-metadata.json",
            "https://auth.service.com/oauth/client/metadata",
            "https://app.bsky.social/client.json",
        ]
        audience = "https://auth.provider.com"
        now = datetime.now(timezone.utc)

        for client_id in client_ids:
            claims = create_client_assertion_claims(client_id, audience, now)
            assert claims["iss"] == client_id
            assert claims["sub"] == client_id

    def test_create_client_assertion_claims_various_audiences(self):
        """Test claims with various audience formats."""
        client_id = "https://client.example.com/metadata.json"
        audiences = [
            "https://auth.bsky.social",
            "https://authorization.server.com",
            "https://oauth.provider.net/token",
        ]
        now = datetime.now(timezone.utc)

        for audience in audiences:
            claims = create_client_assertion_claims(client_id, audience, now)
            assert claims["aud"] == audience


class TestCreateClientAssertionJwt:
    """Test complete client assertion JWT creation."""

    def test_create_client_assertion_jwt_returns_string(self):
        """Test that create_client_assertion_jwt returns a JWT string."""
        signing_key, _ = generate_dpop_key()  # Reuse key generation
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        key_id = "test-key-123"

        jwt_string = create_client_assertion_jwt(
            signing_key, client_id, audience, key_id
        )

        assert isinstance(jwt_string, str)
        # JWT should have 3 parts separated by dots
        parts = jwt_string.split(".")
        assert len(parts) == 3

    def test_create_client_assertion_jwt_valid_structure(self):
        """Test that created JWT has valid structure and can be parsed."""
        signing_key, _ = generate_dpop_key()
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        key_id = "test-key-123"

        jwt_string = create_client_assertion_jwt(
            signing_key, client_id, audience, key_id
        )

        # Parse JWT
        parsed_jwt = jwt.JWT(jwt=jwt_string, key=signing_key)

        # Verify header
        header = json.loads(parsed_jwt.header)
        assert header["alg"] == "ES256"
        assert header["kid"] == key_id

        # Verify claims
        claims = json.loads(parsed_jwt.claims)
        assert claims["iss"] == client_id
        assert claims["sub"] == client_id
        assert claims["aud"] == audience
        assert "iat" in claims
        assert "jti" in claims  # Default includes JTI

    def test_create_client_assertion_jwt_signature_verification(self):
        """Test that JWT signature can be verified with the key."""
        signing_key, _ = generate_dpop_key()
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        key_id = "test-key-123"

        jwt_string = create_client_assertion_jwt(
            signing_key, client_id, audience, key_id
        )

        # Verification should succeed with the correct key
        try:
            jwt.JWT(jwt=jwt_string, key=signing_key)
        except Exception as e:
            pytest.fail(f"JWT verification failed: {e}")

    def test_create_client_assertion_jwt_signature_verification_fails_wrong_key(self):
        """Test that JWT signature verification fails with wrong key."""
        signing_key, _ = generate_dpop_key()
        wrong_key, _ = generate_dpop_key()
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        key_id = "test-key-123"

        jwt_string = create_client_assertion_jwt(
            signing_key, client_id, audience, key_id
        )

        # Verification should fail with wrong key
        with pytest.raises(Exception):
            jwt.JWT(jwt=jwt_string, key=wrong_key)

    def test_create_client_assertion_jwt_with_jti(self):
        """Test JWT creation with JTI included (default behavior)."""
        signing_key, _ = generate_dpop_key()
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        key_id = "test-key-123"

        jwt_string = create_client_assertion_jwt(
            signing_key, client_id, audience, key_id
        )

        parsed_jwt = jwt.JWT(jwt=jwt_string, key=signing_key)
        claims = json.loads(parsed_jwt.claims)

        assert "jti" in claims
        assert isinstance(claims["jti"], str)
        assert len(claims["jti"]) > 0

    def test_create_client_assertion_jwt_without_jti(self):
        """Test JWT creation without JTI."""
        signing_key, _ = generate_dpop_key()
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        key_id = "test-key-123"

        jwt_string = create_client_assertion_jwt(
            signing_key, client_id, audience, key_id, include_jti=False
        )

        parsed_jwt = jwt.JWT(jwt=jwt_string, key=signing_key)
        claims = json.loads(parsed_jwt.claims)

        assert "jti" not in claims

    def test_create_client_assertion_jwt_custom_issued_at(self):
        """Test JWT creation with custom issued_at time."""
        signing_key, _ = generate_dpop_key()
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        key_id = "test-key-123"
        issued_at = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        jwt_string = create_client_assertion_jwt(
            signing_key, client_id, audience, key_id, issued_at=issued_at
        )

        parsed_jwt = jwt.JWT(jwt=jwt_string, key=signing_key)
        claims = json.loads(parsed_jwt.claims)

        assert claims["iat"] == int(issued_at.timestamp())

    def test_create_client_assertion_jwt_unique_jtis(self):
        """Test that multiple JWTs have unique JTIs."""
        signing_key, _ = generate_dpop_key()
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        key_id = "test-key-123"

        jwt_strings = [
            create_client_assertion_jwt(signing_key, client_id, audience, key_id)
            for _ in range(5)
        ]

        jtis = []
        for jwt_string in jwt_strings:
            parsed_jwt = jwt.JWT(jwt=jwt_string, key=signing_key)
            claims = json.loads(parsed_jwt.claims)
            jtis.append(claims["jti"])

        # All JTIs should be unique
        assert len(set(jtis)) == 5


class TestCreateClientAssertionHeaderAndClaims:
    """Test separate client assertion header and claims creation for middleware."""

    def test_create_client_assertion_header_and_claims_returns_tuple(self):
        """Test that function returns tuple of header and claims."""
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        key_id = "test-key-123"
        now = datetime.now(timezone.utc)

        result = create_client_assertion_header_and_claims(
            client_id, audience, key_id, now
        )

        assert isinstance(result, tuple)
        assert len(result) == 2

        header, claims = result
        assert isinstance(header, dict)
        assert isinstance(claims, dict)

    def test_create_client_assertion_header_and_claims_consistency(self):
        """Test that components match individual function outputs."""
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        key_id = "test-key-123"
        now = datetime.now(timezone.utc)

        # Get components separately
        expected_header = create_client_assertion_header(key_id)
        expected_claims = create_client_assertion_claims(client_id, audience, now)

        # Get components together
        header, claims = create_client_assertion_header_and_claims(
            client_id, audience, key_id, now
        )

        assert header == expected_header
        assert claims == expected_claims

    def test_create_client_assertion_header_and_claims_middleware_usage(self):
        """Test usage pattern for middleware (components used separately)."""
        signing_key, _ = generate_dpop_key()
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        key_id = "test-key-123"
        now = datetime.now(timezone.utc)

        header, claims = create_client_assertion_header_and_claims(
            client_id, audience, key_id, now
        )

        # Middleware would typically add jti to claims
        claims["jti"] = secrets.token_urlsafe(32)

        # Then create JWT manually
        test_jwt = jwt.JWT(header=header, claims=claims)
        test_jwt.make_signed_token(signing_key)

        # Should be valid structure and signable
        assert test_jwt.header is not None
        assert test_jwt.claims is not None
        assert test_jwt.token is not None

    def test_create_client_assertion_header_and_claims_with_jti(self):
        """Test with JTI parameter."""
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        key_id = "test-key-123"
        now = datetime.now(timezone.utc)

        header, claims = create_client_assertion_header_and_claims(
            client_id, audience, key_id, now, include_jti=True
        )

        # Verify header
        assert header["alg"] == "ES256"
        assert header["kid"] == key_id

        # Verify claims
        assert claims["iss"] == client_id
        assert claims["sub"] == client_id
        assert claims["aud"] == audience
        assert claims["iat"] == int(now.timestamp())
        assert "jti" in claims

    def test_create_client_assertion_header_and_claims_without_jti(self):
        """Test without JTI parameter (default behavior)."""
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        key_id = "test-key-123"
        now = datetime.now(timezone.utc)

        header, claims = create_client_assertion_header_and_claims(
            client_id, audience, key_id, now
        )

        # Verify header
        assert header["alg"] == "ES256"
        assert header["kid"] == key_id

        # Verify claims
        assert claims["iss"] == client_id
        assert claims["sub"] == client_id
        assert claims["aud"] == audience
        assert claims["iat"] == int(now.timestamp())
        assert "jti" not in claims


class TestJwtIntegration:
    """Test integration between JWT functions."""

    def test_full_dpop_flow(self):
        """Test complete DPoP JWT creation flow."""
        # Step 1: Generate key pair
        dpop_key, public_key_dict = generate_dpop_key()

        # Step 2: Create JWT
        jwt_string = create_dpop_jwt(
            dpop_key, "POST", "https://auth.bsky.social/oauth/token"
        )

        # Step 3: Verify JWT is valid and contains expected data
        parsed_jwt = jwt.JWT(jwt=jwt_string, key=dpop_key)
        header = json.loads(parsed_jwt.header)
        claims = json.loads(parsed_jwt.claims)

        # Verify header compliance
        assert header["alg"] == "ES256"
        assert header["typ"] == "dpop+jwt"
        assert header["jwk"] == public_key_dict

        # Verify claims compliance
        assert claims["htm"] == "POST"
        assert claims["htu"] == "https://auth.bsky.social/oauth/token"
        assert isinstance(claims["iat"], int)
        assert isinstance(claims["exp"], int)
        assert isinstance(claims["jti"], str)
        assert len(claims["jti"]) > 0

    def test_full_dpop_flow_with_issuer(self):
        """Test complete DPoP JWT creation flow with issuer."""
        # Step 1: Generate key pair
        dpop_key, public_key_dict = generate_dpop_key()
        issuer = "https://aip.auth.service"

        # Step 2: Create JWT with issuer
        jwt_string = create_dpop_jwt(
            dpop_key, "POST", "https://auth.bsky.social/oauth/token", issuer=issuer
        )

        # Step 3: Verify JWT is valid and contains expected data
        parsed_jwt = jwt.JWT(jwt=jwt_string, key=dpop_key)
        header = json.loads(parsed_jwt.header)
        claims = json.loads(parsed_jwt.claims)

        # Verify header compliance
        assert header["alg"] == "ES256"
        assert header["typ"] == "dpop+jwt"
        assert header["jwk"] == public_key_dict

        # Verify claims compliance including issuer
        assert claims["htm"] == "POST"
        assert claims["htu"] == "https://auth.bsky.social/oauth/token"
        assert claims["iss"] == issuer
        assert isinstance(claims["iat"], int)
        assert isinstance(claims["exp"], int)
        assert isinstance(claims["jti"], str)
        assert len(claims["jti"]) > 0

    def test_middleware_integration_pattern(self):
        """Test the middleware usage pattern with separate components."""
        # Simulate middleware workflow
        dpop_key, public_key_dict = generate_dpop_key()

        # Middleware gets header and claims separately
        header, claims = create_dpop_header_and_claims(
            "POST", "https://example.com/par", public_key_dict
        )

        # Middleware adds unique jti
        claims["jti"] = secrets.token_urlsafe(32)

        # Middleware creates and signs JWT
        middleware_jwt = jwt.JWT(header=header, claims=claims)
        middleware_jwt.make_signed_token(dpop_key)
        jwt_string = middleware_jwt.serialize()

        # Verify the result
        verified_jwt = jwt.JWT(jwt=jwt_string, key=dpop_key)
        verified_header = json.loads(verified_jwt.header)
        verified_claims = json.loads(verified_jwt.claims)

        assert verified_header == header
        assert verified_claims == claims

    def test_middleware_integration_pattern_with_issuer(self):
        """Test the middleware usage pattern with issuer."""
        # Simulate middleware workflow with issuer
        dpop_key, public_key_dict = generate_dpop_key()
        issuer = "https://middleware.auth.service"

        # Middleware gets header and claims separately with issuer
        header, claims = create_dpop_header_and_claims(
            "POST", "https://example.com/par", public_key_dict, issuer=issuer
        )

        # Verify issuer is in claims
        assert claims["iss"] == issuer

        # Middleware adds unique jti
        claims["jti"] = secrets.token_urlsafe(32)

        # Middleware creates and signs JWT
        middleware_jwt = jwt.JWT(header=header, claims=claims)
        middleware_jwt.make_signed_token(dpop_key)
        jwt_string = middleware_jwt.serialize()

        # Verify the result
        verified_jwt = jwt.JWT(jwt=jwt_string, key=dpop_key)
        verified_header = json.loads(verified_jwt.header)
        verified_claims = json.loads(verified_jwt.claims)

        assert verified_header == header
        assert verified_claims == claims
        assert verified_claims["iss"] == issuer

    def test_full_client_assertion_flow(self):
        """Test complete client assertion JWT creation flow."""
        # Step 1: Generate key pair
        signing_key, _ = generate_dpop_key()
        client_id = "https://aip.example.com/client-metadata.json"
        audience = "https://auth.bsky.social"
        key_id = "signing-key-123"

        # Step 2: Create client assertion JWT
        jwt_string = create_client_assertion_jwt(
            signing_key, client_id, audience, key_id
        )

        # Step 3: Verify JWT is valid and contains expected data
        parsed_jwt = jwt.JWT(jwt=jwt_string, key=signing_key)
        header = json.loads(parsed_jwt.header)
        claims = json.loads(parsed_jwt.claims)

        # Verify header compliance
        assert header["alg"] == "ES256"
        assert header["kid"] == key_id

        # Verify claims compliance (RFC 7523)
        assert claims["iss"] == client_id
        assert claims["sub"] == client_id
        assert claims["aud"] == audience
        assert isinstance(claims["iat"], int)
        assert isinstance(claims["jti"], str)
        assert len(claims["jti"]) > 0

    def test_client_assertion_middleware_integration_pattern(self):
        """Test the middleware usage pattern for client assertions."""
        # Simulate middleware workflow
        signing_key, _ = generate_dpop_key()
        client_id = "https://aip.example.com/client-metadata.json"
        audience = "https://auth.bsky.social"
        key_id = "signing-key-123"

        # Middleware gets header and claims separately
        header, claims = create_client_assertion_header_and_claims(
            client_id, audience, key_id
        )

        # Middleware adds unique jti (as GenerateClaimAssertionMiddleware does)
        claims["jti"] = secrets.token_urlsafe(32)

        # Middleware creates and signs JWT
        middleware_jwt = jwt.JWT(header=header, claims=claims)
        middleware_jwt.make_signed_token(signing_key)
        jwt_string = middleware_jwt.serialize()

        # Verify the result
        verified_jwt = jwt.JWT(jwt=jwt_string, key=signing_key)
        verified_header = json.loads(verified_jwt.header)
        verified_claims = json.loads(verified_jwt.claims)

        assert verified_header == header
        assert verified_claims == claims

    def test_dpop_and_client_assertion_integration(self):
        """Test using both DPoP and client assertion together (OAuth flow)."""
        # Generate keys for both DPoP and client assertion
        dpop_key, dpop_public_key = generate_dpop_key()
        signing_key, _ = generate_dpop_key()  # Different key for client assertion

        client_id = "https://aip.example.com/client-metadata.json"
        audience = "https://auth.bsky.social"
        key_id = "signing-key-123"
        endpoint = "https://auth.bsky.social/oauth/token"

        # Create DPoP JWT
        dpop_jwt = create_dpop_jwt(dpop_key, "POST", endpoint)

        # Create client assertion JWT
        client_assertion_jwt = create_client_assertion_jwt(
            signing_key, client_id, audience, key_id
        )

        # Verify both JWTs are valid and independent
        dpop_parsed = jwt.JWT(jwt=dpop_jwt, key=dpop_key)
        client_parsed = jwt.JWT(jwt=client_assertion_jwt, key=signing_key)

        dpop_claims = json.loads(dpop_parsed.claims)
        client_claims = json.loads(client_parsed.claims)

        # DPoP claims
        assert dpop_claims["htm"] == "POST"
        assert dpop_claims["htu"] == endpoint

        # Client assertion claims
        assert client_claims["iss"] == client_id
        assert client_claims["sub"] == client_id
        assert client_claims["aud"] == audience

    def test_multiple_jwt_uniqueness(self):
        """Test that multiple JWTs for same endpoint are unique."""
        dpop_key, _ = generate_dpop_key()
        endpoint = "https://example.com/token"

        jwts = [create_dpop_jwt(dpop_key, "POST", endpoint) for _ in range(10)]

        # All JWTs should be different (due to different iat, exp, jti)
        assert len(set(jwts)) == 10

        # But all should be valid for the same key
        for jwt_string in jwts:
            parsed_jwt = jwt.JWT(jwt=jwt_string, key=dpop_key)
            claims = json.loads(parsed_jwt.claims)
            assert claims["htm"] == "POST"
            assert claims["htu"] == endpoint


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_create_dpop_header_empty_public_key(self):
        """Test behavior with empty public key dict."""
        empty_dict = {}
        header = create_dpop_header(empty_dict)

        assert header["alg"] == "ES256"
        assert header["typ"] == "dpop+jwt"
        assert header["jwk"] == empty_dict

    def test_create_dpop_claims_empty_strings(self):
        """Test behavior with empty string parameters."""
        now = datetime.now(timezone.utc)

        claims = create_dpop_claims("", "", now)

        assert claims["htm"] == ""  # Empty method becomes empty
        assert claims["htu"] == ""  # Empty URI becomes empty
        assert "iat" in claims
        assert "exp" in claims

    def test_create_dpop_claims_zero_expiration(self):
        """Test behavior with zero expiration time."""
        now = datetime.now(timezone.utc)

        claims = create_dpop_claims("POST", "https://example.com/token", now, 0)

        assert claims["exp"] == claims["iat"]  # Expires immediately

    def test_create_dpop_claims_negative_expiration(self):
        """Test behavior with negative expiration time."""
        now = datetime.now(timezone.utc)

        claims = create_dpop_claims("POST", "https://example.com/token", now, -30)

        assert claims["exp"] == claims["iat"] - 30  # Expires in the past

    def test_create_dpop_jwt_invalid_key_type(self):
        """Test that create_dpop_jwt fails gracefully with wrong key type."""
        # Create RSA key instead of EC key
        rsa_key = jwk.JWK.generate(kty="RSA", size=2048)

        # Should fail when trying to create JWT
        with pytest.raises(Exception):
            create_dpop_jwt(rsa_key, "POST", "https://example.com/token")


class TestSecurityProperties:
    """Test security-related properties of JWT implementation."""

    def test_jti_entropy(self):
        """Test that JTI values have sufficient entropy."""
        dpop_key, _ = generate_dpop_key()

        jtis = []
        for _ in range(100):
            jwt_string = create_dpop_jwt(dpop_key, "POST", "https://example.com/token")
            parsed_jwt = jwt.JWT(jwt=jwt_string, key=dpop_key)
            claims = json.loads(parsed_jwt.claims)
            jtis.append(claims["jti"])

        # All JTIs should be unique
        assert len(set(jtis)) == 100

        # JTIs should be of reasonable length (URL-safe base64 encoded)
        for jti in jtis:
            assert len(jti) >= 32  # At least 32 characters for good entropy

    def test_key_generation_entropy(self):
        """Test that key generation produces unique keys."""
        keys = [generate_dpop_key() for _ in range(50)]

        # All key IDs should be unique
        key_ids = [key[0].export(as_dict=True)["kid"] for key in keys]
        assert len(set(key_ids)) == 50

        # All public key coordinates should be unique
        x_coords = [key[1]["x"] for key in keys]
        y_coords = [key[1]["y"] for key in keys]
        assert len(set(x_coords)) == 50
        assert len(set(y_coords)) == 50

    def test_timestamp_accuracy(self):
        """Test that timestamps are accurate and reasonable."""
        before = datetime.now(timezone.utc).replace(microsecond=0)
        dpop_key, _ = generate_dpop_key()
        jwt_string = create_dpop_jwt(dpop_key, "POST", "https://example.com/token")
        after = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=1)

        parsed_jwt = jwt.JWT(jwt=jwt_string, key=dpop_key)
        claims = json.loads(parsed_jwt.claims)

        iat_time = datetime.fromtimestamp(claims["iat"], tz=timezone.utc)
        exp_time = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)

        # iat should be within the test execution timeframe
        assert before <= iat_time <= after

        # exp should be exactly 30 seconds after iat
        assert exp_time == iat_time + timedelta(seconds=30)

    def test_private_key_not_exposed(self):
        """Test that private key material is never exposed in public components."""
        dpop_key, public_key_dict = generate_dpop_key()

        # Public key dict should not contain private material
        assert "d" not in public_key_dict

        # Header should not contain private material
        header = create_dpop_header(public_key_dict)
        jwk_in_header = header["jwk"]
        assert "d" not in jwk_in_header

        # Claims should not contain any key material
        claims = create_dpop_claims("POST", "https://example.com/token")
        for value in claims.values():
            if isinstance(value, str):
                # No key material should appear in string values
                assert "d" not in value


class TestRfcCompliance:
    """Test compliance with DPoP JWT specification."""

    def test_dpop_jwt_typ_header(self):
        """Test that typ header is exactly 'dpop+jwt' as per spec."""
        _, public_key_dict = generate_dpop_key()
        header = create_dpop_header(public_key_dict)

        assert header["typ"] == "dpop+jwt"

    def test_dpop_jwt_required_claims(self):
        """Test that all required DPoP claims are present."""
        now = datetime.now(timezone.utc)
        claims = create_dpop_claims("POST", "https://example.com/token", now)

        # Required claims per DPoP spec
        required_claims = ["htm", "htu", "iat", "exp"]
        for claim in required_claims:
            assert claim in claims

    def test_dpop_jwt_optional_issuer_claim(self):
        """Test that issuer claim is optional but properly formatted when provided."""
        now = datetime.now(timezone.utc)

        # Without issuer
        claims_no_issuer = create_dpop_claims("POST", "https://example.com/token", now)
        assert "iss" not in claims_no_issuer

        # With issuer
        issuer = "https://auth.provider.example.com"
        claims_with_issuer = create_dpop_claims(
            "POST", "https://example.com/token", now, issuer=issuer
        )
        assert "iss" in claims_with_issuer
        assert claims_with_issuer["iss"] == issuer
        assert isinstance(claims_with_issuer["iss"], str)

    def test_dpop_jwt_htm_format(self):
        """Test that htm claim is uppercase HTTP method."""
        methods = ["get", "post", "put", "delete", "patch", "options", "head"]
        now = datetime.now(timezone.utc)

        for method in methods:
            claims = create_dpop_claims(method, "https://example.com/api", now)
            assert claims["htm"] == method.upper()

    def test_dpop_jwt_htu_format(self):
        """Test that htu claim contains full URI."""
        uris = [
            "https://example.com/token",
            "https://auth.bsky.social/oauth/token",
            "https://pds.example.com/oauth/par",
        ]
        now = datetime.now(timezone.utc)

        for uri in uris:
            claims = create_dpop_claims("POST", uri, now)
            assert claims["htu"] == uri

    def test_dpop_jwt_timestamp_format(self):
        """Test that timestamps are NumericDate format (seconds since epoch)."""
        now = datetime.now(timezone.utc)
        claims = create_dpop_claims("POST", "https://example.com/token", now)

        # Should be integers (NumericDate format)
        assert isinstance(claims["iat"], int)
        assert isinstance(claims["exp"], int)

        # Should be reasonable values (not microseconds)
        current_timestamp = int(now.timestamp())
        assert abs(claims["iat"] - current_timestamp) <= 1  # Within 1 second
        assert claims["exp"] > claims["iat"]  # Expiration after issuance

    def test_dpop_jwt_jti_uniqueness_requirement(self):
        """Test that jti provides replay protection through uniqueness."""
        dpop_key, _ = generate_dpop_key()

        # Generate many JWTs
        jwt_strings = [
            create_dpop_jwt(dpop_key, "POST", "https://example.com/token")
            for _ in range(1000)
        ]

        # Extract all JTIs
        jtis = []
        for jwt_string in jwt_strings:
            parsed_jwt = jwt.JWT(jwt=jwt_string, key=dpop_key)
            claims = json.loads(parsed_jwt.claims)
            jtis.append(claims["jti"])

        # All JTIs must be unique for replay protection
        assert len(set(jtis)) == 1000

    def test_dpop_jwt_issuer_claim_consistency(self):
        """Test that issuer claim is consistent across all JWT creation methods."""
        dpop_key, public_key_dict = generate_dpop_key()
        now = datetime.now(timezone.utc)
        issuer = "https://consistent.issuer.example.com"

        # Test via create_dpop_claims
        claims_direct = create_dpop_claims(
            "POST", "https://example.com/token", now, issuer=issuer
        )
        assert claims_direct["iss"] == issuer

        # Test via create_dpop_header_and_claims
        header, claims_indirect = create_dpop_header_and_claims(
            "POST", "https://example.com/token", public_key_dict, now, issuer=issuer
        )
        assert claims_indirect["iss"] == issuer
        assert claims_direct["iss"] == claims_indirect["iss"]

        # Test via create_dpop_jwt
        jwt_string = create_dpop_jwt(
            dpop_key, "POST", "https://example.com/token", issuer=issuer
        )
        parsed_jwt = jwt.JWT(jwt=jwt_string, key=dpop_key)
        claims_from_jwt = json.loads(parsed_jwt.claims)
        assert claims_from_jwt["iss"] == issuer
        assert claims_direct["iss"] == claims_from_jwt["iss"]

    def test_client_assertion_jwt_rfc7523_compliance(self):
        """Test that client assertion JWTs comply with RFC 7523 requirements."""
        signing_key, _ = generate_dpop_key()
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        key_id = "test-key-123"

        jwt_string = create_client_assertion_jwt(
            signing_key, client_id, audience, key_id
        )
        parsed_jwt = jwt.JWT(jwt=jwt_string, key=signing_key)

        header = json.loads(parsed_jwt.header)
        claims = json.loads(parsed_jwt.claims)

        # RFC 7523 header requirements
        assert header["alg"] == "ES256"  # Algorithm must be specified
        assert header["kid"] == key_id  # Key ID should be present

        # RFC 7523 claims requirements
        assert claims["iss"] == client_id  # Issuer MUST be client_id
        assert claims["sub"] == client_id  # Subject MUST be client_id
        assert claims["aud"] == audience  # Audience MUST be auth server
        assert isinstance(claims["iat"], int)  # Issued at MUST be present
        assert "jti" in claims  # JTI recommended for replay protection

    def test_client_assertion_jwt_required_claims(self):
        """Test that all required client assertion claims are present."""
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        now = datetime.now(timezone.utc)

        claims = create_client_assertion_claims(client_id, audience, now)

        # Required claims per RFC 7523
        required_claims = ["iss", "sub", "aud", "iat"]
        for claim in required_claims:
            assert claim in claims

    def test_client_assertion_jwt_iss_sub_same_value(self):
        """Test that iss and sub have the same value (RFC 7523 requirement)."""
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        now = datetime.now(timezone.utc)

        claims = create_client_assertion_claims(client_id, audience, now)

        # RFC 7523: "iss" and "sub" MUST have the same value (client_id)
        assert claims["iss"] == claims["sub"]
        assert claims["iss"] == client_id

    def test_client_assertion_jwt_timestamp_format(self):
        """Test that timestamps are NumericDate format (seconds since epoch)."""
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        now = datetime.now(timezone.utc)

        claims = create_client_assertion_claims(client_id, audience, now)

        # Should be integers (NumericDate format)
        assert isinstance(claims["iat"], int)

        # Should be reasonable values (not microseconds)
        current_timestamp = int(now.timestamp())
        assert abs(claims["iat"] - current_timestamp) <= 1  # Within 1 second

    def test_client_assertion_jwt_jti_replay_protection(self):
        """Test that jti provides replay protection through uniqueness."""
        signing_key, _ = generate_dpop_key()
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        key_id = "test-key-123"

        # Generate many client assertion JWTs
        jwt_strings = [
            create_client_assertion_jwt(signing_key, client_id, audience, key_id)
            for _ in range(100)
        ]

        # Extract all JTIs
        jtis = []
        for jwt_string in jwt_strings:
            parsed_jwt = jwt.JWT(jwt=jwt_string, key=signing_key)
            claims = json.loads(parsed_jwt.claims)
            jtis.append(claims["jti"])

        # All JTIs must be unique for replay protection
        assert len(set(jtis)) == 100

    def test_client_assertion_consistency_across_methods(self):
        """Test that client assertion components are consistent across all creation methods."""
        signing_key, _ = generate_dpop_key()
        client_id = "https://client.example.com/metadata.json"
        audience = "https://auth.provider.com"
        key_id = "test-key-123"
        now = datetime.now(timezone.utc)

        # Test via create_client_assertion_claims
        claims_direct = create_client_assertion_claims(client_id, audience, now)

        # Test via create_client_assertion_header_and_claims
        header, claims_indirect = create_client_assertion_header_and_claims(
            client_id, audience, key_id, now
        )
        assert claims_direct == claims_indirect

        # Test via create_client_assertion_jwt (without JTI for comparison)
        jwt_string = create_client_assertion_jwt(
            signing_key, client_id, audience, key_id, now, include_jti=False
        )
        parsed_jwt = jwt.JWT(jwt=jwt_string, key=signing_key)
        claims_from_jwt = json.loads(parsed_jwt.claims)

        # Should match (excluding jti which wasn't included)
        for key in claims_direct:
            assert claims_direct[key] == claims_from_jwt[key]
