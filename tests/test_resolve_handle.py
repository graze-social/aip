"""
Unit tests for handle resolution in social.graze.aip.resolve.handle

Tests cover AT Protocol handle/DID resolution, DNS/HTTP resolution methods,
DID document parsing, and error handling with comprehensive mocking.
"""

import pytest
from unittest.mock import AsyncMock, Mock, patch
from aiohttp import ClientSession, ClientResponse

from social.graze.aip.resolve.handle import (
    SubjectType,
    ParsedSubject,
    ResolvedSubject,
    resolve_handle_dns,
    resolve_handle_http,
    resolve_handle,
    handle_predicate,
    pds_predicate,
    resolve_did_method_plc,
    resolve_did_method_web,
    resolve_did,
    resolve_subject,
    parse_input,
)


class TestPydanticModels:
    """Test suite for Pydantic model validation."""

    def test_parsed_subject_creation(self):
        """Test ParsedSubject model creation with valid data."""
        parsed = ParsedSubject(
            subject_type=SubjectType.did_method_plc, subject="did:plc:abc123"
        )
        assert parsed.subject_type == SubjectType.did_method_plc
        assert parsed.subject == "did:plc:abc123"

    def test_resolved_subject_creation(self):
        """Test ResolvedSubject model creation with valid data."""
        resolved = ResolvedSubject(
            did="did:plc:abc123",
            handle="user.bsky.social",
            pds="https://pds.example.com",
        )
        assert resolved.did == "did:plc:abc123"
        assert resolved.handle == "user.bsky.social"
        assert resolved.pds == "https://pds.example.com"

    def test_subject_type_enum_values(self):
        """Test SubjectType enum has expected values."""
        assert SubjectType.did_method_plc == 1
        assert SubjectType.did_method_web == 2
        assert SubjectType.hostname == 3


class TestParseInput:
    """Test suite for parse_input function."""

    def test_parse_did_plc(self):
        """Test parsing did:plc DID returns correct type."""
        result = parse_input("did:plc:abc123def456")
        assert result.subject_type == SubjectType.did_method_plc
        assert result.subject == "did:plc:abc123def456"

    def test_parse_did_web(self):
        """Test parsing did:web DID returns correct type."""
        result = parse_input("did:web:example.com")
        assert result.subject_type == SubjectType.did_method_web
        assert result.subject == "did:web:example.com"

    def test_parse_hostname(self):
        """Test parsing hostname returns correct type."""
        result = parse_input("user.bsky.social")
        assert result.subject_type == SubjectType.hostname
        assert result.subject == "user.bsky.social"

    def test_parse_with_at_prefix(self):
        """Test parsing removes at:// prefix."""
        result = parse_input("at://user.bsky.social")
        assert result.subject_type == SubjectType.hostname
        assert result.subject == "user.bsky.social"

    def test_parse_with_at_symbol(self):
        """Test parsing removes @ prefix."""
        result = parse_input("@user.bsky.social")
        assert result.subject_type == SubjectType.hostname
        assert result.subject == "user.bsky.social"

    def test_parse_with_whitespace(self):
        """Test parsing strips whitespace."""
        result = parse_input("  user.bsky.social  ")
        assert result.subject_type == SubjectType.hostname
        assert result.subject == "user.bsky.social"

    def test_parse_complex_prefixes(self):
        """Test parsing with multiple prefixes."""
        result = parse_input("  at://@user.bsky.social  ")
        assert result.subject_type == SubjectType.hostname
        assert result.subject == "user.bsky.social"


class TestPredicateFunctions:
    """Test suite for predicate helper functions."""

    def test_handle_predicate_true(self):
        """Test handle_predicate returns True for at:// URLs."""
        assert handle_predicate("at://user.bsky.social") is True

    def test_handle_predicate_false(self):
        """Test handle_predicate returns False for non-at:// URLs."""
        assert handle_predicate("https://user.bsky.social") is False
        assert handle_predicate("user.bsky.social") is False
        assert handle_predicate("") is False

    def test_pds_predicate_true(self):
        """Test pds_predicate returns True for valid PDS service."""
        service = {
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": "https://pds.example.com",
        }
        assert pds_predicate(service) is True

    def test_pds_predicate_false_wrong_type(self):
        """Test pds_predicate returns False for wrong service type."""
        service = {
            "type": "SomeOtherService",
            "serviceEndpoint": "https://pds.example.com",
        }
        assert pds_predicate(service) is False

    def test_pds_predicate_false_missing_endpoint(self):
        """Test pds_predicate returns False for missing serviceEndpoint."""
        service = {"type": "AtprotoPersonalDataServer"}
        assert pds_predicate(service) is False

    def test_pds_predicate_false_empty_dict(self):
        """Test pds_predicate returns False for empty dict."""
        assert pds_predicate({}) is False


class TestResolveHandleDns:
    """Test suite for DNS handle resolution."""

    @pytest.mark.asyncio
    @patch("social.graze.aip.resolve.handle.DNSResolver")
    async def test_resolve_handle_dns_success(self, mock_resolver_class):
        """Test successful DNS resolution."""
        # Setup mock
        mock_resolver = AsyncMock()
        mock_resolver_class.return_value = mock_resolver

        mock_result = Mock()
        mock_result.text = "did=did:plc:abc123"
        mock_resolver.query.return_value = [mock_result]

        # Test
        result = await resolve_handle_dns("user.bsky.social")

        # Verify
        assert result == "did:plc:abc123"
        mock_resolver.query.assert_called_once_with("_atproto.user.bsky.social", "TXT")

    @pytest.mark.asyncio
    @patch("social.graze.aip.resolve.handle.DNSResolver")
    async def test_resolve_handle_dns_no_results(self, mock_resolver_class):
        """Test DNS resolution with no results."""
        mock_resolver = AsyncMock()
        mock_resolver_class.return_value = mock_resolver
        mock_resolver.query.return_value = []

        result = await resolve_handle_dns("user.bsky.social")
        assert result is None

    @pytest.mark.asyncio
    @patch("social.graze.aip.resolve.handle.DNSResolver")
    @patch("social.graze.aip.resolve.handle.sentry_sdk")
    async def test_resolve_handle_dns_exception(self, mock_sentry, mock_resolver_class):
        """Test DNS resolution with exception."""
        mock_resolver = AsyncMock()
        mock_resolver_class.return_value = mock_resolver
        mock_resolver.query.side_effect = Exception("DNS error")

        result = await resolve_handle_dns("user.bsky.social")

        assert result is None
        mock_sentry.capture_exception.assert_called_once()

    @pytest.mark.asyncio
    @patch("social.graze.aip.resolve.handle.DNSResolver")
    async def test_resolve_handle_dns_none_results(self, mock_resolver_class):
        """Test DNS resolution with None results."""
        mock_resolver = AsyncMock()
        mock_resolver_class.return_value = mock_resolver
        mock_resolver.query.return_value = None

        result = await resolve_handle_dns("user.bsky.social")
        assert result is None


class TestResolveHandleHttp:
    """Test suite for HTTP handle resolution."""

    @pytest.mark.asyncio
    async def test_resolve_handle_http_success(self):
        """Test successful HTTP resolution."""
        # Create mock session and response
        mock_session = AsyncMock(spec=ClientSession)
        mock_response = AsyncMock(spec=ClientResponse)
        mock_response.status = 200
        mock_response.text.return_value = "did:plc:abc123"

        mock_session.get.return_value.__aenter__.return_value = mock_response

        result = await resolve_handle_http(mock_session, "user.bsky.social")

        assert result == "did:plc:abc123"
        mock_session.get.assert_called_once_with(
            "https://user.bsky.social/.well-known/atproto-did"
        )

    @pytest.mark.asyncio
    async def test_resolve_handle_http_not_found(self):
        """Test HTTP resolution with 404 response."""
        mock_session = AsyncMock(spec=ClientSession)
        mock_response = AsyncMock(spec=ClientResponse)
        mock_response.status = 404

        mock_session.get.return_value.__aenter__.return_value = mock_response

        result = await resolve_handle_http(mock_session, "user.bsky.social")
        assert result is None

    @pytest.mark.asyncio
    async def test_resolve_handle_http_empty_body(self):
        """Test HTTP resolution with empty body."""
        mock_session = AsyncMock(spec=ClientSession)
        mock_response = AsyncMock(spec=ClientResponse)
        mock_response.status = 200
        mock_response.text.return_value = None

        mock_session.get.return_value.__aenter__.return_value = mock_response

        result = await resolve_handle_http(mock_session, "user.bsky.social")
        assert result is None


class TestResolveHandle:
    """Test suite for combined handle resolution."""

    @pytest.mark.asyncio
    @patch("social.graze.aip.resolve.handle.resolve_handle_dns")
    @patch("social.graze.aip.resolve.handle.resolve_handle_http")
    async def test_resolve_handle_dns_success(self, mock_http, mock_dns):
        """Test combined resolution prefers DNS result."""
        mock_dns.return_value = "did:plc:dns123"
        mock_http.return_value = "did:plc:http456"

        mock_session = AsyncMock()
        result = await resolve_handle(mock_session, "user.bsky.social")

        assert result == "did:plc:dns123"

    @pytest.mark.asyncio
    @patch("social.graze.aip.resolve.handle.resolve_handle_dns")
    @patch("social.graze.aip.resolve.handle.resolve_handle_http")
    async def test_resolve_handle_http_fallback(self, mock_http, mock_dns):
        """Test combined resolution falls back to HTTP."""
        mock_dns.return_value = None
        mock_http.return_value = "did:plc:http456"

        mock_session = AsyncMock()
        result = await resolve_handle(mock_session, "user.bsky.social")

        assert result == "did:plc:http456"

    @pytest.mark.asyncio
    @patch("social.graze.aip.resolve.handle.resolve_handle_dns")
    @patch("social.graze.aip.resolve.handle.resolve_handle_http")
    async def test_resolve_handle_both_fail(self, mock_http, mock_dns):
        """Test combined resolution when both methods fail."""
        mock_dns.return_value = None
        mock_http.return_value = None

        mock_session = AsyncMock()
        result = await resolve_handle(mock_session, "user.bsky.social")

        assert result is None


class TestResolveDidMethodPlc:
    """Test suite for did:plc resolution."""

    @pytest.mark.asyncio
    async def test_resolve_did_method_plc_success(self):
        """Test successful did:plc resolution."""
        mock_session = AsyncMock(spec=ClientSession)
        mock_response = AsyncMock(spec=ClientResponse)
        mock_response.status = 200
        mock_response.json.return_value = {
            "alsoKnownAs": ["at://user.bsky.social"],
            "service": [
                {
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://pds.example.com",
                }
            ],
        }

        mock_session.get.return_value.__aenter__.return_value = mock_response

        result = await resolve_did_method_plc(
            "plc.directory", mock_session, "did:plc:abc123"
        )

        assert result.did == "did:plc:abc123"
        assert result.handle == "user.bsky.social"
        assert result.pds == "https://pds.example.com"
        mock_session.get.assert_called_once_with("https://plc.directory/did:plc:abc123")

    @pytest.mark.asyncio
    async def test_resolve_did_method_plc_not_found(self):
        """Test did:plc resolution with 404 response."""
        mock_session = AsyncMock(spec=ClientSession)
        mock_response = AsyncMock(spec=ClientResponse)
        mock_response.status = 404

        mock_session.get.return_value.__aenter__.return_value = mock_response

        result = await resolve_did_method_plc(
            "plc.directory", mock_session, "did:plc:abc123"
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_resolve_did_method_plc_no_handle(self):
        """Test did:plc resolution with missing handle."""
        mock_session = AsyncMock(spec=ClientSession)
        mock_response = AsyncMock(spec=ClientResponse)
        mock_response.status = 200
        mock_response.json.return_value = {
            "alsoKnownAs": ["https://user.bsky.social"],  # Not at:// URL
            "service": [
                {
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://pds.example.com",
                }
            ],
        }

        mock_session.get.return_value.__aenter__.return_value = mock_response

        result = await resolve_did_method_plc(
            "plc.directory", mock_session, "did:plc:abc123"
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_resolve_did_method_plc_no_pds(self):
        """Test did:plc resolution with missing PDS."""
        mock_session = AsyncMock(spec=ClientSession)
        mock_response = AsyncMock(spec=ClientResponse)
        mock_response.status = 200
        mock_response.json.return_value = {
            "alsoKnownAs": ["at://user.bsky.social"],
            "service": [
                {
                    "type": "SomeOtherService",  # Not PDS
                    "serviceEndpoint": "https://other.example.com",
                }
            ],
        }

        mock_session.get.return_value.__aenter__.return_value = mock_response

        result = await resolve_did_method_plc(
            "plc.directory", mock_session, "did:plc:abc123"
        )

        assert result is None


class TestResolveDidMethodWeb:
    """Test suite for did:web resolution."""

    @pytest.mark.asyncio
    async def test_resolve_did_method_web_success(self):
        """Test successful did:web resolution."""
        mock_session = AsyncMock(spec=ClientSession)
        mock_response = AsyncMock(spec=ClientResponse)
        mock_response.status = 200
        mock_response.json.return_value = {
            "alsoKnownAs": ["at://user.example.com"],
            "service": [
                {
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://pds.example.com",
                }
            ],
        }

        mock_session.get.return_value.__aenter__.return_value = mock_response

        result = await resolve_did_method_web(mock_session, "did:web:example.com")

        assert result.did == "did:web:example.com"
        assert result.handle == "user.example.com"
        assert result.pds == "https://pds.example.com"
        mock_session.get.assert_called_once_with(
            "https://example.com/.well-known/did.json"
        )

    @pytest.mark.asyncio
    async def test_resolve_did_method_web_with_path(self):
        """Test did:web resolution with path components."""
        mock_session = AsyncMock(spec=ClientSession)
        mock_response = AsyncMock(spec=ClientResponse)
        mock_response.status = 200
        mock_response.json.return_value = {
            "alsoKnownAs": ["at://user.example.com"],
            "service": [
                {
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://pds.example.com",
                }
            ],
        }

        mock_session.get.return_value.__aenter__.return_value = mock_response

        result = await resolve_did_method_web(
            mock_session, "did:web:example.com:user:alice"
        )

        assert result.did == "did:web:example.com:user:alice"
        assert result.handle == "user.example.com"
        assert result.pds == "https://pds.example.com"
        mock_session.get.assert_called_once_with(
            "https://example.com/user/alice/did.json"
        )

    @pytest.mark.asyncio
    async def test_resolve_did_method_web_empty_parts(self):
        """Test did:web resolution with malformed DID."""
        mock_session = AsyncMock(spec=ClientSession)

        result = await resolve_did_method_web(mock_session, "did:web:")

        assert result is None

    @pytest.mark.asyncio
    async def test_resolve_did_method_web_not_found(self):
        """Test did:web resolution with 404 response."""
        mock_session = AsyncMock(spec=ClientSession)
        mock_response = AsyncMock(spec=ClientResponse)
        mock_response.status = 404

        mock_session.get.return_value.__aenter__.return_value = mock_response

        result = await resolve_did_method_web(mock_session, "did:web:example.com")

        assert result is None


class TestResolveDid:
    """Test suite for DID resolution router."""

    @pytest.mark.asyncio
    @patch("social.graze.aip.resolve.handle.resolve_did_method_plc")
    async def test_resolve_did_plc(self, mock_plc):
        """Test DID resolution routes to PLC method."""
        expected_result = ResolvedSubject(
            did="did:plc:abc123",
            handle="user.bsky.social",
            pds="https://pds.example.com",
        )
        mock_plc.return_value = expected_result

        mock_session = AsyncMock()
        result = await resolve_did(mock_session, "plc.directory", "did:plc:abc123")

        assert result == expected_result
        mock_plc.assert_called_once_with(
            "plc.directory", mock_session, "did:plc:abc123"
        )

    @pytest.mark.asyncio
    @patch("social.graze.aip.resolve.handle.resolve_did_method_web")
    async def test_resolve_did_web(self, mock_web):
        """Test DID resolution routes to web method."""
        expected_result = ResolvedSubject(
            did="did:web:example.com",
            handle="user.example.com",
            pds="https://pds.example.com",
        )
        mock_web.return_value = expected_result

        mock_session = AsyncMock()
        result = await resolve_did(mock_session, "plc.directory", "did:web:example.com")

        assert result == expected_result
        mock_web.assert_called_once_with(mock_session, "did:web:example.com")

    @pytest.mark.asyncio
    async def test_resolve_did_unsupported(self):
        """Test DID resolution with unsupported method."""
        mock_session = AsyncMock()
        result = await resolve_did(mock_session, "plc.directory", "did:unknown:abc123")

        assert result is None


class TestResolveSubject:
    """Test suite for main subject resolution function."""

    @pytest.mark.asyncio
    @patch("social.graze.aip.resolve.handle.parse_input")
    async def test_resolve_subject_invalid_input(self, mock_parse):
        """Test subject resolution with invalid input."""
        mock_parse.return_value = None

        mock_session = AsyncMock()
        result = await resolve_subject(mock_session, "plc.directory", "invalid")

        assert result is None

    @pytest.mark.asyncio
    @patch("social.graze.aip.resolve.handle.resolve_handle")
    @patch("social.graze.aip.resolve.handle.resolve_did")
    async def test_resolve_subject_hostname(
        self, mock_resolve_did, mock_resolve_handle
    ):
        """Test subject resolution for hostname."""
        mock_resolve_handle.return_value = "did:plc:abc123"
        expected_result = ResolvedSubject(
            did="did:plc:abc123",
            handle="user.bsky.social",
            pds="https://pds.example.com",
        )
        mock_resolve_did.return_value = expected_result

        mock_session = AsyncMock()
        result = await resolve_subject(
            mock_session, "plc.directory", "user.bsky.social"
        )

        assert result == expected_result
        mock_resolve_handle.assert_called_once_with(mock_session, "user.bsky.social")
        mock_resolve_did.assert_called_once_with(
            mock_session, "plc.directory", "did:plc:abc123"
        )

    @pytest.mark.asyncio
    @patch("social.graze.aip.resolve.handle.resolve_did")
    async def test_resolve_subject_did_plc(self, mock_resolve_did):
        """Test subject resolution for did:plc."""
        expected_result = ResolvedSubject(
            did="did:plc:abc123",
            handle="user.bsky.social",
            pds="https://pds.example.com",
        )
        mock_resolve_did.return_value = expected_result

        mock_session = AsyncMock()
        result = await resolve_subject(mock_session, "plc.directory", "did:plc:abc123")

        assert result == expected_result
        mock_resolve_did.assert_called_once_with(
            mock_session, "plc.directory", "did:plc:abc123"
        )

    @pytest.mark.asyncio
    @patch("social.graze.aip.resolve.handle.resolve_did")
    async def test_resolve_subject_did_web(self, mock_resolve_did):
        """Test subject resolution for did:web."""
        expected_result = ResolvedSubject(
            did="did:web:example.com",
            handle="user.example.com",
            pds="https://pds.example.com",
        )
        mock_resolve_did.return_value = expected_result

        mock_session = AsyncMock()
        result = await resolve_subject(
            mock_session, "plc.directory", "did:web:example.com"
        )

        assert result == expected_result
        mock_resolve_did.assert_called_once_with(
            mock_session, "plc.directory", "did:web:example.com"
        )

    @pytest.mark.asyncio
    @patch("social.graze.aip.resolve.handle.resolve_handle")
    async def test_resolve_subject_handle_resolution_fails(self, mock_resolve_handle):
        """Test subject resolution when handle resolution fails."""
        mock_resolve_handle.return_value = None

        mock_session = AsyncMock()
        result = await resolve_subject(
            mock_session, "plc.directory", "user.bsky.social"
        )

        assert result is None

    @pytest.mark.asyncio
    @patch("social.graze.aip.resolve.handle.resolve_handle")
    @patch("social.graze.aip.resolve.handle.resolve_did")
    async def test_resolve_subject_did_resolution_fails(
        self, mock_resolve_did, mock_resolve_handle
    ):
        """Test subject resolution when DID resolution fails."""
        mock_resolve_handle.return_value = "did:plc:abc123"
        mock_resolve_did.return_value = None

        mock_session = AsyncMock()
        result = await resolve_subject(
            mock_session, "plc.directory", "user.bsky.social"
        )

        assert result is None


class TestErrorHandlingAndEdgeCases:
    """Test suite for error handling and edge cases."""

    @pytest.mark.asyncio
    @patch("social.graze.aip.resolve.handle.sentry_sdk")
    async def test_resolve_handle_http_exception(self, mock_sentry):
        """Test HTTP resolution handles exceptions gracefully."""
        mock_session = AsyncMock(spec=ClientSession)
        mock_session.get.side_effect = Exception("Network error")

        # Should not raise, should return None
        result = await resolve_handle_http(mock_session, "user.bsky.social")
        assert result is None
        mock_sentry.capture_exception.assert_called_once()

    @pytest.mark.asyncio
    async def test_resolve_did_method_plc_invalid_json(self):
        """Test PLC resolution with invalid JSON."""
        mock_session = AsyncMock(spec=ClientSession)
        mock_response = AsyncMock(spec=ClientResponse)
        mock_response.status = 200
        mock_response.json.return_value = None

        mock_session.get.return_value.__aenter__.return_value = mock_response

        result = await resolve_did_method_plc(
            "plc.directory", mock_session, "did:plc:abc123"
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_resolve_did_method_web_invalid_json(self):
        """Test web DID resolution with invalid JSON."""
        mock_session = AsyncMock(spec=ClientSession)
        mock_response = AsyncMock(spec=ClientResponse)
        mock_response.status = 200
        mock_response.json.return_value = None

        mock_session.get.return_value.__aenter__.return_value = mock_response

        result = await resolve_did_method_web(mock_session, "did:web:example.com")

        assert result is None

    def test_parse_input_empty_string(self):
        """Test parsing empty string."""
        result = parse_input("")
        assert result.subject_type == SubjectType.hostname
        assert result.subject == ""

    def test_parse_input_only_prefixes(self):
        """Test parsing string with only prefixes."""
        result = parse_input("at://@")
        assert result.subject_type == SubjectType.hostname
        assert result.subject == ""

    @pytest.mark.asyncio
    async def test_resolve_did_method_web_malformed_did(self):
        """Test web DID resolution with completely malformed DID."""
        mock_session = AsyncMock(spec=ClientSession)

        # Test with DID that doesn't have proper format
        result = await resolve_did_method_web(mock_session, "not-a-did")

        assert result is None

    def test_predicate_functions_with_none(self):
        """Test predicate functions handle None values."""
        assert handle_predicate(None) is False  # Should handle None gracefully
        assert pds_predicate(None) is False  # Should handle None gracefully
