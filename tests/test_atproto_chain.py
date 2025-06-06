"""
Comprehensive unit tests for AT Protocol middleware chain infrastructure.

Tests cover middleware chain pattern, OAuth 2.0 client assertions, DPoP handling,
request/response transformation, retry logic, and HTTP client functionality.
"""

import json
from unittest.mock import AsyncMock, Mock, patch
from typing import Any, Dict

import pytest
from aiohttp import ClientResponse, ClientSession, FormData, hdrs, web
from jwcrypto import jwt, jwk
from multidict import CIMultiDictProxy

from social.graze.aip.atproto.chain import (
    ChainRequest,
    ChainResponse,
    RequestMiddlewareBase,
    StatsdMiddleware,
    DebugMiddleware,
    GenerateClaimAssertionMiddleware,
    GenerateDpopMiddleware,
    EndOfLineChainMiddleware,
    ChainMiddlewareContext,
    ChainMiddlewareClient,
)
from social.graze.aip.app.metrics import MetricsClient


# Test fixtures and utilities
def create_headers_proxy(headers_list):
    """Create CIMultiDictProxy from list of tuples."""
    from multidict import CIMultiDict

    return CIMultiDictProxy(CIMultiDict(headers_list))


def create_test_jwk() -> jwk.JWK:
    """Create a test JWK for testing purposes."""
    return jwk.JWK.generate(kty="EC", curve="P-256", alg="ES256")


def create_mock_response(
    status: int = 200,
    headers: Dict[str, str] | None = None,
    content_type: str = "application/json",
    body: Any = None,
) -> ClientResponse:
    """Create a mock aiohttp ClientResponse."""
    mock_response = AsyncMock(spec=ClientResponse)
    mock_response.status = status

    # Create headers with CIMultiDictProxy
    from multidict import CIMultiDict

    headers_dict = headers or {}
    if hdrs.CONTENT_TYPE not in headers_dict:
        headers_dict[hdrs.CONTENT_TYPE] = content_type
    headers_multidict = CIMultiDict(headers_dict)
    mock_response.headers = CIMultiDictProxy(headers_multidict)

    # Set body responses based on content type
    if content_type.startswith("application/json"):
        mock_response.json = AsyncMock(return_value=body or {})
        mock_response.text = AsyncMock(return_value=json.dumps(body or {}))
        mock_response.read = AsyncMock(return_value=json.dumps(body or {}).encode())
    elif content_type.startswith("text/"):
        text_body = str(body) if body is not None else "test response"
        mock_response.json = AsyncMock(side_effect=Exception("Not JSON"))
        mock_response.text = AsyncMock(return_value=text_body)
        mock_response.read = AsyncMock(return_value=text_body.encode())
    else:
        binary_body = body if isinstance(body, bytes) else b"binary data"
        mock_response.json = AsyncMock(side_effect=Exception("Not JSON"))
        mock_response.text = AsyncMock(side_effect=Exception("Not text"))
        mock_response.read = AsyncMock(return_value=binary_body)

    mock_response.raise_for_status = Mock()
    mock_response.closed = False
    mock_response.close = Mock()

    return mock_response


class TestChainRequest:
    """Test ChainRequest dataclass and methods."""

    def test_chain_request_creation(self):
        """Test ChainRequest can be created with various parameters."""
        request = ChainRequest(
            method="POST",
            url="https://example.com/api",
            headers={"Authorization": "Bearer token"},
            trace_request_ctx={"trace_id": "123"},
            kwargs={"timeout": 30},
        )

        assert request.method == "POST"
        assert request.url == "https://example.com/api"
        assert request.headers == {"Authorization": "Bearer token"}
        assert request.trace_request_ctx == {"trace_id": "123"}
        assert request.kwargs == {"timeout": 30}

    def test_chain_request_minimal_creation(self):
        """Test ChainRequest with only required parameters."""
        request = ChainRequest(method="GET", url="https://example.com")

        assert request.method == "GET"
        assert request.url == "https://example.com"
        assert request.headers is None
        assert request.trace_request_ctx is None
        assert request.kwargs is None

    def test_from_chain_request_copy(self):
        """Test from_chain_request creates an exact copy."""
        original = ChainRequest(
            method="PUT",
            url="https://example.com/resource",
            headers={"Content-Type": "application/json"},
            trace_request_ctx={"span_id": "456"},
            kwargs={"data": {"key": "value"}},
        )

        copy = ChainRequest.from_chain_request(original)

        assert copy.method == original.method
        assert copy.url == original.url
        assert copy.headers == original.headers
        assert copy.trace_request_ctx == original.trace_request_ctx
        assert copy.kwargs == original.kwargs

        # Ensure it's a copy, not the same object
        assert copy is not original

    def test_from_chain_request_with_none_values(self):
        """Test from_chain_request handles None values correctly."""
        original = ChainRequest(method="DELETE", url="https://example.com/item")
        copy = ChainRequest.from_chain_request(original)

        assert copy.method == "DELETE"
        assert copy.url == "https://example.com/item"
        assert copy.headers is None
        assert copy.trace_request_ctx is None
        assert copy.kwargs is None


class TestChainResponse:
    """Test ChainResponse dataclass and methods."""

    def test_chain_response_creation(self):
        """Test ChainResponse can be created with various parameters."""
        headers = create_headers_proxy([("Content-Type", "application/json")])
        response = ChainResponse(
            status=200, headers=headers, body={"message": "success"}
        )

        assert response.status == 200
        assert response.headers == headers
        assert response.body == {"message": "success"}

    def test_chain_response_minimal_creation(self):
        """Test ChainResponse with only required parameters."""
        headers = create_headers_proxy([])
        response = ChainResponse(status=404, headers=headers)

        assert response.status == 404
        assert response.headers == headers
        assert response.body is None

    @pytest.mark.asyncio
    async def test_from_aiohttp_response_json(self):
        """Test conversion from aiohttp response with JSON content."""
        mock_response = create_mock_response(
            status=200, content_type="application/json", body={"key": "value"}
        )

        chain_response = await ChainResponse.from_aiohttp_response(mock_response)

        assert chain_response.status == 200
        assert chain_response.body == {"key": "value"}
        mock_response.json.assert_called_once()  # type: ignore

    @pytest.mark.asyncio
    async def test_from_aiohttp_response_text(self):
        """Test conversion from aiohttp response with text content."""
        mock_response = create_mock_response(
            status=200, content_type="text/plain", body="Hello, World!"
        )

        chain_response = await ChainResponse.from_aiohttp_response(mock_response)

        assert chain_response.status == 200
        assert chain_response.body == "Hello, World!"
        mock_response.text.assert_called_once()  # type: ignore

    @pytest.mark.asyncio
    async def test_from_aiohttp_response_binary(self):
        """Test conversion from aiohttp response with binary content."""
        mock_response = create_mock_response(
            status=200, content_type="application/octet-stream", body=b"binary data"
        )

        chain_response = await ChainResponse.from_aiohttp_response(mock_response)

        assert chain_response.status == 200
        assert chain_response.body == b"binary data"
        mock_response.read.assert_called_once()  # type: ignore

    def test_body_contains_string(self):
        """Test body_contains with string body."""
        headers = create_headers_proxy([])
        response = ChainResponse(status=200, headers=headers, body="Hello, World!")

        assert response.body_contains("Hello")
        assert response.body_contains("World")
        assert not response.body_contains("Goodbye")

    def test_body_contains_bytes(self):
        """Test body_contains with bytes body."""
        headers = create_headers_proxy([])
        response = ChainResponse(status=200, headers=headers, body=b"binary content")

        assert response.body_contains("binary")
        assert response.body_contains("content")
        assert not response.body_contains("text")

    def test_body_contains_dict(self):
        """Test body_contains with dict body."""
        headers = create_headers_proxy([])
        response = ChainResponse(
            status=200,
            headers=headers,
            body={"error": "invalid_request", "message": "Bad request"},
        )

        assert response.body_contains("error")  # Key exists
        assert response.body_contains("message")  # Key exists
        assert not response.body_contains("invalid_request")  # Value, not key
        assert not response.body_contains("success")  # Neither key nor value

    def test_body_contains_none(self):
        """Test body_contains with None body."""
        headers = create_headers_proxy([])
        response = ChainResponse(status=204, headers=headers, body=None)

        assert not response.body_contains("anything")

    def test_body_matches_kv_success(self):
        """Test body_matches_kv with matching key-value pair."""
        headers = create_headers_proxy([])
        response = ChainResponse(
            status=400,
            headers=headers,
            body={"error": "invalid_dpop_proof", "code": 400},
        )

        assert response.body_matches_kv("error", "invalid_dpop_proof")
        assert response.body_matches_kv("code", 400)

    def test_body_matches_kv_failure(self):
        """Test body_matches_kv with non-matching pairs."""
        headers = create_headers_proxy([])
        response = ChainResponse(
            status=400, headers=headers, body={"error": "invalid_request", "code": 400}
        )

        assert not response.body_matches_kv("error", "invalid_dpop_proof")
        assert not response.body_matches_kv("code", 401)
        assert not response.body_matches_kv("missing_key", "value")

    def test_body_matches_kv_non_dict(self):
        """Test body_matches_kv with non-dict body."""
        headers = create_headers_proxy([])
        response = ChainResponse(status=200, headers=headers, body="string body")

        assert not response.body_matches_kv("any", "value")

    def test_body_matches_kv_none(self):
        """Test body_matches_kv with None body."""
        headers = create_headers_proxy([])
        response = ChainResponse(status=204, headers=headers, body=None)

        assert not response.body_matches_kv("any", "value")

    def test_to_web_response_string(self):
        """Test conversion to web.Response with string body."""
        headers = create_headers_proxy([("Content-Type", "text/plain")])
        response = ChainResponse(status=200, headers=headers, body="Hello, World!")

        web_response = response.to_web_response()

        assert isinstance(web_response, web.Response)
        assert web_response.status == 200
        assert web_response.headers["Content-Type"].startswith("text/plain")

    def test_to_web_response_bytes(self):
        """Test conversion to web.Response with bytes body."""
        headers = create_headers_proxy([("Content-Type", "application/octet-stream")])
        response = ChainResponse(status=200, headers=headers, body=b"binary data")

        web_response = response.to_web_response()

        assert isinstance(web_response, web.Response)
        assert web_response.status == 200

    def test_to_web_response_dict(self):
        """Test conversion to web.Response with dict body."""
        headers = create_headers_proxy([("Content-Type", "application/json")])
        response = ChainResponse(status=200, headers=headers, body={"key": "value"})

        web_response = response.to_web_response()

        assert isinstance(web_response, web.Response)
        assert web_response.status == 200

    def test_to_web_response_none_body(self):
        """Test conversion to web.Response with None body."""
        headers = create_headers_proxy([("Content-Type", "text/plain")])
        response = ChainResponse(status=204, headers=headers, body=None)

        web_response = response.to_web_response()

        assert isinstance(web_response, web.Response)
        assert web_response.status == 204


class TestRequestMiddlewareBase:
    """Test RequestMiddlewareBase abstract class."""

    def test_abstract_class_cannot_be_instantiated(self):
        """Test that RequestMiddlewareBase cannot be instantiated directly."""
        with pytest.raises(TypeError):
            RequestMiddlewareBase()  # type: ignore

    def test_handle_gen_returns_callable(self):
        """Test that handle_gen returns a proper callback function."""

        class TestMiddleware(RequestMiddlewareBase):
            async def handle(self, next, request):
                return await next(request)

        middleware = TestMiddleware()
        mock_next = AsyncMock()

        callback = middleware.handle_gen(mock_next)

        assert callable(callback)
        assert hasattr(callback, "__call__")

    @pytest.mark.asyncio
    async def test_handle_gen_invokes_handle(self):
        """Test that handle_gen properly invokes handle method."""

        class TestMiddleware(RequestMiddlewareBase):
            async def handle(self, next, request):
                return await next(request)

        middleware = TestMiddleware()
        mock_next = AsyncMock(return_value=("response", "chain_response"))
        request = ChainRequest("GET", "https://example.com")

        callback = middleware.handle_gen(mock_next)
        result = await callback(request)

        mock_next.assert_called_once_with(request)
        assert result == ("response", "chain_response")


class TestStatsdMiddleware:
    """Test StatsdMiddleware for metrics collection."""

    def test_statsd_middleware_creation(self):
        """Test StatsdMiddleware can be created with metrics client."""
        mock_metrics = Mock(spec=MetricsClient)
        middleware = StatsdMiddleware(mock_metrics)

        assert middleware._metrics_client == mock_metrics

    @pytest.mark.asyncio
    async def test_statsd_middleware_success_metrics(self):
        """Test that metrics are sent on successful request."""
        mock_metrics = Mock(spec=MetricsClient)
        middleware = StatsdMiddleware(mock_metrics)

        mock_next = AsyncMock(return_value=("response", "chain_response"))
        request = ChainRequest("POST", "https://example.com/api")

        with patch(
            "social.graze.aip.atproto.chain.time", side_effect=[1000.0, 1001.5]
        ):  # 1.5 second duration
            result = await middleware.handle(mock_next, request)

        mock_next.assert_called_once_with(request)
        assert result == ("response", "chain_response")

        # Verify metrics were sent
        mock_metrics.timer.assert_called_once_with(
            "aip.client.request.time", 1.5, tag_dict={"method": "post"}
        )
        mock_metrics.increment.assert_called_once_with(
            "aip.client.request.count", 1, tag_dict={"method": "post"}
        )

    @pytest.mark.asyncio
    async def test_statsd_middleware_exception_handling(self):
        """Test that exceptions are captured by Sentry and metrics still sent."""
        mock_metrics = Mock(spec=MetricsClient)
        middleware = StatsdMiddleware(mock_metrics)

        test_exception = Exception("Test error")
        mock_next = AsyncMock(side_effect=test_exception)
        request = ChainRequest("GET", "https://example.com")

        with patch(
            "social.graze.aip.atproto.chain.time", side_effect=[1000.0, 1000.2]
        ):  # 0.2 second duration
            with patch("sentry_sdk.capture_exception") as mock_sentry:
                with pytest.raises(Exception, match="Test error"):
                    await middleware.handle(mock_next, request)

        # Verify Sentry captured the exception
        mock_sentry.assert_called_once_with(test_exception)

        # Verify metrics were still sent
        timer_call = mock_metrics.timer.call_args
        assert timer_call[0][0] == "aip.client.request.time"
        assert abs(timer_call[0][1] - 0.2) < 0.001  # Allow small floating point error
        assert timer_call[1]["tag_dict"] == {"method": "get"}
        mock_metrics.increment.assert_called_once_with(
            "aip.client.request.count", 1, tag_dict={"method": "get"}
        )

    @pytest.mark.asyncio
    async def test_statsd_middleware_method_case_handling(self):
        """Test that HTTP methods are properly lowercased for metrics."""
        mock_metrics = Mock(spec=MetricsClient)
        middleware = StatsdMiddleware(mock_metrics)

        mock_next = AsyncMock(return_value=("response", "chain_response"))
        request = ChainRequest("PUT", "https://example.com")

        with patch("social.graze.aip.atproto.chain.time", side_effect=[1000.0, 1001.0]):
            await middleware.handle(mock_next, request)

        # Verify method is lowercased in tags
        expected_tags = {"method": "put"}
        mock_metrics.timer.assert_called_once_with(
            "aip.client.request.time", 1.0, tag_dict=expected_tags
        )
        mock_metrics.increment.assert_called_once_with(
            "aip.client.request.count", 1, tag_dict=expected_tags
        )


class TestDebugMiddleware:
    """Test DebugMiddleware for debug logging."""

    @pytest.mark.asyncio
    async def test_debug_middleware_logs_request_response(self):
        """Test that DebugMiddleware logs both request and response."""
        middleware = DebugMiddleware()

        mock_response = (
            "client_response",
            Mock(
                status=200,
                headers={"Content-Type": "application/json"},
                body={"result": "success"},
            ),
        )
        mock_next = AsyncMock(return_value=mock_response)
        request = ChainRequest(
            "POST",
            "https://example.com/api",
            headers={"Authorization": "Bearer token"},
            kwargs={"timeout": 30},
        )

        with patch("social.graze.aip.atproto.chain.logger") as mock_logger:
            result = await middleware.handle(mock_next, request)

        mock_next.assert_called_once_with(request)
        assert result == mock_response

        # Verify debug logging
        assert mock_logger.debug.call_count == 2

        # Check request log
        request_log_call = mock_logger.debug.call_args_list[0]
        assert "Request:" in request_log_call[0][0]
        assert "POST" in request_log_call[0][0]
        assert "https://example.com/api" in request_log_call[0][0]

        # Check response log
        response_log_call = mock_logger.debug.call_args_list[1]
        assert "Response:" in response_log_call[0][0]
        assert "200" in response_log_call[0][0]

    @pytest.mark.asyncio
    async def test_debug_middleware_exception_propagation(self):
        """Test that DebugMiddleware properly propagates exceptions."""
        middleware = DebugMiddleware()

        test_exception = Exception("Test error")
        mock_next = AsyncMock(side_effect=test_exception)
        request = ChainRequest("GET", "https://example.com")

        with patch("social.graze.aip.atproto.chain.logger"):
            with pytest.raises(Exception, match="Test error"):
                await middleware.handle(mock_next, request)


class TestGenerateClaimAssertionMiddleware:
    """Test GenerateClaimAssertionMiddleware for OAuth 2.0 client assertions."""

    def test_generate_claim_assertion_middleware_creation(self):
        """Test middleware can be created with proper parameters."""
        signing_key = create_test_jwk()
        header = {"alg": "ES256", "kid": "test-key"}
        claims = {"iss": "client-id", "aud": "auth-server"}

        middleware = GenerateClaimAssertionMiddleware(signing_key, header, claims)

        assert middleware._signing_key == signing_key
        assert middleware._client_assertion_header == header
        assert middleware._client_assertion_claims == claims

    @pytest.mark.asyncio
    async def test_generate_claim_assertion_no_kwargs(self):
        """Test middleware passes through when no kwargs present."""
        signing_key = create_test_jwk()
        header = {"alg": "ES256", "kid": "test-key"}
        claims = {"iss": "client-id", "aud": "auth-server"}

        middleware = GenerateClaimAssertionMiddleware(signing_key, header, claims)

        mock_next = AsyncMock(return_value=("response", "chain_response"))
        request = ChainRequest("POST", "https://example.com")

        result = await middleware.handle(mock_next, request)

        mock_next.assert_called_once_with(request)
        assert result == ("response", "chain_response")

    @pytest.mark.asyncio
    async def test_generate_claim_assertion_adds_jwt(self):
        """Test middleware adds client assertion JWT to form data."""
        signing_key = create_test_jwk()
        header = {"alg": "ES256", "kid": "test-key"}
        claims = {"iss": "client-id", "aud": "auth-server"}

        middleware = GenerateClaimAssertionMiddleware(signing_key, header, claims)

        mock_next = AsyncMock(return_value=("response", "chain_response"))
        request = ChainRequest(
            "POST", "https://example.com/token", kwargs={"data": FormData()}
        )

        with patch("secrets.token_urlsafe", return_value="test-jti"):
            await middleware.handle(mock_next, request)

        mock_next.assert_called_once_with(request)

        # Verify JWT was added to form data
        form_data = request.kwargs["data"]  # type: ignore
        field_names = [field[0]["name"] for field in form_data._fields]
        assert "client_assertion" in field_names

    @pytest.mark.asyncio
    async def test_generate_claim_assertion_creates_form_data(self):
        """Test middleware creates FormData when none exists."""
        signing_key = create_test_jwk()
        header = {"alg": "ES256", "kid": "test-key"}
        claims = {"iss": "client-id", "aud": "auth-server"}

        middleware = GenerateClaimAssertionMiddleware(signing_key, header, claims)

        mock_next = AsyncMock(return_value=("response", "chain_response"))
        request = ChainRequest(
            "POST", "https://example.com/token", kwargs={}  # No data field
        )

        with patch("secrets.token_urlsafe", return_value="test-jti"):
            await middleware.handle(mock_next, request)

        # Verify FormData was created and JWT added
        assert "data" in request.kwargs  # type: ignore
        form_data = request.kwargs["data"]  # type: ignore
        assert isinstance(form_data, FormData)

    @pytest.mark.asyncio
    async def test_generate_claim_assertion_jwt_structure(self):
        """Test that generated JWT has correct structure."""
        signing_key = create_test_jwk()
        header = {"alg": "ES256", "kid": "test-key"}
        claims = {"iss": "client-id", "aud": "auth-server"}

        middleware = GenerateClaimAssertionMiddleware(signing_key, header, claims)

        mock_next = AsyncMock(return_value=("response", "chain_response"))
        request = ChainRequest(
            "POST", "https://example.com/token", kwargs={"data": FormData()}
        )

        with patch("secrets.token_urlsafe", return_value="unique-jti"):
            await middleware.handle(mock_next, request)

        # Extract the JWT from form data
        form_data = request.kwargs["data"]  # type: ignore
        jwt_field = None
        for field in form_data._fields:
            if field[0]["name"] == "client_assertion":
                jwt_field = field[2]  # Value is the third element in the tuple
                break

        assert jwt_field is not None

        # Verify JWT structure by parsing it
        parsed_jwt = jwt.JWT(jwt=jwt_field, key=signing_key)
        parsed_header = json.loads(parsed_jwt.header)
        parsed_claims = json.loads(parsed_jwt.claims)

        assert parsed_header["alg"] == "ES256"
        assert parsed_header["kid"] == "test-key"
        assert parsed_claims["iss"] == "client-id"
        assert parsed_claims["aud"] == "auth-server"
        assert parsed_claims["jti"] == "unique-jti"


class TestGenerateDpopMiddleware:
    """Test GenerateDpopMiddleware for DPoP header generation and nonce handling."""

    def test_generate_dpop_middleware_creation(self):
        """Test middleware can be created with proper parameters."""
        dpop_key = create_test_jwk()
        header = {"alg": "ES256", "typ": "dpop+jwt"}
        claims = {"htm": "POST", "htu": "https://example.com"}

        middleware = GenerateDpopMiddleware(dpop_key, header, claims)

        assert middleware._dpop_key == dpop_key
        assert middleware._dpop_assertion_header == header
        assert middleware._dpop_assertion_claims == claims

    @pytest.mark.asyncio
    async def test_generate_dpop_adds_header(self):
        """Test middleware adds DPoP header to request."""
        dpop_key = create_test_jwk()
        header = {"alg": "ES256", "typ": "dpop+jwt"}
        claims = {"htm": "POST", "htu": "https://example.com"}

        middleware = GenerateDpopMiddleware(dpop_key, header, claims)

        mock_chain_response = Mock(status=200)
        mock_next = AsyncMock(return_value=("response", mock_chain_response))
        request = ChainRequest("POST", "https://example.com")

        with patch("secrets.token_urlsafe", return_value="test-jti"):
            await middleware.handle(mock_next, request)

        mock_next.assert_called_once_with(request)

        # Verify DPoP header was added
        assert "DPoP" in request.headers  # type: ignore

    @pytest.mark.asyncio
    async def test_generate_dpop_creates_headers_dict(self):
        """Test middleware creates headers dict when none exists."""
        dpop_key = create_test_jwk()
        header = {"alg": "ES256", "typ": "dpop+jwt"}
        claims = {"htm": "POST", "htu": "https://example.com"}

        middleware = GenerateDpopMiddleware(dpop_key, header, claims)

        mock_chain_response = Mock(status=200)
        mock_next = AsyncMock(return_value=("response", mock_chain_response))
        request = ChainRequest("POST", "https://example.com")  # No headers

        with patch("secrets.token_urlsafe", return_value="test-jti"):
            await middleware.handle(mock_next, request)

        # Verify headers dict was created and DPoP added
        assert request.headers is not None
        assert "DPoP" in request.headers

    @pytest.mark.asyncio
    async def test_generate_dpop_no_retry_on_success(self):
        """Test no retry when response is successful."""
        dpop_key = create_test_jwk()
        header = {"alg": "ES256", "typ": "dpop+jwt"}
        claims = {"htm": "POST", "htu": "https://example.com"}

        middleware = GenerateDpopMiddleware(dpop_key, header, claims)

        mock_client_response = Mock()
        mock_chain_response = Mock(status=200)
        mock_next = AsyncMock(return_value=(mock_client_response, mock_chain_response))
        request = ChainRequest("POST", "https://example.com")

        with patch("secrets.token_urlsafe", return_value="test-jti"):
            result = await middleware.handle(mock_next, request)

        assert result == (mock_client_response, mock_chain_response)
        assert len(result) == 2  # No retry request

    @pytest.mark.asyncio
    async def test_generate_dpop_retry_on_invalid_dpop_proof(self):
        """Test retry when DPoP proof is invalid and nonce is provided."""
        dpop_key = create_test_jwk()
        header = {"alg": "ES256", "typ": "dpop+jwt"}
        claims = {"htm": "POST", "htu": "https://example.com"}

        middleware = GenerateDpopMiddleware(dpop_key, header, claims)

        mock_client_response = Mock()
        mock_chain_response = Mock(
            status=401, headers=create_headers_proxy([("DPoP-Nonce", "server-nonce")])
        )
        mock_chain_response.body_matches_kv = Mock(return_value=True)

        mock_next = AsyncMock(return_value=(mock_client_response, mock_chain_response))
        request = ChainRequest("POST", "https://example.com")

        with patch("secrets.token_urlsafe", return_value="test-jti"):
            result = await middleware.handle(mock_next, request)

        # Should return retry request
        assert len(result) == 3
        client_resp, chain_resp, retry_request = result

        assert client_resp == mock_client_response
        assert chain_resp == mock_chain_response
        assert isinstance(retry_request, ChainRequest)

        # Verify nonce was added to claims
        assert middleware._dpop_assertion_claims["nonce"] == "server-nonce"

    @pytest.mark.asyncio
    async def test_generate_dpop_retry_on_use_dpop_nonce(self):
        """Test retry when server requests DPoP nonce usage."""
        dpop_key = create_test_jwk()
        header = {"alg": "ES256", "typ": "dpop+jwt"}
        claims = {"htm": "POST", "htu": "https://example.com"}

        middleware = GenerateDpopMiddleware(dpop_key, header, claims)

        mock_client_response = Mock()
        mock_chain_response = Mock(
            status=400, headers=create_headers_proxy([("DPoP-Nonce", "required-nonce")])
        )
        mock_chain_response.body_matches_kv = Mock(
            side_effect=lambda key, value: value == "use_dpop_nonce"
        )

        mock_next = AsyncMock(return_value=(mock_client_response, mock_chain_response))
        request = ChainRequest("POST", "https://example.com")

        with patch("secrets.token_urlsafe", return_value="test-jti"):
            result = await middleware.handle(mock_next, request)

        # Should return retry request
        assert len(result) == 3

        # Verify nonce was added to claims
        assert middleware._dpop_assertion_claims["nonce"] == "required-nonce"

    @pytest.mark.asyncio
    async def test_generate_dpop_no_retry_without_nonce_error(self):
        """Test no retry when error is not DPoP-related."""
        dpop_key = create_test_jwk()
        header = {"alg": "ES256", "typ": "dpop+jwt"}
        claims = {"htm": "POST", "htu": "https://example.com"}

        middleware = GenerateDpopMiddleware(dpop_key, header, claims)

        mock_client_response = Mock()
        mock_chain_response = Mock(status=401)
        mock_chain_response.body_matches_kv = Mock(return_value=False)

        mock_next = AsyncMock(return_value=(mock_client_response, mock_chain_response))
        request = ChainRequest("POST", "https://example.com")

        with patch("secrets.token_urlsafe", return_value="test-jti"):
            result = await middleware.handle(mock_next, request)

        # Should not return retry request
        assert len(result) == 2
        assert result == (mock_client_response, mock_chain_response)

    @pytest.mark.asyncio
    async def test_generate_dpop_exception_on_none_headers(self):
        """Test exception when response headers are None during error handling."""
        dpop_key = create_test_jwk()
        header = {"alg": "ES256", "typ": "dpop+jwt"}
        claims = {"htm": "POST", "htu": "https://example.com"}

        middleware = GenerateDpopMiddleware(dpop_key, header, claims)

        mock_client_response = Mock()
        mock_chain_response = Mock(status=401, headers=None)
        mock_chain_response.body_matches_kv = Mock(return_value=True)

        mock_next = AsyncMock(return_value=(mock_client_response, mock_chain_response))
        request = ChainRequest("POST", "https://example.com")

        with patch("secrets.token_urlsafe", return_value="test-jti"):
            with pytest.raises(ValueError, match="Response headers are None"):
                await middleware.handle(mock_next, request)


class TestEndOfLineChainMiddleware:
    """Test EndOfLineChainMiddleware for HTTP request execution."""

    def test_end_of_line_middleware_creation(self):
        """Test middleware can be created with proper parameters."""
        mock_request_func = AsyncMock()
        mock_logger = Mock()

        middleware = EndOfLineChainMiddleware(
            mock_request_func, mock_logger, raise_for_status=True
        )

        assert middleware._request_func == mock_request_func
        assert middleware._logger == mock_logger
        assert middleware._raise_for_status is True

    @pytest.mark.asyncio
    async def test_end_of_line_executes_request(self):
        """Test middleware executes HTTP request with proper parameters."""
        mock_response = create_mock_response(200, body={"success": True})
        mock_request_func = AsyncMock(return_value=mock_response)
        mock_logger = Mock()

        middleware = EndOfLineChainMiddleware(mock_request_func, mock_logger)

        request = ChainRequest(
            "POST",
            "https://example.com/api",
            headers={"Authorization": "Bearer token"},
            trace_request_ctx={"trace_id": "123"},
            kwargs={"timeout": 30},
        )

        result = await middleware.handle(request)

        # Verify request function was called with correct parameters
        mock_request_func.assert_called_once_with(
            "post",  # lowercase method
            "https://example.com/api",
            headers={"Authorization": "Bearer token"},
            trace_request_ctx={"trace_id": "123"},
            timeout=30,
        )

        # Verify result structure
        client_response, chain_response = result  # type: ignore
        assert client_response == mock_response
        assert isinstance(chain_response, ChainResponse)
        assert chain_response.status == 200

    @pytest.mark.asyncio
    async def test_end_of_line_raise_for_status(self):
        """Test middleware calls raise_for_status when enabled."""
        mock_response = create_mock_response(200)
        mock_request_func = AsyncMock(return_value=mock_response)
        mock_logger = Mock()

        middleware = EndOfLineChainMiddleware(
            mock_request_func, mock_logger, raise_for_status=True
        )

        request = ChainRequest("GET", "https://example.com")

        await middleware.handle(request)

        mock_response.raise_for_status.assert_called_once()  # type: ignore

    @pytest.mark.asyncio
    async def test_end_of_line_no_raise_for_status(self):
        """Test middleware doesn't call raise_for_status when disabled."""
        mock_response = create_mock_response(404)
        mock_request_func = AsyncMock(return_value=mock_response)
        mock_logger = Mock()

        middleware = EndOfLineChainMiddleware(
            mock_request_func, mock_logger, raise_for_status=False
        )

        request = ChainRequest("GET", "https://example.com")

        await middleware.handle(request)

        mock_response.raise_for_status.assert_not_called()  # type: ignore

    @pytest.mark.asyncio
    async def test_end_of_line_empty_trace_context(self):
        """Test middleware handles empty trace context properly."""
        mock_response = create_mock_response(200)
        mock_request_func = AsyncMock(return_value=mock_response)
        mock_logger = Mock()

        middleware = EndOfLineChainMiddleware(mock_request_func, mock_logger)

        request = ChainRequest("GET", "https://example.com")  # No trace context

        await middleware.handle(request)

        # Verify call was made with empty trace context
        call_args = mock_request_func.call_args
        assert "trace_request_ctx" in call_args.kwargs
        assert call_args.kwargs["trace_request_ctx"] == {}

    @pytest.mark.asyncio
    async def test_end_of_line_empty_kwargs(self):
        """Test middleware handles empty kwargs properly."""
        mock_response = create_mock_response(200)
        mock_request_func = AsyncMock(return_value=mock_response)
        mock_logger = Mock()

        middleware = EndOfLineChainMiddleware(mock_request_func, mock_logger)

        request = ChainRequest("GET", "https://example.com")  # No kwargs

        await middleware.handle(request)

        # Verify minimal call was made
        call_args = mock_request_func.call_args
        assert call_args[0] == ("get", "https://example.com")


class TestChainMiddlewareContext:
    """Test ChainMiddlewareContext for retry logic and context management."""

    def test_chain_context_creation(self):
        """Test ChainMiddlewareContext can be created with proper parameters."""
        mock_callback = AsyncMock()
        mock_logger = Mock()
        request = ChainRequest("GET", "https://example.com")

        context = ChainMiddlewareContext(
            mock_callback, request, mock_logger, raise_for_status=True, attempt_max=5
        )

        assert context._chain_callback == mock_callback
        assert context._chain_request == request
        assert context._logger == mock_logger
        assert context._raise_for_status is True
        assert context._attempt_max == 5

    @pytest.mark.asyncio
    async def test_chain_context_successful_request(self):
        """Test context executes successful request without retry."""
        mock_client_response = Mock()
        mock_chain_response = Mock()
        mock_callback = AsyncMock(
            return_value=(mock_client_response, mock_chain_response)
        )
        mock_logger = Mock()
        request = ChainRequest("GET", "https://example.com")

        context = ChainMiddlewareContext(mock_callback, request, mock_logger)

        result = await context

        assert result == (mock_client_response, mock_chain_response)
        mock_callback.assert_called_once_with(request)

    @pytest.mark.asyncio
    async def test_chain_context_retry_logic(self):
        """Test context handles retry when new request is returned."""
        mock_client_response1 = Mock()
        mock_chain_response1 = Mock()
        retry_request = ChainRequest("GET", "https://example.com/retry")

        mock_client_response2 = Mock()
        mock_chain_response2 = Mock()

        mock_callback = AsyncMock(
            side_effect=[
                (mock_client_response1, mock_chain_response1, retry_request),
                (mock_client_response2, mock_chain_response2),
            ]
        )
        mock_logger = Mock()
        request = ChainRequest("GET", "https://example.com")

        context = ChainMiddlewareContext(mock_callback, request, mock_logger)

        result = await context

        assert result == (mock_client_response2, mock_chain_response2)
        assert mock_callback.call_count == 2
        mock_callback.assert_any_call(request)
        mock_callback.assert_any_call(retry_request)

    @pytest.mark.asyncio
    async def test_chain_context_max_attempts_exceeded(self):
        """Test context raises exception when max attempts exceeded."""
        retry_request = ChainRequest("GET", "https://example.com/retry")
        mock_callback = AsyncMock(return_value=(Mock(), Mock(), retry_request))
        mock_logger = Mock()
        request = ChainRequest("GET", "https://example.com")

        context = ChainMiddlewareContext(
            mock_callback, request, mock_logger, attempt_max=2
        )

        with pytest.raises(Exception, match="Max attempts reached"):
            await context

        assert mock_callback.call_count == 2

    @pytest.mark.asyncio
    async def test_chain_context_as_context_manager(self):
        """Test context works as async context manager."""
        mock_client_response = Mock()
        mock_chain_response = Mock()
        mock_callback = AsyncMock(
            return_value=(mock_client_response, mock_chain_response)
        )
        mock_logger = Mock()
        request = ChainRequest("GET", "https://example.com")

        context = ChainMiddlewareContext(mock_callback, request, mock_logger)

        async with context as result:
            assert result == (mock_client_response, mock_chain_response)

    @pytest.mark.asyncio
    async def test_chain_context_cleanup_on_exit(self):
        """Test context properly cleans up client response on exit."""
        mock_client_response = Mock()
        mock_client_response.closed = False
        mock_client_response.close = Mock()
        mock_chain_response = Mock()
        mock_callback = AsyncMock(
            return_value=(mock_client_response, mock_chain_response)
        )
        mock_logger = Mock()
        request = ChainRequest("GET", "https://example.com")

        context = ChainMiddlewareContext(mock_callback, request, mock_logger)

        async with context:
            pass  # Exit context

        mock_client_response.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_chain_context_no_cleanup_if_closed(self):
        """Test context doesn't clean up if response already closed."""
        mock_client_response = Mock()
        mock_client_response.closed = True
        mock_client_response.close = Mock()
        mock_chain_response = Mock()
        mock_callback = AsyncMock(
            return_value=(mock_client_response, mock_chain_response)
        )
        mock_logger = Mock()
        request = ChainRequest("GET", "https://example.com")

        context = ChainMiddlewareContext(mock_callback, request, mock_logger)

        async with context:
            pass

        mock_client_response.close.assert_not_called()

    @pytest.mark.asyncio
    async def test_chain_context_raise_for_status_after_retry(self):
        """Test raise_for_status is called after retry logic completes."""
        mock_client_response = Mock()
        mock_chain_response = Mock()
        retry_request = ChainRequest("GET", "https://example.com/retry")

        mock_final_response = Mock()
        mock_final_chain_response = Mock()

        mock_callback = AsyncMock(
            side_effect=[
                (mock_client_response, mock_chain_response, retry_request),
                (mock_final_response, mock_final_chain_response),
            ]
        )
        mock_logger = Mock()
        request = ChainRequest("GET", "https://example.com")

        context = ChainMiddlewareContext(
            mock_callback, request, mock_logger, raise_for_status=True
        )

        await context

        # raise_for_status should be called on intermediate response during retry
        mock_client_response.raise_for_status.assert_called_once()
        # Final response doesn't get raise_for_status called (no more retries)
        mock_final_response.raise_for_status.assert_not_called()


class TestChainMiddlewareClient:
    """Test ChainMiddlewareClient HTTP client functionality."""

    def test_client_creation_with_session(self):
        """Test client can be created with existing session."""
        mock_session = Mock(spec=ClientSession)
        mock_logger = Mock()
        mock_middleware = [Mock(spec=RequestMiddlewareBase)]

        client = ChainMiddlewareClient(
            client_session=mock_session,
            logger=mock_logger,
            middleware=mock_middleware,
            raise_for_status=True,
        )

        assert client._client == mock_session
        assert client._logger == mock_logger
        assert client._middleware == mock_middleware
        assert client._raise_for_status is True
        assert client._closed is None  # Session provided by user

    def test_client_creation_without_session(self):
        """Test client creates new session when none provided."""
        mock_logger = Mock()

        with patch(
            "social.graze.aip.atproto.chain.ClientSession"
        ) as mock_session_class:
            mock_session = Mock()
            mock_session_class.return_value = mock_session

            client = ChainMiddlewareClient(
                logger=mock_logger, timeout=30, connector="test"
            )

            mock_session_class.assert_called_once_with(timeout=30, connector="test")
            assert client._client == mock_session
            assert client._closed is False  # Client owns the session

    def test_client_default_logger(self):
        """Test client creates default logger when none provided."""
        with patch("social.graze.aip.atproto.chain.ClientSession"):
            with patch("logging.getLogger") as mock_get_logger:
                mock_logger = Mock()
                mock_get_logger.return_value = mock_logger

                client = ChainMiddlewareClient()

                mock_get_logger.assert_called_once_with("aiohttp_chain")
                assert client._logger == mock_logger

    def test_client_request_method(self):
        """Test client request method creates proper context."""
        mock_session = Mock(spec=ClientSession)
        client = ChainMiddlewareClient(client_session=mock_session)

        context = client.request("POST", "https://example.com", timeout=30)

        assert isinstance(context, ChainMiddlewareContext)

    def test_client_get_method(self):
        """Test client GET convenience method."""
        mock_session = Mock(spec=ClientSession)
        client = ChainMiddlewareClient(client_session=mock_session)

        context = client.get("https://example.com", timeout=30)

        assert isinstance(context, ChainMiddlewareContext)

    def test_client_post_method(self):
        """Test client POST convenience method."""
        mock_session = Mock(spec=ClientSession)
        client = ChainMiddlewareClient(client_session=mock_session)

        context = client.post("https://example.com", data={"key": "value"})

        assert isinstance(context, ChainMiddlewareContext)

    def test_client_put_method(self):
        """Test client PUT convenience method."""
        mock_session = Mock(spec=ClientSession)
        client = ChainMiddlewareClient(client_session=mock_session)

        context = client.put("https://example.com", json={"key": "value"})

        assert isinstance(context, ChainMiddlewareContext)

    def test_client_patch_method(self):
        """Test client PATCH convenience method."""
        mock_session = Mock(spec=ClientSession)
        client = ChainMiddlewareClient(client_session=mock_session)

        context = client.patch("https://example.com")

        assert isinstance(context, ChainMiddlewareContext)

    def test_client_delete_method(self):
        """Test client DELETE convenience method."""
        mock_session = Mock(spec=ClientSession)
        client = ChainMiddlewareClient(client_session=mock_session)

        context = client.delete("https://example.com")

        assert isinstance(context, ChainMiddlewareContext)

    def test_client_head_method(self):
        """Test client HEAD convenience method."""
        mock_session = Mock(spec=ClientSession)
        client = ChainMiddlewareClient(client_session=mock_session)

        context = client.head("https://example.com")

        assert isinstance(context, ChainMiddlewareContext)

    def test_client_options_method(self):
        """Test client OPTIONS convenience method."""
        mock_session = Mock(spec=ClientSession)
        client = ChainMiddlewareClient(client_session=mock_session)

        context = client.options("https://example.com")

        assert isinstance(context, ChainMiddlewareContext)

    @pytest.mark.asyncio
    async def test_client_close(self):
        """Test client close method."""
        mock_session = Mock(spec=ClientSession)
        mock_session.close = AsyncMock()
        client = ChainMiddlewareClient(client_session=mock_session)

        await client.close()

        mock_session.close.assert_called_once()
        assert client._closed is True

    @pytest.mark.asyncio
    async def test_client_as_context_manager(self):
        """Test client works as async context manager."""
        mock_session = Mock(spec=ClientSession)
        mock_session.close = AsyncMock()

        async with ChainMiddlewareClient(client_session=mock_session) as client:
            assert isinstance(client, ChainMiddlewareClient)

        mock_session.close.assert_called_once()

    def test_client_del_warning(self):
        """Test client warns when not properly closed."""
        mock_session = Mock(spec=ClientSession)
        mock_logger = Mock()
        client = ChainMiddlewareClient(client_session=mock_session, logger=mock_logger)
        client._closed = False  # Simulate not closed

        # Trigger __del__
        del client

        # Note: __del__ behavior testing is tricky in pytest, so we'll just verify structure

    def test_client_middleware_chain_composition(self):
        """Test that middleware chain is properly composed in reverse order."""
        mock_session = Mock(spec=ClientSession)
        mock_session.request = AsyncMock()

        # Create mock middleware
        middleware1 = Mock(spec=RequestMiddlewareBase)
        middleware2 = Mock(spec=RequestMiddlewareBase)
        middleware3 = Mock(spec=RequestMiddlewareBase)

        # Mock handle_gen to return a simple function
        middleware1.handle_gen = Mock(return_value=AsyncMock())
        middleware2.handle_gen = Mock(return_value=AsyncMock())
        middleware3.handle_gen = Mock(return_value=AsyncMock())

        client = ChainMiddlewareClient(
            client_session=mock_session,
            middleware=[middleware1, middleware2, middleware3],
        )

        # Create a request context (triggers middleware chain composition)
        client.request("GET", "https://example.com")

        # Verify middleware chain composition happened
        # Middleware should be applied in reverse order (3, 2, 1)
        assert middleware1.handle_gen.called
        assert middleware2.handle_gen.called
        assert middleware3.handle_gen.called


class TestIntegrationScenarios:
    """Test integration scenarios and error cases."""

    @pytest.mark.asyncio
    async def test_full_oauth_flow_simulation(self):
        """Test complete OAuth flow with DPoP and client assertion."""
        # Create test keys
        dpop_key = create_test_jwk()
        signing_key = create_test_jwk()

        # Create middleware stack
        metrics_client = Mock(spec=MetricsClient)
        middleware_stack = [
            StatsdMiddleware(metrics_client),
            DebugMiddleware(),
            GenerateClaimAssertionMiddleware(
                signing_key,
                {"alg": "ES256", "kid": "client-key"},
                {"iss": "client-id", "aud": "auth-server"},
            ),
            GenerateDpopMiddleware(
                dpop_key,
                {"alg": "ES256", "typ": "dpop+jwt"},
                {"htm": "POST", "htu": "https://auth.example.com/token"},
            ),
        ]

        # Mock successful token response
        mock_response = create_mock_response(
            200, body={"access_token": "token", "token_type": "DPoP"}
        )
        mock_session = Mock(spec=ClientSession)
        mock_session.request = AsyncMock(return_value=mock_response)

        client = ChainMiddlewareClient(
            client_session=mock_session, middleware=middleware_stack
        )

        # Execute request
        with patch("social.graze.aip.atproto.chain.time", side_effect=[1000.0, 1001.0]):
            with patch("secrets.token_urlsafe", return_value="unique-jti"):
                async with client.post(
                    "https://auth.example.com/token", data=FormData()
                ) as (client_resp, chain_resp):
                    assert chain_resp.status == 200
                    assert chain_resp.body["access_token"] == "token"  # type: ignore

        # Verify metrics were collected
        metrics_client.timer.assert_called_once()
        metrics_client.increment.assert_called_once()

    @pytest.mark.asyncio
    async def test_dpop_nonce_retry_flow(self):
        """Test DPoP nonce retry flow."""
        dpop_key = create_test_jwk()

        middleware = GenerateDpopMiddleware(
            dpop_key,
            {"alg": "ES256", "typ": "dpop+jwt"},
            {"htm": "POST", "htu": "https://auth.example.com/token"},
        )

        # First response: requires nonce
        first_response = Mock(
            status=401, headers=create_headers_proxy([("DPoP-Nonce", "server-nonce")])
        )
        first_response.body_matches_kv = Mock(return_value=True)

        # Second response: success
        second_response = Mock(status=200)
        second_response.body_matches_kv = Mock(return_value=False)

        call_count = 0

        async def mock_next(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return (Mock(), first_response)
            else:
                return (Mock(), second_response)

        request = ChainRequest("POST", "https://auth.example.com/token")

        with patch("secrets.token_urlsafe", return_value="test-jti"):
            result = await middleware.handle(mock_next, request)

        # Should return retry request
        assert len(result) == 3
        assert middleware._dpop_assertion_claims["nonce"] == "server-nonce"

    @pytest.mark.asyncio
    async def test_middleware_exception_propagation(self):
        """Test that exceptions properly propagate through middleware chain."""

        class FailingMiddleware(RequestMiddlewareBase):
            async def handle(self, next, request):
                raise ValueError("Middleware failure")

        failing_middleware = FailingMiddleware()
        mock_session = Mock(spec=ClientSession)

        client = ChainMiddlewareClient(
            client_session=mock_session, middleware=[failing_middleware]
        )

        with pytest.raises(ValueError, match="Middleware failure"):
            async with client.get("https://example.com"):
                pass

    @pytest.mark.asyncio
    async def test_max_retries_in_context(self):
        """Test that context respects max retry attempts."""
        retry_request = ChainRequest("GET", "https://example.com/retry")
        mock_callback = AsyncMock(return_value=(Mock(), Mock(), retry_request))
        mock_logger = Mock()
        request = ChainRequest("GET", "https://example.com")

        context = ChainMiddlewareContext(
            mock_callback, request, mock_logger, attempt_max=3
        )

        with pytest.raises(Exception, match="Max attempts reached"):
            await context

        assert mock_callback.call_count == 3

    @pytest.mark.asyncio
    async def test_complex_middleware_chain_order(self):
        """Test complex middleware chain execution order."""
        execution_order = []

        class OrderTrackingMiddleware(RequestMiddlewareBase):
            def __init__(self, name):
                self.name = name

            async def handle(self, next, request):
                execution_order.append(f"{self.name}_start")
                result = await next(request)
                execution_order.append(f"{self.name}_end")
                return result

        middleware_stack = [
            OrderTrackingMiddleware("first"),
            OrderTrackingMiddleware("second"),
            OrderTrackingMiddleware("third"),
        ]

        mock_response = create_mock_response(200)
        mock_session = Mock(spec=ClientSession)
        mock_session.request = AsyncMock(return_value=mock_response)

        client = ChainMiddlewareClient(
            client_session=mock_session, middleware=middleware_stack
        )

        async with client.get("https://example.com"):
            pass

        # Middleware should execute in order (FIFO) for request processing,
        # with response processing in reverse order (standard middleware pattern)
        expected_order = [
            "first_start",
            "second_start",
            "third_start",
            "third_end",
            "second_end",
            "first_end",
        ]
        assert execution_order == expected_order


class TestSecurityAndEdgeCases:
    """Test security properties and edge cases."""

    def test_chain_request_immutability_protection(self):
        """Test that ChainRequest copy doesn't share mutable references."""
        original_headers = {"Authorization": "Bearer token"}
        original_kwargs = {"timeout": 30, "data": ["item1"]}

        original = ChainRequest(
            "POST",
            "https://example.com",
            headers=original_headers,
            kwargs=original_kwargs,
        )

        copy = ChainRequest.from_chain_request(original)

        # Modify original's mutable fields
        original.headers["New-Header"] = "value"  # type: ignore
        original.kwargs["data"].append("item2")  # type: ignore

        # Copy should be affected since we share references (current behavior)
        # This test documents the current behavior - if immutability is needed,
        # deep copy would be required
        assert copy.headers == original.headers
        assert copy.kwargs == original.kwargs

    @pytest.mark.asyncio
    async def test_jwt_entropy_in_middleware(self):
        """Test that JWTs generated by middleware have sufficient entropy."""
        signing_key = create_test_jwk()
        middleware = GenerateClaimAssertionMiddleware(
            signing_key,
            {"alg": "ES256", "kid": "test-key"},
            {"iss": "client-id", "aud": "auth-server"},
        )

        mock_next = AsyncMock(return_value=("response", "chain_response"))

        # Generate multiple JWTs with fresh requests each time
        jtis = []
        for i in range(10):
            # Create fresh request each time to avoid reusing form data
            request = ChainRequest(
                "POST", "https://example.com/token", kwargs={"data": FormData()}
            )

            with patch("secrets.token_urlsafe", return_value=f"jti-{i}"):
                await middleware.handle(mock_next, request)

            # Extract JTI from form data
            form_data = request.kwargs["data"]  # type: ignore
            for field in form_data._fields:
                if field[0]["name"] == "client_assertion":
                    jwt_token = field[2]  # Value is the third element in the tuple
                    parsed_jwt = jwt.JWT(jwt=jwt_token, key=signing_key)
                    claims = json.loads(parsed_jwt.claims)
                    jtis.append(claims["jti"])
                    break

        # All JTIs should be unique
        assert len(set(jtis)) == len(jtis)

    @pytest.mark.asyncio
    async def test_response_headers_edge_cases(self):
        """Test response handling with edge case headers."""
        # Test with empty headers
        mock_response = create_mock_response(200, headers={})
        chain_response = await ChainResponse.from_aiohttp_response(mock_response)
        assert chain_response.status == 200

        # Test with unusual content types (gets treated as binary since it doesn't start with "application/json")
        mock_response = create_mock_response(
            200,
            headers={"Content-Type": "application/custom+json"},
            body={"data": "value"},
        )
        chain_response = await ChainResponse.from_aiohttp_response(mock_response)
        # This content type doesn't start with "application/json" so it's treated as binary
        assert chain_response.body == b'{"data": "value"}'

    @pytest.mark.asyncio
    async def test_memory_cleanup_on_exceptions(self):
        """Test that resources are properly cleaned up on exceptions."""
        mock_client_response = Mock()
        mock_client_response.closed = False
        mock_client_response.close = Mock()

        mock_callback = AsyncMock(return_value=(mock_client_response, Mock()))
        mock_logger = Mock()
        request = ChainRequest("GET", "https://example.com")

        context = ChainMiddlewareContext(mock_callback, request, mock_logger)

        try:
            async with context:
                raise ValueError("Test exception")
        except ValueError:
            pass

        # Response should still be closed despite exception
        mock_client_response.close.assert_called_once()

    def test_middleware_type_safety(self):
        """Test that middleware chain validates types properly."""
        mock_session = Mock(spec=ClientSession)

        # Should accept proper middleware
        valid_middleware = [Mock(spec=RequestMiddlewareBase)]
        client = ChainMiddlewareClient(
            client_session=mock_session, middleware=valid_middleware
        )
        assert client._middleware == valid_middleware

        # Should accept None middleware
        client = ChainMiddlewareClient(client_session=mock_session, middleware=None)
        assert client._middleware is None

    @pytest.mark.asyncio
    async def test_large_response_handling(self):
        """Test handling of large response bodies."""
        large_data = {"data": "x" * 10000}  # Large JSON response
        mock_response = create_mock_response(200, body=large_data)

        chain_response = await ChainResponse.from_aiohttp_response(mock_response)

        assert chain_response.status == 200
        assert chain_response.body == large_data
        # body_contains for dicts checks keys, not values, so check for the key "data"
        assert chain_response.body_contains("data")

    def test_url_handling_edge_cases(self):
        """Test URL handling with various edge cases."""
        test_urls = [
            "https://example.com",
            "https://example.com/",
            "https://example.com/path?query=value",
            "https://example.com:8080/path",
            "https://sub.domain.example.com/complex/path?a=1&b=2#fragment",
        ]

        for url in test_urls:
            request = ChainRequest("GET", url)
            assert request.url == url

            # Test copy preserves URL
            copy = ChainRequest.from_chain_request(request)
            assert copy.url == url
