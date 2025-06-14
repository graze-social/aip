"""Middleware chain infrastructure for AT Protocol HTTP requests.

Provides a flexible middleware chain pattern for AT Protocol requests with support
for OAuth 2.0 client assertions, DPoP (Demonstration of Proof-of-Possession),
StatsD telemetry, and request/response transformation.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
import json
import secrets
from time import time
from types import TracebackType
from typing import (
    Any,
    Awaitable,
    Callable,
    Generator,
    Optional,
    Sequence,
    Tuple,
    Union,
    Protocol,
    Dict,
)
import logging
from aiohttp import web, ClientResponse, ClientSession, FormData, hdrs
from aiohttp.typedefs import StrOrURL
from multidict import CIMultiDictProxy
from jwcrypto import jwt, jwk
import sentry_sdk

from social.graze.aip.app.metrics import MetricsClient

RequestFunc = Callable[..., Awaitable[ClientResponse]]
"""Type alias for async HTTP request functions."""

logger = logging.getLogger(__name__)


class _LoggerStub(Protocol):
    """_Logger defines which methods logger object should have."""

    @abstractmethod
    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        pass

    @abstractmethod
    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        pass

    @abstractmethod
    def exception(self, msg: str, *args: Any, **kwargs: Any) -> None:
        pass


_LoggerType = Union[_LoggerStub, logging.Logger]


@dataclass
class ChainRequest:
    """Encapsulates HTTP request data for middleware chain processing."""

    method: str
    url: StrOrURL
    headers: dict[str, Any] | None = None
    trace_request_ctx: dict[str, Any] | None = None
    kwargs: dict[str, Any] | None = None

    @staticmethod
    def from_chain_request(request: "ChainRequest") -> "ChainRequest":
        """Create a copy of an existing ChainRequest."""
        return ChainRequest(
            method=request.method,
            url=request.url,
            headers=request.headers,
            trace_request_ctx=request.trace_request_ctx,
            kwargs=request.kwargs,
        )


@dataclass
class ChainResponse:
    """Encapsulates HTTP response data from middleware chain processing."""

    status: int
    headers: CIMultiDictProxy[str]
    body: str | bytes | dict[str, Any] | None = None
    # exception: BaseException | None = None

    @staticmethod
    async def from_aiohttp_response(response: ClientResponse) -> "ChainResponse":
        """Convert aiohttp ClientResponse to ChainResponse with proper content handling."""
        status = response.status
        headers = response.headers

        content_type = response.headers.get(hdrs.CONTENT_TYPE, "")

        if content_type.startswith("application/json"):
            return ChainResponse(
                status=status, headers=headers, body=await response.json()
            )
        elif content_type.startswith("text/"):
            return ChainResponse(
                status=status, headers=headers, body=await response.text()
            )
        else:
            return ChainResponse(
                status=status, headers=headers, body=await response.read()
            )

    def body_contains(self, text: str) -> bool:
        """Check if response body contains specified text."""
        if self.body is None:
            return False

        if isinstance(self.body, str):
            return text in self.body

        elif isinstance(self.body, bytes):
            return text.encode("utf-8") in self.body

        elif isinstance(self.body, dict):
            return text in self.body

        return False

    def body_matches_kv(self, key: str, value: Any) -> bool:
        """Check if response body dict contains specific key-value pair."""
        if self.body is None:
            return False

        return (
            isinstance(self.body, dict) and key in self.body and self.body[key] == value
        )

    def to_web_response(self) -> web.Response:
        """Convert ChainResponse to aiohttp web.Response."""
        rargs = {
            "status": self.status,
            "headers": {"Content-Type": self.headers.get(hdrs.CONTENT_TYPE, "")},
        }
        if isinstance(self.body, str):
            rargs["text"] = self.body
        elif isinstance(self.body, bytes):
            rargs["body"] = self.body
        elif isinstance(self.body, dict):
            rargs["body"] = json.dumps(self.body)
        return web.Response(**rargs)


NextChainResponseCallbackType = (
    Tuple[ClientResponse, ChainResponse]
    | Tuple[ClientResponse, ChainResponse, ChainRequest]
)
"""Response type from middleware chain callbacks.

Can optionally include a new ChainRequest for retries.
"""

NextChainCallbackType = Callable[
    [ChainRequest], Awaitable[NextChainResponseCallbackType]
]
"""Type alias for middleware chain callback functions."""


class RequestMiddlewareBase(ABC):
    """Abstract base class for middleware chain components."""

    @abstractmethod
    async def handle(
        self, next: NextChainCallbackType, request: ChainRequest
    ) -> NextChainResponseCallbackType:
        """Process request through middleware chain.

        Args:
            next: Next middleware callback in chain
            request: Request to process

        Returns:
            Response tuple, optionally with retry request
        """
        pass

    def handle_gen(self, next: NextChainCallbackType) -> NextChainCallbackType:
        """Generate middleware callback for chain composition."""

        async def next_invoke(request: ChainRequest) -> NextChainResponseCallbackType:
            return await self.handle(next, request)

        return next_invoke


class StatsdMiddleware(RequestMiddlewareBase):
    """Middleware for collecting request timing and count metrics via metrics abstraction layer.
    
    This middleware supports multiple metrics backends (OTEL, Telegraf, NoOp) through
    the MetricsClient interface, providing vendor-agnostic telemetry collection for
    HTTP client requests in the middleware chain.
    """

    def __init__(
        self,
        metrics_client: MetricsClient,
    ) -> None:
        """Initialize with metrics client for telemetry collection."""
        super().__init__()
        self._metrics_client = metrics_client

    async def handle(
        self, next: NextChainCallbackType, request: ChainRequest
    ) -> NextChainResponseCallbackType:
        start_time = time()
        try:
            return await next(request)
        except Exception as e:
            sentry_sdk.capture_exception(e)
            raise e
        finally:
            self._metrics_client.timer(
                "aip.client.request.time",
                time() - start_time,
                tag_dict={
                    "method": request.method.lower(),
                },
            )
            self._metrics_client.increment(
                "aip.client.request.count",
                1,
                tag_dict={
                    "method": request.method.lower(),
                },
            )


class DebugMiddleware(RequestMiddlewareBase):
    """Middleware for debug logging of requests and responses."""

    async def handle(
        self, next: NextChainCallbackType, request: ChainRequest
    ) -> NextChainResponseCallbackType:
        logger.debug(
            f"Request: {request.method} {request.url} {request.headers} {request.kwargs}"
        )
        response = await next(request)
        logger.debug(
            f"Response: {response[1].status} {response[1].headers} {response[1].body}"
        )
        return response


class GenerateClaimAssertionMiddleware(RequestMiddlewareBase):
    """Middleware for generating OAuth 2.0 client assertion JWTs."""

    def __init__(
        self,
        signing_key: jwk.JWK,
        client_assertion_header: Dict[str, Any],
        client_assertion_claims: Dict[str, Any],
    ) -> None:
        """Initialize with JWT signing key and assertion parameters."""
        super().__init__()
        self._signing_key = signing_key
        self._client_assertion_header = client_assertion_header
        self._client_assertion_claims = client_assertion_claims

    async def handle(
        self, next: NextChainCallbackType, request: ChainRequest
    ) -> NextChainResponseCallbackType:

        if request.kwargs is None:
            return await next(request)

        self._client_assertion_claims["jti"] = secrets.token_urlsafe(32)
        claims_assertation = jwt.JWT(
            header=self._client_assertion_header,
            claims=self._client_assertion_claims,
        )
        claims_assertation.make_signed_token(self._signing_key)
        claims_assertation_token = claims_assertation.serialize()

        data: Optional[FormData] = None
        if request.kwargs is not None:
            data = request.kwargs.get("data", None)

        if data is None:
            data = FormData()

        data.add_field("client_assertion", claims_assertation_token)

        request.kwargs["data"] = data

        return await next(request)


class GenerateDpopMiddleware(RequestMiddlewareBase):
    """Middleware for generating DPoP (Demonstration of Proof-of-Possession) headers.

    Handles DPoP nonce challenges for enhanced OAuth 2.0 security.
    """

    def __init__(
        self,
        dpop_key: jwk.JWK,
        dop_assertion_header: Dict[str, Any],
        dop_assertion_claims: Dict[str, Any],
    ) -> None:
        """Initialize with DPoP key and assertion parameters."""
        super().__init__()
        self._dpop_key = dpop_key
        self._dpop_assertion_header = dop_assertion_header
        self._dpop_assertion_claims = dop_assertion_claims

    async def handle(
        self, next: NextChainCallbackType, request: ChainRequest
    ) -> NextChainResponseCallbackType:
        self._dpop_assertion_claims["jti"] = secrets.token_urlsafe(32)

        dpop_assertation = jwt.JWT(
            header=self._dpop_assertion_header,
            claims=self._dpop_assertion_claims,
        )
        dpop_assertation.make_signed_token(self._dpop_key)
        dpop_assertation_token = dpop_assertation.serialize()

        if request.headers is None:
            request.headers = {}
        request.headers["DPoP"] = dpop_assertation_token

        response = await next(request)
        client_response = response[0]
        chain_response = response[1]
        new_request = None
        if len(response) == 3:
            new_request = response[2]

        if chain_response.status == 401 or chain_response.status == 400:
            if chain_response.headers is None:
                raise ValueError("Response headers are None")

            if chain_response.body_matches_kv(
                "error", "invalid_dpop_proof"
            ) or chain_response.body_matches_kv("error", "use_dpop_nonce"):
                self._dpop_assertion_claims["nonce"] = chain_response.headers.get(
                    "DPoP-Nonce", ""
                )

                if new_request is None:
                    new_request = ChainRequest.from_chain_request(request)

        if new_request is None:
            return client_response, chain_response
        return client_response, chain_response, new_request


class EndOfLineChainMiddleware:
    """Terminal middleware that executes the actual HTTP request."""

    def __init__(
        self,
        request_func: RequestFunc,
        logger: _LoggerType,
        raise_for_status: bool = False,
    ) -> None:
        """Initialize with request function and error handling options."""
        super().__init__()
        self._request_func = request_func
        self._raise_for_status = raise_for_status
        self._logger = logger

    async def handle(self, request: ChainRequest) -> NextChainResponseCallbackType:
        """Execute HTTP request and convert response to ChainResponse."""
        response: ClientResponse = await self._request_func(
            request.method.lower(),
            request.url,
            headers=request.headers,
            trace_request_ctx={
                **(request.trace_request_ctx or {}),
            },
            **(request.kwargs or {}),
        )

        if self._raise_for_status:
            response.raise_for_status()

        return response, await ChainResponse.from_aiohttp_response(response)


class ChainMiddlewareContext:
    """Context manager for executing middleware chain with retry logic."""

    def __init__(
        self,
        chain_callback: NextChainCallbackType,
        chain_request: ChainRequest,
        logger: _LoggerType,
        raise_for_status: bool = False,
        attempt_max: int = 3,
    ) -> None:
        """Initialize context with chain callback and retry parameters."""
        self._chain_callback = chain_callback
        self._chain_request = chain_request
        self._logger = logger
        self._raise_for_status = raise_for_status

        self._chain_response: ChainResponse | None = None
        self.client_response: ClientResponse | None = None

        self._attempt_max = attempt_max

    async def _do_request(self) -> Tuple[ClientResponse, ChainResponse]:
        current_attempt = 0

        chain_request = self._chain_request

        while True:
            current_attempt += 1

            if current_attempt > self._attempt_max:
                raise Exception("Max attempts reached")

            response = await self._chain_callback(chain_request)
            client_response = response[0]
            chain_response = response[1]
            new_request = None
            if len(response) == 3:
                new_request = response[2]

            self._chain_response = chain_response
            self.client_response = client_response

            if new_request is None:
                return client_response, chain_response

            chain_request = new_request

            if self._raise_for_status:
                client_response.raise_for_status()

    def __await__(self) -> Generator[Any, None, Tuple[ClientResponse, ChainResponse]]:
        return self.__aenter__().__await__()

    async def __aenter__(self) -> Tuple[ClientResponse, ChainResponse]:
        return await self._do_request()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self.client_response is not None and not self.client_response.closed:
            self.client_response.close()


class ChainMiddlewareClient:
    """HTTP client with configurable middleware chain for AT Protocol requests.

    Provides HTTP methods with middleware processing for OAuth 2.0, DPoP,
    telemetry, and request transformation.
    """

    def __init__(
        self,
        client_session: ClientSession | None = None,
        logger: _LoggerType | None = None,
        middleware: Sequence[RequestMiddlewareBase] | None = None,
        raise_for_status: bool = False,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """Initialize client with optional middleware chain and session."""
        if client_session is not None:
            client = client_session
            closed = None
        else:
            client = ClientSession(*args, **kwargs)
            closed = False

        self._middleware = middleware

        self._client = client
        self._closed = closed

        self._logger: _LoggerType = logger or logging.getLogger("aiohttp_chain")
        self._raise_for_status = raise_for_status

    def request(
        self,
        method: str,
        url: StrOrURL,
        raise_for_status: bool | None = None,
        **kwargs: Any,
    ) -> ChainMiddlewareContext:
        """Make HTTP request with specified method through middleware chain."""
        return self._make_request(
            method=method,
            url=url,
            **kwargs,
        )

    def get(
        self,
        url: StrOrURL,
        raise_for_status: bool | None = None,
        **kwargs: Any,
    ) -> ChainMiddlewareContext:
        return self._make_request(
            method=hdrs.METH_GET,
            url=url,
            **kwargs,
        )

    def options(
        self,
        url: StrOrURL,
        raise_for_status: bool | None = None,
        **kwargs: Any,
    ) -> ChainMiddlewareContext:
        return self._make_request(
            method=hdrs.METH_OPTIONS,
            url=url,
            **kwargs,
        )

    def head(
        self,
        url: StrOrURL,
        raise_for_status: bool | None = None,
        **kwargs: Any,
    ) -> ChainMiddlewareContext:
        return self._make_request(
            method=hdrs.METH_HEAD,
            url=url,
            **kwargs,
        )

    def post(
        self,
        url: StrOrURL,
        raise_for_status: bool | None = None,
        **kwargs: Any,
    ) -> ChainMiddlewareContext:
        return self._make_request(
            method=hdrs.METH_POST,
            url=url,
            **kwargs,
        )

    def put(
        self,
        url: StrOrURL,
        raise_for_status: bool | None = None,
        **kwargs: Any,
    ) -> ChainMiddlewareContext:
        return self._make_request(
            method=hdrs.METH_PUT,
            url=url,
            **kwargs,
        )

    def patch(
        self,
        url: StrOrURL,
        raise_for_status: bool | None = None,
        **kwargs: Any,
    ) -> ChainMiddlewareContext:
        return self._make_request(
            method=hdrs.METH_PATCH,
            url=url,
            **kwargs,
        )

    def delete(
        self,
        url: StrOrURL,
        raise_for_status: bool | None = None,
        **kwargs: Any,
    ) -> ChainMiddlewareContext:
        return self._make_request(
            method=hdrs.METH_DELETE,
            url=url,
            **kwargs,
        )

    async def close(self) -> None:
        """Close underlying HTTP session."""
        await self._client.close()
        self._closed = True

    def _make_request(
        self,
        method: str,
        url: StrOrURL,
        raise_for_status: bool | None = None,
        **kwargs: Any,
    ) -> ChainMiddlewareContext:
        chain_request = ChainRequest(
            method=method,
            url=url,
            headers=kwargs.pop("headers", {}),
            trace_request_ctx=kwargs.pop("trace_request_ctx", None),
            kwargs=kwargs,
        )

        if raise_for_status is None:
            raise_for_status = self._raise_for_status

        end_of_line_middleware = EndOfLineChainMiddleware(
            request_func=self._client.request,
            logger=self._logger,
            raise_for_status=raise_for_status,
        )

        chain_callback: NextChainCallbackType = end_of_line_middleware.handle

        full_middleware_chain = reversed(self._middleware or [])

        for mw in full_middleware_chain:
            chain_callback = mw.handle_gen(chain_callback)

        return ChainMiddlewareContext(
            chain_callback=chain_callback,
            chain_request=chain_request,
            logger=self._logger,
            raise_for_status=raise_for_status,
        )

    async def __aenter__(self) -> "ChainMiddlewareClient":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.close()

    def __del__(self) -> None:
        if getattr(self, "_closed", None) is None:
            # in case object was not initialized (__init__ raised an exception)
            return

        if not self._closed:
            self._logger.warning("Aiohttp chain client was not closed")
