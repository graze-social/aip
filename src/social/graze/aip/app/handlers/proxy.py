from datetime import datetime, timezone
import logging
from time import time
from typing import (
    List,
    Optional,
    Dict,
    Any,
)
from aiohttp import web
import hashlib
import base64
from jwcrypto import jwk
import sentry_sdk
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from social.graze.aip.app.config import (
    DatabaseSessionMakerAppKey,
    SessionAppKey,
    SettingsAppKey,
    TelegrafStatsdClientAppKey,
)
from social.graze.aip.app.handlers.helpers import auth_token_helper
from social.graze.aip.atproto.chain import (
    ChainMiddlewareClient,
    DebugMiddleware,
    GenerateDpopMiddleware,
    RequestMiddlewareBase,
    StatsdMiddleware,
)

logger = logging.getLogger(__name__)


async def handle_xrpc_proxy(request: web.Request) -> web.Response:
    statsd_client = request.app[TelegrafStatsdClientAppKey]

    # TODO: Validate this against an allowlist.
    xrpc_method: Optional[str] = request.match_info.get("method", None)
    if xrpc_method is None:
        statsd_client.increment("aip.proxy.invalid_method", 1)
        return web.json_response(status=400, data={"error": "Invalid XRPC method"})

    database_session_maker = request.app[DatabaseSessionMakerAppKey]

    try:
        async with (database_session_maker() as database_session,):
            # TODO: Allow optional auth here.
            auth_token = await auth_token_helper(
                database_session, statsd_client, request
            )
            if auth_token is None:
                statsd_client.increment(
                    "aip.proxy.unauthorized", 1, tag_dict={"method": xrpc_method}
                )
                return web.json_response(status=401, data={"error": "Not Authorized"})
    except web.HTTPException as e:
        sentry_sdk.capture_exception(e)
        raise e
    except Exception as e:
        sentry_sdk.capture_exception(e)
        statsd_client.increment(
            "aip.proxy.exception",
            1,
            tag_dict={"exception": type(e).__name__, "method": xrpc_method},
        )
        return web.json_response(status=500, data={"error": "Internal Server Error"})

    now = datetime.now(timezone.utc)

    # TODO: Look for endpoint header and fallback to context PDS value.
    # TODO: Support more complex URLs that include prefixes and or suffixes.
    parsed_destination = urlparse(f"{auth_token.context_service}/xrpc/{xrpc_method}")
    parsed_destination_query = dict(parse_qsl(request.query_string))
    parsed_destination = parsed_destination._replace(
        query=urlencode(parsed_destination_query)
    )
    xrpc_url = urlunparse(parsed_destination)

    http_session = request.app[SessionAppKey]

    headers = {
        "Content-Type": request.headers.get("Content-Type", "application/json"),
    }

    chain_middleware: List[RequestMiddlewareBase] = [StatsdMiddleware(statsd_client)]

    # App password sessions use the `Authorization` header with `Bearer` scheme.
    if auth_token.app_password_session is not None:
        headers["Authorization"] = (
            f"Bearer {auth_token.app_password_session.access_token}"
        )

    # OAuth sessions use the `Authorization` header with `DPoP` scheme.
    elif (
        auth_token.app_password_session is None and auth_token.oauth_session is not None
    ):
        hashed_access_token = hashlib.sha256(
            str(auth_token.oauth_session.access_token).encode("ascii")
        ).digest()
        encoded_hashed_access_token = base64.urlsafe_b64encode(hashed_access_token)
        pkcs_access_token = encoded_hashed_access_token.decode("ascii").rstrip("=")

        dpop_key = jwk.JWK(**auth_token.oauth_session.dpop_jwk)
        dpop_key_public_key = dpop_key.export_public(as_dict=True)
        dpop_assertation_header = {
            "alg": "ES256",
            "jwk": dpop_key_public_key,
            "typ": "dpop+jwt",
        }
        dpop_assertation_claims = {
            "htm": request.method,
            "htu": f"{auth_token.context_service}/xrpc/{xrpc_method}",
            "iat": int(now.timestamp()) - 1,
            "exp": int(now.timestamp()) + 30,
            "nonce": "tmp",
            "ath": pkcs_access_token,
            "iss": f"{auth_token.oauth_session.issuer}",
        }

        headers["Authorization"] = f"DPoP {auth_token.oauth_session.access_token}"

        chain_middleware.append(
            GenerateDpopMiddleware(
                dpop_key,
                dpop_assertation_header,
                dpop_assertation_claims,
            )
        )

    settings = request.app[SettingsAppKey]
    if settings.debug:
        chain_middleware.append(DebugMiddleware())

    rargs: Dict[str, Any] = {}

    if request.method == "POST":
        rargs["data"] = await request.read()

    chain_client = ChainMiddlewareClient(
        client_session=http_session, raise_for_status=False, middleware=chain_middleware
    )

    start_time = time()
    cross_subject = auth_token.guid != auth_token.context_guid
    auth_method = "anonymous"
    if auth_token.app_password_session is not None:
        auth_method = "app-password"
    elif (
        auth_token.oauth_session is not None and auth_token.app_password_session is None
    ):
        auth_method = "oauth"

    try:
        async with chain_client.request(
            request.method, xrpc_url, raise_for_status=None, headers=headers, **rargs
        ) as (
            client_response,
            chain_response,
        ):
            # TODO: Figure out if websockets or SSE support is needed. Gut says no.
            # TODO: Think about using a header like `X-AIP-Error` for additional error context.
            return chain_response.to_web_response()
    finally:
        statsd_client.timer(
            "aip.proxy.request.time",
            time() - start_time,
            tag_dict={
                "xrpc_service": auth_token.context_service.removeprefix("https://"),
                "xrpc_method": xrpc_method,
                "method": request.method.lower(),
                "authentication": auth_method,
                "cross_subject": str(cross_subject),
            },
        )
