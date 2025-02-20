from datetime import datetime, timezone
import json
import logging
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
    # TODO: Validate this against an allowlist.
    xrpc_method: Optional[str] = request.match_info.get("method", None)
    if xrpc_method is None:
        raise web.HTTPBadRequest(
            body=json.dumps({"error": "Invalid XRPC method"}),
            content_type="application/json",
        )

    database_session_maker = request.app[DatabaseSessionMakerAppKey]

    try:
        async with (database_session_maker() as database_session,):
            # TODO: Allow optional auth here.
            auth_token = await auth_token_helper(request, database_session)
            if auth_token is None:
                raise web.HTTPUnauthorized(
                    body=json.dumps({"error": "Not Authorized"}),
                    content_type="application/json",
                )
    except web.HTTPException as e:
        raise e
    except Exception:
        raise web.HTTPInternalServerError(
            body=json.dumps({"error": "Internal Server Error"}),
            content_type="application/json",
        )

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

    statsd_client = request.app[TelegrafStatsdClientAppKey]

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
    async with chain_client.request(
        request.method, xrpc_url, raise_for_status=None, headers=headers, **rargs
    ) as (
        client_response,
        chain_response,
    ):
        # TODO: Figure out if websockets or SSE support is needed. Gut says no.
        # TODO: Think about using a header like `X-AIP-Error` for additional error context.
        return chain_response.to_web_response()
        # return web.Response(status=chain_response.status, body=chain_response.body, headers=chain_response.headers)
