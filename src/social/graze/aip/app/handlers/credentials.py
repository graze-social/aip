import logging
from aiohttp import web
import sentry_sdk

from social.graze.aip.app.config import (
    DatabaseSessionMakerAppKey,
    TelegrafStatsdClientAppKey,
)
from social.graze.aip.app.handlers.helpers import auth_token_helper

logger = logging.getLogger(__name__)


async def handle_internal_credentials(request: web.Request) -> web.Response:
    statsd_client = request.app[TelegrafStatsdClientAppKey]
    database_session_maker = request.app[DatabaseSessionMakerAppKey]

    try:
        async with (database_session_maker() as database_session,):
            # TODO: Allow optional auth here.
            auth_token = await auth_token_helper(
                database_session, statsd_client, request
            )
            if auth_token is None:
                return web.json_response(status=401, data={"error": "Not Authorized"})
    except web.HTTPException as e:
        sentry_sdk.capture_exception(e)
        raise e
    except Exception as e:
        sentry_sdk.capture_exception(e)
        return web.json_response(status=500, data={"error": "Internal Server Error"})

    if auth_token.app_password_session is not None:
        return web.json_response(
            {
                "type": "bearer",
                "token": auth_token.app_password_session.access_token,
            }
        )

    if auth_token.oauth_session is not None:
        return web.json_response(
            {
                "type": "dpop",
                "token": auth_token.oauth_session.access_token,
                "jwk": auth_token.oauth_session.dpop_jwk,
                "issuer": auth_token.oauth_session.issuer,
            }
        )

    return web.json_response(
        {
            "type": "none",
        }
    )
