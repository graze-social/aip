import json
import logging

from aiohttp import web
import sentry_sdk

from social.graze.aip.app.config import (
    DatabaseSessionMakerAppKey,
    HealthGaugeAppKey,
    SessionAppKey,
    SettingsAppKey,
    TelegrafStatsdClientAppKey,
)
from social.graze.aip.app.handlers.helpers import auth_token_helper
from social.graze.aip.model.handles import upsert_handle_stmt
from social.graze.aip.resolve.handle import resolve_subject

logger = logging.getLogger(__name__)


async def handle_internal_me(request: web.Request):
    database_session_maker = request.app[DatabaseSessionMakerAppKey]
    statsd_client = request.app[TelegrafStatsdClientAppKey]

    try:
        async with (database_session_maker() as database_session,):
            auth_token = await auth_token_helper(
                database_session, statsd_client, request, allow_permissions=False
            )
            if auth_token is None:
                raise web.HTTPUnauthorized(
                    body=json.dumps({"error": "Not Authorized"}),
                    content_type="application/json",
                )

            # TODO: Include has_app_password boolean in the response.

            return web.json_response(
                {
                    "handle": auth_token.handle,
                    "pds": auth_token.context_service,
                    "did": auth_token.subject,
                    "guid": auth_token.guid,
                    "oauth_session_valid": auth_token.oauth_session is not None,
                    "app_password_session_valid": auth_token.app_password_session
                    is not None,
                }
            )
    except web.HTTPException as e:
        sentry_sdk.capture_exception(e)
        raise e
    except Exception as e:
        sentry_sdk.capture_exception(e)
        raise web.HTTPInternalServerError(
            body=json.dumps({"error": "Internal Server Error"}),
            content_type="application/json",
        )


async def handle_internal_ready(request: web.Request):
    health_gauge = request.app[HealthGaugeAppKey]
    if await health_gauge.is_healthy():
        return web.Response(status=200)
    return web.Response(status=503)


async def handle_internal_alive(request: web.Request):
    return web.Response(status=200)


async def handle_internal_resolve(request: web.Request):
    subjects = request.query.getall("subject", [])
    if len(subjects) == 0:
        return web.json_response([])

    # Nick: This could be improved by using Redis to cache results. Eventually inputs should go into a queue to be
    # processed in the background and the results streamed back to the client via SSE. If this becomes a high volume
    # endpoint, then we should run our own PLC replica or consider tapping into jetstream.

    database_session_maker = request.app[DatabaseSessionMakerAppKey]
    settings = request.app[SettingsAppKey]

    # TODO: Use a pydantic list structure for this.
    results = []
    async with database_session_maker() as database_session:
        for subject in subjects:
            resolved_subject = await resolve_subject(
                request.app[SessionAppKey], settings.plc_hostname, subject
            )
            if resolved_subject is None:
                continue
            async with database_session.begin():
                stmt = upsert_handle_stmt(
                    resolved_subject.did, resolved_subject.handle, resolved_subject.pds
                )
                await database_session.execute(stmt)
                await database_session.commit()
            results.append(resolved_subject.model_dump())
    return web.json_response(results)
