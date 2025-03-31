import json
import logging
from typing import (
    Optional,
    Dict,
    List,
    Any,
)
from aiohttp import web
import aiohttp_jinja2
from jwcrypto import jwt
from pydantic import BaseModel
from sqlalchemy import select
import sentry_sdk
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse


from social.graze.aip.app.config import (
    DatabaseSessionMakerAppKey,
    RedisClientAppKey,
    SessionAppKey,
    SettingsAppKey,
    TelegrafStatsdClientAppKey,
)
from social.graze.aip.atproto.oauth import oauth_complete, oauth_init, oauth_refresh
from social.graze.aip.model.handles import Handle
from social.graze.aip.model.oauth import OAuthSession

logger = logging.getLogger(__name__)


def context_vars(settings):
    return {
        "svg_logo": settings.svg_logo,
        "brand_name": settings.brand_name,
        "destination": settings.destination,
        "background_from": settings.background_from,
        "background_to": settings.background_to,
        "text_color": settings.text_color,
        "form_color": settings.form_color,
    }

class ATProtocolOAuthClientMetadata(BaseModel):
    client_id: str
    dpop_bound_access_tokens: bool
    application_type: str
    redirect_uris: List[str]
    client_uri: str
    grant_types: List[str]
    response_types: List[str]
    scope: str
    client_name: str
    token_endpoint_auth_method: str
    jwks_uri: str
    logo_uri: str
    tos_uri: str
    policy_uri: str
    subject_type: str
    token_endpoint_auth_signing_alg: str


async def handle_atproto_login(request: web.Request):
    settings = request.app[SettingsAppKey]
    return await aiohttp_jinja2.render_template_async(
        "atproto_login.html", request, context=context_vars(settings)
    )


async def handle_atproto_login_submit(request: web.Request):
    settings = request.app[SettingsAppKey]
    data = await request.post()
    subject: Optional[str] = data.get("subject", None)  # type: ignore
    destination: Optional[str] = data.get("destination", None)  # type: ignore

    if subject is None:
        return await aiohttp_jinja2.render_template_async(
            "atproto_login.html",
            request,
            context=dict(**context_vars(settings), **{"error_message": "No subject provided"}),
        )

    http_session = request.app[SessionAppKey]
    database_session_maker = request.app[DatabaseSessionMakerAppKey]
    statsd_client = request.app[TelegrafStatsdClientAppKey]

    if destination is None:
        destination = settings.default_destination

    try:
        redirect_destination = await oauth_init(
            settings,
            statsd_client,
            http_session,
            database_session_maker,
            subject,
            destination,
        )
    except Exception as e:
        sentry_sdk.capture_exception(e)
        # TODO: Return a localized error message.
        return await aiohttp_jinja2.render_template_async(
            "atproto_login.html",
            request,
            context=dict(**context_vars(settings), **{"error_message": str(e)}),
        )

    raise web.HTTPFound(str(redirect_destination))


async def handle_atproto_callback(request: web.Request):
    state: Optional[str] = request.query.get("state", None)
    issuer: Optional[str] = request.query.get("iss", None)
    code: Optional[str] = request.query.get("code", None)

    settings = request.app[SettingsAppKey]
    http_session = request.app[SessionAppKey]
    database_session_maker = request.app[DatabaseSessionMakerAppKey]
    redis_session = request.app[RedisClientAppKey]
    statsd_client = request.app[TelegrafStatsdClientAppKey]

    try:
        (serialized_auth_token, destination) = await oauth_complete(
            settings,
            http_session,
            statsd_client,
            database_session_maker,
            redis_session,
            state,
            issuer,
            code,
        )
    except Exception as e:
        return await aiohttp_jinja2.render_template_async(
            "alert.html",
            request,
            context={"error_message": str(e)},
        )

    parsed_destination = urlparse(destination)
    query = dict(parse_qsl(parsed_destination.query))
    query.update({"auth_token": serialized_auth_token})
    parsed_destination = parsed_destination._replace(query=urlencode(query))
    redirect_destination = urlunparse(parsed_destination)
    raise web.HTTPFound(redirect_destination)


async def handle_atproto_refresh(request: web.Request):
    settings = request.app[SettingsAppKey]
    http_session = request.app[SessionAppKey]
    statsd_client = request.app[TelegrafStatsdClientAppKey]
    database_session_maker = request.app[DatabaseSessionMakerAppKey]
    redis_session = request.app[RedisClientAppKey]

    serialized_auth_token: Optional[str] = request.query.get("auth_token", None)
    if serialized_auth_token is None:
        raise Exception("Invalid request")

    validated_auth_token = jwt.JWT(
        jwt=serialized_auth_token, key=settings.json_web_keys, algs=["ES256"]
    )
    auth_token_claims = json.loads(validated_auth_token.claims)

    auth_token_subject: Optional[str] = auth_token_claims.get("sub", None)
    auth_token_session_group: Optional[str] = auth_token_claims.get("grp", None)

    async with (database_session_maker() as database_session,):
        async with database_session.begin():
            oauth_session_stmt = select(OAuthSession).where(
                OAuthSession.guid == auth_token_subject,
                OAuthSession.session_group == auth_token_session_group,
            )
            oauth_session: OAuthSession = (
                await database_session.scalars(oauth_session_stmt)
            ).one()

            await database_session.commit()

        await oauth_refresh(
            settings,
            http_session,
            statsd_client,
            database_session,
            redis_session,
            oauth_session,
        )

    # The same auth token is returned, but the access token is updated.
    raise web.HTTPFound(f"/auth/atproto/debug?auth_token={serialized_auth_token}")


async def handle_atproto_debug(request: web.Request):
    settings = request.app[SettingsAppKey]
    database_session_maker = request.app[DatabaseSessionMakerAppKey]

    serialized_auth_token: Optional[str] = request.query.get("auth_token", None)
    if serialized_auth_token is None:
        raise Exception("Invalid request")

    validated_auth_token = jwt.JWT(
        jwt=serialized_auth_token, key=settings.json_web_keys, algs=["ES256"]
    )
    auth_token_claims = json.loads(validated_auth_token.claims)
    auth_token_header = json.loads(validated_auth_token.header)

    auth_token_subject: Optional[str] = auth_token_claims.get("sub", None)
    auth_token_session_group: Optional[str] = auth_token_claims.get("grp", None)

    async with database_session_maker() as database_session:

        async with database_session.begin():

            oauth_session_stmt = select(OAuthSession).where(
                OAuthSession.guid == auth_token_subject,
                OAuthSession.session_group == auth_token_session_group,
            )
            oauth_session: Optional[OAuthSession] = (
                await database_session.scalars(oauth_session_stmt)
            ).first()
            if oauth_session is None:
                raise Exception("Invalid request: no matching session")

            handle_stmt = select(Handle).where(Handle.guid == oauth_session.guid)
            handle: Optional[Handle] = (
                await database_session.scalars(handle_stmt)
            ).first()
            if handle is None:
                raise Exception("Invalid request: no matching handle")

            await database_session.commit()

    return await aiohttp_jinja2.render_template_async(
        "atproto_debug.html",
        request,
        context={
            "auth_token": {"claims": auth_token_claims, "header": auth_token_header},
            "oauth_session": oauth_session,
            "handle": handle,
            "serialized_auth_token": serialized_auth_token,
        },
    )


async def handle_jwks(request: web.Request):
    settings = request.app[SettingsAppKey]
    results: List[Dict[str, Any]] = []
    for kid in settings.active_signing_keys:
        key = settings.json_web_keys.get_key(kid)
        if key is None:
            continue
        results.append(key.export_public(as_dict=True))
    return web.json_response({"keys": results})


async def handle_atproto_client_metadata(request: web.Request):
    settings = request.app[SettingsAppKey]
    client_id = (
        f"https://{settings.external_hostname}/auth/atproto/client-metadata.json"
    )
    client_uri = f"https://{settings.external_hostname}"
    jwks_uri = f"https://{settings.external_hostname}/.well-known/jwks.json"
    logo_uri = f"https://{settings.external_hostname}/logo.png"
    policy_uri = f"https://{settings.external_hostname}/PLACEHOLDER"
    redirect_uris = [f"https://{settings.external_hostname}/auth/atproto/callback"]
    tos_uri = f"https://{settings.external_hostname}/PLACEHOLDER"
    client_metadata = ATProtocolOAuthClientMetadata(
        application_type="web",
        client_id=client_id,
        client_name="Graze Social",
        client_uri=client_uri,
        dpop_bound_access_tokens=True,
        grant_types=["authorization_code", "refresh_token"],
        jwks_uri=jwks_uri,
        logo_uri=logo_uri,
        policy_uri=policy_uri,
        redirect_uris=redirect_uris,
        response_types=["code"],
        scope="atproto transition:generic",
        token_endpoint_auth_method="private_key_jwt",
        token_endpoint_auth_signing_alg="ES256",
        subject_type="public",
        tos_uri=tos_uri,
    )
    return web.json_response(client_metadata.dict())
