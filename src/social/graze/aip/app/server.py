import datetime
import os
import logging
import secrets
from typing import Optional, Dict, List, Any, Tuple
import jinja2
from aiohttp import web
import aiohttp_jinja2
import aiohttp
import hashlib
import base64
from jwcrypto import jwk
from ulid import ULID
from pydantic import BaseModel
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
)

from social.graze.aip.app.config import Settings, SettingsAppKey
from social.graze.aip.resolve.handle import resolve_subject
from social.graze.aip.model.handles import upsert_handle_stmt, Handle
from social.graze.aip.model.oauth import OAuthRequest, OAuthSession
from social.graze.aip.atproto.pds import (
    oauth_protected_resource,
    oauth_authorization_server,
)
from social.graze.aip.atproto.dpop import dpop_request

logger = logging.getLogger(__name__)
DatabaseAppKey = web.AppKey("database", AsyncEngine)
DatabaseSessionAppKey = web.AppKey("session_maker", async_sessionmaker[AsyncSession])
SessionAppKey = web.AppKey("http_session", aiohttp.ClientSession)


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


async def handle_index(request: web.Request):
    return await aiohttp_jinja2.render_template_async("index.html", request, context={})


async def handle_atproto_login(request: web.Request):
    return await aiohttp_jinja2.render_template_async(
        "atproto_login.html", request, context={}
    )


def generate_pkce_verifier() -> Tuple[str, str]:
    pkce_token = secrets.token_urlsafe(80)

    hashed = hashlib.sha256(pkce_token.encode("ascii")).digest()
    encoded = base64.urlsafe_b64encode(hashed)
    pkce_challenge = encoded.decode("ascii").rstrip("=")
    return (pkce_token, pkce_challenge)


async def handle_atproto_login_submit(request: web.Request):
    settings = request.app[SettingsAppKey]
    session = request.app[SessionAppKey]
    data = await request.post()
    subject = data.get("subject", None)

    if subject is None:
        return await aiohttp_jinja2.render_template_async(
            "atproto_login.html",
            request,
            context={"error_message": "No subject provided"},
        )

    signing_key_id = next(iter(settings.active_signing_keys), None)
    if signing_key_id is None:
        raise Exception("No active signing keys configured")

    signing_key = settings.json_web_keys.get_key(signing_key_id)
    if signing_key is None:
        raise Exception("No active signing key available")

    resolved_handle = await resolve_subject(session, settings.plc_hostname, subject)
    if resolved_handle is None:
        return await aiohttp_jinja2.render_template_async(
            "atproto_login.html",
            request,
            context={"error_message": "Unable to resolve subject", "subject": subject},
        )

    state = secrets.token_urlsafe(32)
    (pkce_verifier, code_challenge) = generate_pkce_verifier()

    protected_resource = await oauth_protected_resource(session, resolved_handle.pds)

    first_authorization_servers = next(
        iter(protected_resource.get("authorization_servers", [])), None
    )
    if first_authorization_servers is None:
        raise Exception("No authorization server found")

    authorization_server = await oauth_authorization_server(
        session, first_authorization_servers
    )

    authorization_endpoint = authorization_server.get("authorization_endpoint", None)
    if authorization_endpoint is None:
        raise Exception("No authorization endpoint found")

    issuer = authorization_server.get("issuer", None)
    if issuer is None:
        raise Exception("No authorization issuer found")

    par_url = authorization_server.get("pushed_authorization_request_endpoint", None)
    if par_url is None:
        raise Exception("No PAR URL found")

    dpop_key = jwk.JWK.generate(kty="EC", crv="P-256", kid=str(ULID()), alg="ES256")
    dpop_key_public_key = dpop_key.export_public(as_dict=True)

    client_id = (
        f"https://{settings.external_hostname}/auth/atproto/client-metadata.json"
    )
    redirect_url = f"https://{settings.external_hostname}/auth/atproto/callback"

    now = datetime.datetime.now()

    client_assertion_header = {"alg": "ES256", "kid": signing_key_id}
    client_assertion_claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": issuer,
        "iat": int(now.timestamp()),
    }

    dpop_assertation_header = {
        "alg": "ES256",
        "jwk": dpop_key_public_key,
        "typ": "dpop+jwt",
    }
    dpop_assertation_claims = {
        "htm": "POST",
        "htu": par_url,
        "iat": int(now.timestamp()),
        "exp": int(now.timestamp()) + 30,
        "nonce": "tmp",
    }

    data = aiohttp.FormData(
        {
            "response_type": "code",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
            "client_id": client_id,
            "redirect_uri": redirect_url,
            "scope": "atproto transition:generic",
            "login_hint": resolved_handle.handle,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        }
    )

    par_resp = await dpop_request(
        session,
        par_url,
        dpop_key,
        dpop_assertation_header,
        dpop_assertation_claims,
        signing_key,
        client_assertion_header,
        client_assertion_claims,
        data=data,
    )
    par_expires = par_resp.get("expires_in", 60)
    par_request_uri = par_resp.get("request_uri", None)
    if par_request_uri is None:
        raise Exception("No PAR request URI found")

    # TODO: Use the following redis command to implement a 120 second lock on the resolved subject.
    #       SET "login:{resolved_handle.did}" "1" NX EX 120
    #       https://redis.io/docs/latest/commands/set/

    db_session = request.app[DatabaseSessionAppKey]
    async with db_session() as session:

        async with session.begin():
            stmt = upsert_handle_stmt(
                resolved_handle.did, resolved_handle.handle, resolved_handle.pds
            )
            guid_result = await session.execute(stmt)
            guid = guid_result.scalars().one()

            session.add(
                OAuthRequest(
                    oauth_state=state,
                    issuer=issuer,
                    guid=guid,
                    pkce_verifier=pkce_verifier,
                    secret_jwk_id=signing_key_id,
                    dpop_jwk=dpop_key.export(private_key=True, as_dict=True),
                    destination="/settings",
                    created_at=now,
                    expires_at=now + datetime.timedelta(0, par_expires),
                )
            )

            await session.commit()

    parsed_authorization_endpoint = urlparse(authorization_endpoint)
    query = dict(parse_qsl(parsed_authorization_endpoint.query))
    query.update({"client_id": client_id, "request_uri": par_request_uri})
    parsed_authorization_endpoint = parsed_authorization_endpoint._replace(
        query=urlencode(query)
    )
    redirect_destination = urlunparse(parsed_authorization_endpoint)

    raise web.HTTPFound(redirect_destination)


async def handle_atproto_callback(request: web.Request):
    settings = request.app[SettingsAppKey]
    http_session = request.app[SessionAppKey]
    db_session = request.app[DatabaseSessionAppKey]

    state = request.query.get("state", None)
    issuer = request.query.get("iss", None)
    code = request.query.get("code", None)

    if state is None or issuer is None or code is None:
        raise Exception("Invalid request")

    async with db_session() as session:

        async with session.begin():

            oauth_request_stmt = select(OAuthRequest).where(
                OAuthRequest.oauth_state == state
            )
            oauth_request = (await session.scalars(oauth_request_stmt)).first()

            handle_stmt = select(Handle).where(Handle.guid == oauth_request.guid)
            handle = (await session.scalars(handle_stmt)).first()

            await session.commit()

        if oauth_request.issuer != issuer:
            raise Exception("Invalid request: issuer mismatch")

        signing_key = settings.json_web_keys.get_key(oauth_request.secret_jwk_id)
        if signing_key is None:
            raise Exception("No active signing key available")

        dpop_key = jwk.JWK(**oauth_request.dpop_jwk)
        dpop_key_public_key = dpop_key.export_public(as_dict=True)

        client_id = (
            f"https://{settings.external_hostname}/auth/atproto/client-metadata.json"
        )
        redirect_url = f"https://{settings.external_hostname}/auth/atproto/callback"
        client_assertion_jti = str(ULID())

        protected_resource = await oauth_protected_resource(http_session, handle.pds)

        first_authorization_servers = next(
            iter(protected_resource.get("authorization_servers", [])), None
        )
        if first_authorization_servers is None:
            raise Exception("No authorization server found")

        authorization_server = await oauth_authorization_server(
            http_session, first_authorization_servers
        )
        token_endpoint = authorization_server.get("token_endpoint", None)
        if token_endpoint is None:
            raise Exception("No authorization endpoint found")

        now = datetime.datetime.now()

        client_assertion_header = {"alg": "ES256", "kid": oauth_request.secret_jwk_id}
        client_assertion_claims = {
            "iss": client_id,
            "sub": client_id,
            "aud": issuer,
            "jti": client_assertion_jti,
            "iat": int(now.timestamp()),
        }

        dpop_assertation_header = {
            "alg": "ES256",
            "jwk": dpop_key_public_key,
            "typ": "dpop+jwt",
        }
        dpop_assertation_claims = {
            "htm": "POST",
            "htu": token_endpoint,
            "iat": int(now.timestamp()),
            "exp": int(now.timestamp()) + 30,
            "nonce": "tmp",
        }

        data = aiohttp.FormData(
            {
                "client_id": client_id,
                "redirect_uri": redirect_url,
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": oauth_request.pkce_verifier,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            }
        )

        token_response = await dpop_request(
            http_session,
            token_endpoint,
            dpop_key,
            dpop_assertation_header,
            dpop_assertation_claims,
            signing_key,
            client_assertion_header,
            client_assertion_claims,
            data=data,
        )

        access_token = token_response.get("access_token", None)
        if access_token is None:
            raise Exception("No access token")

        refresh_token = token_response.get("refresh_token", None)
        if refresh_token is None:
            raise Exception("No refresh token")

        expires_in = token_response.get("expires_in", 1800)

        session_group = str(ULID())

        async with session.begin():
            session.add(
                OAuthSession(
                    session_group=session_group,
                    issuer=issuer,
                    guid=oauth_request.guid,
                    access_token=access_token,
                    refresh_token=refresh_token,
                    secret_jwk_id=oauth_request.secret_jwk_id,
                    dpop_jwk=oauth_request.dpop_jwk,
                    created_at=now,
                    access_token_expires_at=now + datetime.timedelta(0, expires_in),
                    hard_expires_at=now + datetime.timedelta(1),
                )
            )

            await session.commit()

        raise web.HTTPFound(f"/auth/atproto/debug?session_group={session_group}")


async def handle_atproto_debug(request: web.Request):
    return await aiohttp_jinja2.render_template_async(
        "atproto_debug.html", request, context={}
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


async def handle_atproto_client_metadata(request):
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


async def handle_settings(request):
    return await aiohttp_jinja2.render_template_async(
        "settings.html", request, context={}
    )


async def handle_set_app_password(request):
    return await aiohttp_jinja2.render_template_async(
        "settings.html", request, context={}
    )


async def handle_change_permission(request):
    return await aiohttp_jinja2.render_template_async(
        "settings.html", request, context={}
    )


async def handle_internal_me(request):
    return await aiohttp_jinja2.render_template_async(
        "settings.html", request, context={}
    )


async def handle_internal_ready(request):
    return await aiohttp_jinja2.render_template_async(
        "settings.html", request, context={}
    )


async def handle_internal_alive(request):
    return await aiohttp_jinja2.render_template_async(
        "settings.html", request, context={}
    )


async def handle_internal_resolve(request):
    subjects = request.query.getall("subject", [])
    if len(subjects) == 0:
        return web.json_response([])

    db_session = request.app[DatabaseSessionAppKey]
    settings = request.app[SettingsAppKey]

    # TODO: Use a pydantic list structure for this.
    results = []
    async with db_session() as session:
        for subject in subjects:
            resolved_subject = await resolve_subject(
                request.app[SessionAppKey], settings.plc_hostname, subject
            )
            if resolved_subject is None:
                continue
            async with session.begin():
                stmt = upsert_handle_stmt(
                    resolved_subject.did, resolved_subject.handle, resolved_subject.pds
                )
                await session.execute(stmt)
                await session.commit()
            results.append(resolved_subject.dict())
    return web.json_response(results)


async def handle_xrpc_proxy(request):
    return await aiohttp_jinja2.render_template_async(
        "settings.html", request, context={}
    )


async def startup(app):
    settings = app[SettingsAppKey]

    engine = create_async_engine(str(settings.pg_dsn))
    app[DatabaseAppKey] = engine
    database_session = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    app[DatabaseSessionAppKey] = database_session

    app[SessionAppKey] = aiohttp.ClientSession()


async def shutdown(app):
    await app[SessionAppKey].close()
    await app[DatabaseAppKey].dispose()
    await app[SessionAppKey].close()


async def start_web_server(settings: Optional[Settings] = None):

    if settings is None:
        settings = Settings()

    app = web.Application()

    app[SettingsAppKey] = settings

    app.add_routes(
        [
            web.static(
                "/static", os.path.join(os.getcwd(), "static"), append_version=True
            )
        ]
    )

    app.add_routes([web.get("/.well-known/jwks.json", handle_jwks)])

    app.add_routes([web.get("/", handle_index)])
    app.add_routes([web.get("/auth/atproto", handle_atproto_login)])
    app.add_routes([web.post("/auth/atproto", handle_atproto_login_submit)])
    app.add_routes([web.get("/auth/atproto/callback", handle_atproto_callback)])
    app.add_routes([web.get("/auth/atproto/debug", handle_atproto_debug)])
    app.add_routes(
        [web.get("/auth/atproto/client-metadata.json", handle_atproto_client_metadata)]
    )

    app.add_routes(
        [
            web.get("/settings", handle_settings),
            web.post("/settings/app_password", handle_set_app_password),
            web.post("/settings/permissions", handle_change_permission),
        ]
    )

    app.add_routes(
        [
            web.get("/internal/alive", handle_internal_me),
            web.get("/internal/ready", handle_internal_me),
            web.get("/internal/api/me", handle_internal_me),
            web.get("/internal/api/resolve", handle_internal_resolve),
        ]
    )

    app.add_routes(
        [
            web.get("/xrpc/{method}", handle_xrpc_proxy),
            web.post("/xrpc/{method}", handle_xrpc_proxy),
        ]
    )

    _ = aiohttp_jinja2.setup(
        app,
        enable_async=True,
        loader=jinja2.FileSystemLoader(os.path.join(os.getcwd(), "templates")),
    )

    app["static_root_url"] = "/static"

    app.on_startup.append(startup)
    app.on_cleanup.append(shutdown)

    return app
