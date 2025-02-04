import datetime
import os
import logging
import secrets
import time
from typing import Optional, Dict, List, Any, Tuple
import jinja2
from aiohttp import web
import aiohttp_jinja2
import aiohttp
import hashlib
import base64
from jwcrypto import jwt, jwk
from ulid import ULID
from pydantic import BaseModel

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
)

from social.graze.aip.app.config import Settings, SettingsAppKey
from social.graze.aip.resolve.handle import resolve_subject
from social.graze.aip.model.handles import upsert_handle_stmt
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
    pkce_challenge = encoded.decode("ascii")[:-1]
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
    print(f"signing_key_id = {signing_key_id}")

    signing_key = settings.json_web_keys.get_key(signing_key_id)
    if signing_key is None:
        raise Exception("No active signing key available")
    print(f"signing_key = {signing_key}")

    resolved_handle = await resolve_subject(session, settings.plc_hostname, subject)
    if resolved_handle is None:
        return await aiohttp_jinja2.render_template_async(
            "atproto_login.html",
            request,
            context={"error_message": "Unable to resolve subject", "subject": subject},
        )

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    print(f"state = {state}")
    print(f"nonce = {nonce}")
    (pkce_token, pkce_challenge) = generate_pkce_verifier()
    print(f"pkce_token = {pkce_token}")
    print(f"pkce_challenge = {pkce_challenge}")

    protected_resource = await oauth_protected_resource(session, resolved_handle.pds)
    print(f"protected_resource = {protected_resource}")

    first_authorization_servers = next(
        iter(protected_resource.get("authorization_servers", [])), None
    )
    if first_authorization_servers is None:
        raise Exception("No authorization server found")

    authorization_server = await oauth_authorization_server(
        session, first_authorization_servers
    )
    print(f"authorization_server = {authorization_server}")

    par_url = authorization_server.get("pushed_authorization_request_endpoint", None)
    if par_url is None:
        raise Exception("No PAR URL found")

    dpop_key = jwk.JWK.generate(kty="EC", crv="P-256", kid=str(ULID()), alg="ES256")
    dpop_key_public_key = dpop_key.export_public(as_dict=True)

    client_id = (
        f"https://{settings.external_hostname}/auth/atproto/client-metadata.json"
    )
    redirect_url = f"https://{settings.external_hostname}/auth/atproto/callback"
    client_assertion_jti = secrets.token_urlsafe(32)

    now = int(datetime.datetime.now().timestamp())

    client_assertion = jwt.JWT(
        header={"alg": "ES256", "kid": signing_key_id},
        claims={
            "iss": client_id,
            "sub": client_id,
            "aud": authorization_server.get("issuer", ""),
            "jti": client_assertion_jti,
            "iat": int(now),
        },
    )
    client_assertion.make_signed_token(signing_key)
    client_assertion_token = client_assertion.serialize()
    print(f"client_assertion_token = {client_assertion_token}")

    dpop_assertation_jti = secrets.token_urlsafe(32)
    dpop_assertation_header = {"alg": "ES256", "jwk": dpop_key_public_key, "type": "dpop+jwt"}
    dpop_assertation_claims = {
            "jti": dpop_assertation_jti,
            "htm": "post",
            "htu": par_url,
            "iat": int(now),
            "exp": int(now) + 30,
        }

    par_form = aiohttp.FormData({
        "response_type": "code",
        "code_challenge": pkce_challenge,
        "code_challenge_method": "S256",
        "state": state,
        "client_id": client_id,
        "redirect_uri": redirect_url,
        "scope": "atproto transition:generic",
        "login_hint": resolved_handle.handle,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion_token,
    })
    print(f"par_form = {par_form.__dict__}")
    headers = {
        # "DPoP": dpop_assertation_token,
        # "Content-Type": "application/x-www-form-urlencoded"
    }

    par_resp = await dpop_request(
        session,
        dpop_key,
        dpop_assertation_header,
        dpop_assertation_claims,
        "POST",
        # "https://tip-ngerakines.requestcatcher.com/oauth/par",
        authorization_server["pushed_authorization_request_endpoint"],
        headers=headers,
        data=par_form,
    )
    print(f"par_resp = {par_resp}")

    # TODO: Use the following redis command to implement a 120 second lock on the resolved subject.
    #       SET "login:{resolved_handle.did}" "1" NX EX 120
    #       https://redis.io/docs/latest/commands/set/

    db_session = request.app[DatabaseSessionAppKey]
    async with db_session() as session:

        async with session.begin():
            stmt = upsert_handle_stmt(
                resolved_handle.did, resolved_handle.handle, resolved_handle.pds
            )
            await session.execute(stmt)
            await session.commit()

    return await aiohttp_jinja2.render_template_async(
        "atproto_login.html", request, context={"subject": subject}
    )


async def handle_atproto_callback(request: web.Request):
    raise web.HTTPFound("/auth/atproto/debug")


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
    settings  = request.app[SettingsAppKey]

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
