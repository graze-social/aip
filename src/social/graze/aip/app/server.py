import asyncio
import contextlib
import datetime
import json
import os
import logging
import secrets
from typing import Final, Literal, NoReturn, Optional, Dict, List, Any, Tuple, Final
import jinja2
from aiohttp import web
import aiohttp_jinja2
import aiohttp
import hashlib
import base64
from jwcrypto import jwt, jwk
from ulid import ULID
from pydantic import BaseModel, PositiveInt, RootModel, ValidationError, field_validator
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
import redis.asyncio as redis
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
)
from sqlalchemy.dialects.postgresql import insert

from social.graze.aip.app.config import Settings, SettingsAppKey
from social.graze.aip.resolve.handle import resolve_subject
from social.graze.aip.model.handles import upsert_handle_stmt, Handle
from social.graze.aip.model.oauth import (
    OAuthRequest,
    OAuthSession,
    ATProtoAppPassword,
    Permission,
    upsert_permission_stmt,
)
from social.graze.aip.atproto.pds import (
    oauth_protected_resource,
    oauth_authorization_server,
)
from social.graze.aip.atproto.oauth import dpop_oauth_request

logger = logging.getLogger(__name__)
DatabaseAppKey: Final = web.AppKey("database", AsyncEngine)
DatabaseSessionMakerAppKey: Final = web.AppKey(
    "database_session_maker", async_sessionmaker[AsyncSession]
)
SessionAppKey: Final = web.AppKey("http_session", aiohttp.ClientSession)
RedisPoolAppKey: Final = web.AppKey("redis_pool", redis.ConnectionPool)


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
    database_session = request.app[SessionAppKey]
    data = await request.post()
    subject: Optional[str] = data.get("subject", None)  # type: ignore

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

    resolved_handle = await resolve_subject(
        database_session, settings.plc_hostname, subject
    )
    if resolved_handle is None:
        return await aiohttp_jinja2.render_template_async(
            "atproto_login.html",
            request,
            context={"error_message": "Unable to resolve subject", "subject": subject},
        )

    state = secrets.token_urlsafe(32)
    (pkce_verifier, code_challenge) = generate_pkce_verifier()

    protected_resource = await oauth_protected_resource(
        database_session, resolved_handle.pds
    )
    if protected_resource is None:
        raise Exception("No protected resource found")

    first_authorization_servers = next(
        iter(protected_resource.get("authorization_servers", [])), None
    )
    if first_authorization_servers is None:
        raise Exception("No authorization server found")

    authorization_server = await oauth_authorization_server(
        database_session, first_authorization_servers
    )
    if authorization_server is None:
        raise Exception("No authorization server found")

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

    now = datetime.datetime.now(datetime.timezone.utc)

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

    par_resp = await dpop_oauth_request(
        database_session,
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

    database_session_maker = request.app[DatabaseSessionMakerAppKey]

    async with database_session_maker() as database_session:

        async with database_session.begin():
            stmt = upsert_handle_stmt(
                resolved_handle.did, resolved_handle.handle, resolved_handle.pds
            )
            guid_result = await database_session.execute(stmt)
            guid = guid_result.scalars().one()

            database_session.add(
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

            await database_session.commit()

    parsed_authorization_endpoint = urlparse(authorization_endpoint)
    query = dict(parse_qsl(parsed_authorization_endpoint.query))
    query.update({"client_id": client_id, "request_uri": par_request_uri})
    parsed_authorization_endpoint = parsed_authorization_endpoint._replace(
        query=urlencode(query)
    )
    redirect_destination = urlunparse(parsed_authorization_endpoint)

    raise web.HTTPFound(str(redirect_destination))


async def handle_atproto_callback(request: web.Request):
    settings = request.app[SettingsAppKey]
    http_session = request.app[SessionAppKey]

    state: Optional[str] = request.query.get("state", None)
    issuer: Optional[str] = request.query.get("iss", None)
    code: Optional[str] = request.query.get("code", None)

    if state is None or issuer is None or code is None:
        raise Exception("Invalid request")

    service_auth_key_id = next(iter(settings.service_auth_keys), None)
    if service_auth_key_id is None:
        raise Exception("No service auth keys configured")

    service_auth_key = settings.json_web_keys.get_key(service_auth_key_id)
    if service_auth_key is None:
        raise Exception("No service auth key available")

    database_session_maker = request.app[DatabaseSessionMakerAppKey]
    redis_pool = request.app[RedisPoolAppKey]

    async with (
        database_session_maker() as database_session,
        redis.Redis.from_pool(redis_pool) as redis_session,
    ):

        async with database_session.begin():

            oauth_request_stmt = select(OAuthRequest).where(
                OAuthRequest.oauth_state == state
            )
            oauth_request: Optional[OAuthRequest] = (
                await database_session.scalars(oauth_request_stmt)
            ).first()
            if oauth_request is None:
                raise Exception("Invalid request: no matching state")

            handle_stmt = select(Handle).where(Handle.guid == oauth_request.guid)
            handle: Optional[Handle] = (
                await database_session.scalars(handle_stmt)
            ).first()
            if handle is None:
                raise Exception("Invalid request: no matching handle")

            await database_session.commit()

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
        if protected_resource is None:
            raise Exception("No protected resource found")

        first_authorization_servers = next(
            iter(protected_resource.get("authorization_servers", [])), None
        )
        if first_authorization_servers is None:
            raise Exception("No authorization server found")

        authorization_server = await oauth_authorization_server(
            http_session, first_authorization_servers
        )
        if authorization_server is None:
            raise Exception("No authorization server found")

        token_endpoint = authorization_server.get("token_endpoint", None)
        if token_endpoint is None:
            raise Exception("No authorization endpoint found")

        now = datetime.datetime.now(datetime.timezone.utc)

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

        token_response = await dpop_oauth_request(
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

        async with database_session.begin():
            database_session.add(
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

            await database_session.commit()

        # Cache the access token in redis. For users with multiple devices, this just shoves the latest one into the
        # cache keyed on the guid, which is probably fine.
        oauth_session_key = f"auth_session:oauth:{str(oauth_request.guid)}"
        await redis_session.set(oauth_session_key, access_token, ex=expires_in)

        # TODO: Execute a Redis ZADD operation to create a time-sorted queue of session_group keys for refresh jobs.
        # expires_diff = expires_in * 0.8
        # ZADD "auth_session:oauth:refresh" <now + expires_diff> <session_group>

    auth_token = jwt.JWT(
        header={"alg": "ES256", "kid": service_auth_key_id},
        claims={
            "sub": str(oauth_request.guid),
            "grp": session_group,
            "iat": int(now.timestamp()),
        },
    )
    auth_token.make_signed_token(service_auth_key)
    serialized_auth_token = auth_token.serialize()

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

async def handle_internal_me(request: web.Request):
    database_session_maker = request.app[DatabaseSessionMakerAppKey]
    redis_pool = request.app[RedisPoolAppKey]

    try:
        async with (
            database_session_maker() as database_session,
            redis.Redis.from_pool(redis_pool) as redis_session,
        ):
            auth_token = await auth_token_helper(
                request, database_session, allow_permissions=False
            )
            if auth_token is None:
                raise web.HTTPUnauthorized(
                    body=json.dumps({"error": "Not Authorized"}),
                    content_type="application/json",
                )
            auth_session = await auth_session_helper(
                database_session, redis_session, auth_token, attempt_refresh=False
            )

            # TODO: Include has_app_password boolean in the response.

            return web.json_response(
                {
                    "handle": auth_token.handle,
                    "pds": auth_token.pds,
                    "did": auth_token.subject,
                    "guid": auth_token.guid,
                    "session_valid": auth_session is not None,
                }
            )
    except web.HTTPException as e:
        raise e
    except Exception as e:
        raise web.HTTPInternalServerError(
            body=json.dumps({"error": "Internal Server Error"}),
            content_type="application/json",
        )


async def handle_internal_ready(request: web.Request):
    return web.Response(status=200)


async def handle_internal_alive(request: web.Request):
    return web.Response(status=200)


async def handle_internal_resolve(request: web.Request):
    subjects = request.query.getall("subject", [])
    if len(subjects) == 0:
        return web.json_response([])

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
            results.append(resolved_subject.dict())
    return web.json_response(results)


async def handle_xrpc_proxy(request: web.Request):
    # TODO: Validate this against an allowlist.
    xrpc_method: Optional[str] = request.match_info.get("method", None)
    if xrpc_method is None:
        raise web.HTTPBadRequest(
            body=json.dumps({"error": "Invalid XRPC method"}),
            content_type="application/json",
        )

    database_session_maker = request.app[DatabaseSessionMakerAppKey]
    redis_pool = request.app[RedisPoolAppKey]

    try:
        async with (
            database_session_maker() as database_session,
            redis.Redis.from_pool(redis_pool) as redis_session,
        ):
            auth_token = await auth_token_helper(request, database_session)
            if auth_token is None:
                raise web.HTTPUnauthorized(
                    body=json.dumps({"error": "Not Authorized"}),
                    content_type="application/json",
                )
            auth_session = await auth_session_helper(
                database_session, redis_session, auth_token
            )
    except web.HTTPException as e:
        raise e
    except Exception as e:
        raise web.HTTPInternalServerError(
            body=json.dumps({"error": "Internal Server Error"}),
            content_type="application/json",
        )

    http_session = request.app[SessionAppKey]

    xrpc_url = f"{auth_token.pds}/xrpc/{xrpc_method}"
    print(f"XRPC URL: {xrpc_url}")

    headers = {
        "Authorization": f"Bearer {auth_session}",
    }

    web.Response(text="Hello, World!")

    async with http_session.get(
        xrpc_url,
        headers=headers,
    ) as resp:
        if resp.status == 200:
            return await resp.json()
        return await resp.json()


class PermissionOperation(BaseModel):
    op: Literal["test", "add", "remove", "replace"]
    path: str
    value: Optional[PositiveInt] = None


PermissionOperations = RootModel[list[PermissionOperation]]


async def handle_internal_permissions(request: web.Request) -> web.Response:
    database_session_maker = request.app[DatabaseSessionMakerAppKey]
    redis_pool = request.app[RedisPoolAppKey]

    try:
        data = await request.read()
        operations = PermissionOperations.model_validate_json(data)
    except (OSError, ValidationError):
        return web.Response(text="Invalid JSON", status=400)

    try:
        async with (
            database_session_maker() as database_session,
            redis.Redis.from_pool(redis_pool) as redis_session,
        ):
            auth_token = await auth_token_helper(
                request, database_session, allow_permissions=False
            )
            if auth_token is None:
                raise web.HTTPUnauthorized(
                    body=json.dumps({"error": "Not Authorized"}),
                    content_type="application/json",
                )

            # TODO: Fail with error if the user does not have an app-password set.

            now = datetime.datetime.now(datetime.timezone.utc)

            async with database_session.begin():
                results: List[Dict[str, Any]] = []

                for operation in operations.root:
                    if (
                        operation.op == "add" or operation.op == "replace"
                    ) and operation.value is not None:
                        guid = operation.path.removeprefix("/")
                        stmt = upsert_permission_stmt(
                            guid=guid,
                            target_guid=auth_token.guid,
                            permission=operation.value,
                            created_at=now,
                        )
                        await database_session.execute(stmt)

                    if operation.op == "remove":
                        guid = operation.path.removeprefix("/")
                        stmt = delete(Permission).where(
                            Permission.guid == guid,
                            Permission.target_guid == auth_token.guid,
                        )
                        await database_session.execute(stmt)

                    if operation.op == "test":
                        guid = operation.path.removeprefix("/")
                        permission_stmt = select(Permission).where(
                            Permission.guid == guid,
                            Permission.target_guid == auth_token.guid,
                        )
                        if operation.value is not None:
                            permission_stmt = permission_stmt.where(
                                Permission.permission == operation.value
                            )
                        permission: Optional[Permission] = (
                            await database_session.scalars(permission_stmt)
                        ).first()
                        if permission is not None:
                            results.append(
                                {"path": operation.path, "value": permission.permission}
                            )

                await database_session.commit()

                return web.json_response(results)
    except web.HTTPException as e:
        logging.exception("handle_internal_permissions: web.HTTPException")
        raise e
    except Exception as e:
        logging.exception("handle_internal_permissions: Exception")
        raise web.HTTPInternalServerError(
            body=json.dumps({"error": "Internal Server Error"}),
            content_type="application/json",
        )


class AppPasswordOperation(BaseModel):
    value: Optional[str] = None

    @field_validator("value")
    def app_password_check(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None

        if len(v) != 19:
            raise ValueError("invalid format")

        if v.count("-") != 3:
            raise ValueError("invalid format")

        return v


async def handle_internal_app_password(request: web.Request) -> web.Response:
    database_session_maker = request.app[DatabaseSessionMakerAppKey]
    redis_pool = request.app[RedisPoolAppKey]

    try:
        data = await request.read()
        app_password_operation = AppPasswordOperation.model_validate_json(data)
    except (OSError, ValidationError):
        return web.Response(text="Invalid JSON", status=400)

    try:
        async with (
            database_session_maker() as database_session,
            redis.Redis.from_pool(redis_pool) as redis_session,
        ):
            auth_token = await auth_token_helper(
                request, database_session, allow_permissions=False
            )
            if auth_token is None:
                raise web.HTTPUnauthorized(
                    body=json.dumps({"error": "Not Authorized"}),
                    content_type="application/json",
                )

            now = datetime.datetime.now(datetime.timezone.utc)

            async with database_session.begin():
                if app_password_operation.value is None:
                    stmt = delete(ATProtoAppPassword).where(
                        ATProtoAppPassword.guid == auth_token.guid
                    )
                    await database_session.execute(stmt)
                else:
                    stmt = (
                        insert(ATProtoAppPassword)
                        .values(
                            [
                                {
                                    "guid": auth_token.guid,
                                    "app_password": app_password_operation.value,
                                    "created_at": now,
                                }
                            ]
                        )
                        .on_conflict_do_update(
                            index_elements=["guid"],
                            set_={"app_password": app_password_operation.value},
                        )
                    )
                    await database_session.execute(stmt)

                await database_session.commit()

            app_password_key = f"auth_session:app-password:{auth_token.guid}"
            await redis_session.delete(app_password_key)

            # TODO: Add the guid to the refresh queue to create an AT Protocol auth token using the app-password.
            # ZADD "auth_session:app_password:refresh" <now + 5 seconds> guid

            return web.Response(status=200)
    except web.HTTPException as e:
        logging.exception("handle_internal_permissions: web.HTTPException")
        raise e
    except Exception as e:
        logging.exception("handle_internal_permissions: Exception")
        raise web.HTTPInternalServerError(
            body=json.dumps({"error": "Internal Server Error"}),
            content_type="application/json",
        )


class AuthToken(BaseModel):
    auth_token: str

    guid: str
    subject: str
    handle: str
    pds: str

    context_guid: str
    context_subject: str
    context_pds: str


class EncodedException(Exception):
    pass


class AuthHelperException(EncodedException):
    CODE: Final[str] = "error-auth-5000"


async def auth_session_helper(
    # request: web.Request,
    database_session: AsyncSession,
    redis_session: redis.Redis,
    auth_token: AuthToken,
    attempt_refresh: bool = False,
) -> Optional[str]:
    try:
        async with database_session.begin():
            is_self = auth_token.subject == auth_token.context_subject

            # 1. Get an app-password session from redis if it exists. This is a cheap operation, so get it out of the way up front.
            app_password_key = f"auth_session:app-password:{auth_token.context_guid}"
            cached_app_password_value: bytes = await redis_session.get(app_password_key)
            if cached_app_password_value is not None:
                # TODO: Deccrypt the value
                return cached_app_password_value.decode("utf-8")

            # 2. If is_self, then get an oauth session from redis if it exists.
            if is_self:
                oauth_session_key = f"auth_session:oauth:{auth_token.context_guid}"
                cached_oauth_session_value: bytes = await redis_session.get(
                    oauth_session_key
                )
                if cached_oauth_session_value is not None:
                    # TODO: Deccrypt the value
                    return cached_oauth_session_value.decode("utf-8")

            if attempt_refresh is False:
                return None

            # TODO: Make the above redis calls a single mget operation.

            # 3. If not is_self, then get the app-password from the DB, create a session, cache it, and return it.
            # TODO: Implement this.

            # 4. If not is_self, return an error because a valid app-password session is required.
            if not is_self:
                return None

            # 5. If is_self, then get an oauth session from the database if it exists.
            # TODO: Implement this.

            oauth_session_stmt = select(OAuthSession).where(
                OAuthSession.guid == auth_token.context_guid
            )
            oauth_session: Optional[OAuthSession] = (
                await database_session.scalars(oauth_session_stmt)
            ).first()
            await database_session.commit()

            if oauth_session is not None:
                return str(oauth_session.access_token)

            # Lastly, all options have been exhausted.
            return None
    except AuthHelperException:
        logging.exception("auth_session_helper: AuthHelperException")
        return None
    except Exception:
        logging.exception("auth_session_helper: Exception")
        return None


async def auth_token_helper(
    request: web.Request, database_session: AsyncSession, allow_permissions: bool = True
) -> Optional[AuthToken]:
    authorizations: Optional[str] = request.headers.getone("Authorization", None)
    if (
        authorizations is None
        or not authorizations.startswith("Bearer ")
        or len(authorizations) < 8
    ):
        return None

    serialized_auth_token = authorizations[7:]

    settings = request.app[SettingsAppKey]

    try:
        # TODO: Figure out what this raises.
        validated_auth_token = jwt.JWT(
            jwt=serialized_auth_token, key=settings.json_web_keys, algs=["ES256"]
        )
        # TODO: Validate this against a pydantic model
        # auth_token_header: Dict[str, str] = json.loads(validated_auth_token.header)

        # TODO: Validate this against a pydantic model
        auth_token_claims: Dict[str, str] = json.loads(validated_auth_token.claims)

        auth_token_subject: Optional[str] = auth_token_claims.get("sub", None)
        if auth_token_subject is None:
            raise ValueError("auth_token invalid: sub missing")

        auth_token_session_group: Optional[str] = auth_token_claims.get("grp", None)
        if auth_token_session_group is None:
            raise ValueError("auth_token invalid: grp missing")

    except Exception as e:
        logging.exception("auth_token_helper: exception")
        raise AuthHelperException()

    try:

        async with database_session.begin():

            oauth_session_stmt = select(OAuthSession).where(
                OAuthSession.guid == auth_token_subject,
                OAuthSession.session_group == auth_token_session_group,
            )
            oauth_session: OAuthSession = (
                await database_session.scalars(oauth_session_stmt)
            ).one()

            handle_stmt = select(Handle).where(Handle.guid == oauth_session.guid)
            handle: Handle = (await database_session.scalars(handle_stmt)).one()

            x_repository: str = request.headers.getone("X-Repository", handle.did)

            # If the subject of the request is the same as the subject of the auth token, then we have everything we need and can return a full formed AuthToken.
            if x_repository == handle.did:
                x_pds: str = request.headers.getone("X-Pds", handle.pds)
                return AuthToken(
                    auth_token=serialized_auth_token,
                    guid=handle.guid,
                    subject=handle.did,
                    handle=handle.handle,
                    pds=handle.pds,
                    context_guid=handle.guid,
                    context_subject=handle.did,
                    context_pds=x_pds,
                )

            if allow_permissions is False:
                raise Exception("policy violation: permissions not allowed")

            permission_stmt = select(Permission).where(
                Permission.guid == handle.guid,
                Permission.target_guid == x_repository,
                Permission.permission > 0,
            )
            permission: Permission = (
                await database_session.scalars(permission_stmt)
            ).one()

            subject_handle_stmt = select(Handle).where(
                Handle.guid == permission.target_guid
            )
            subject_handle: Handle = (
                await database_session.scalars(subject_handle_stmt)
            ).one()

            x_pds: str = request.headers.getone("X-Pds", subject_handle.pds)

            await database_session.commit()

            return AuthToken(
                auth_token=serialized_auth_token,
                guid=handle.guid,
                subject=handle.did,
                handle=handle.handle,
                pds=handle.pds,
                context_guid=subject_handle.guid,
                context_subject=subject_handle.did,
                context_pds=x_pds,
            )
    except Exception as e:
        logging.exception("auth_token_helper: exception")
        raise AuthHelperException()


async def startup(app):
    settings: Settings = app[SettingsAppKey]

    engine = create_async_engine(str(settings.pg_dsn))
    app[DatabaseAppKey] = engine
    database_session = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    app[DatabaseSessionMakerAppKey] = database_session

    app[SessionAppKey] = aiohttp.ClientSession()

    app[RedisPoolAppKey] = redis.ConnectionPool.from_url(str(settings.redis_dsn))


tick_task_app_key = web.AppKey("tick_task_app_key", asyncio.Task[None])


async def tick_task(app: web.Application) -> NoReturn:
    while True:

        now = datetime.datetime.now(datetime.timezone.utc)

        database_session_maker = app[DatabaseSessionMakerAppKey]
        redis_pool = app[RedisPoolAppKey]

        async with (
            database_session_maker() as database_session,
            redis.Redis.from_pool(redis_pool) as redis_session,
        ):

            # Nick: Buckle up, this is stupid.
            #
            # Given the queue name is "auth_refresh"
            # Given the worker id is "worker1"
            # Given `now = datetime.datetime.now(datetime.timezone.utc)`
            #
            # 1. In a redis pipeline, get some work.
            #    * Populate the worker queue with work. This stores a range of things from the begining of time to "now" into a new queue
            #      ZRANGESTORE "auth_refresh_worker1" "auth_refresh" 1 {now} LIMIT 5
            #
            #    * Get the work that we just populated.
            #      ZRANGE "auth_refresh_worker1" 0 -1
            #
            #    * Store the difference between the worker queue and the main queue to remove the pulled work from the main queue
            #      ZDIFFSTORE "auth_refresh" 2 "auth_refresh" "auth_refresh_worker1"
            #
            # 2. For the work that we just got, process it all and remove each from the worker queue.
            #    ZREM "auth_refresh_worker1" {work_id}
            #
            # 3. Sleep 15-30 seconds and repeat.

            # Nick: This does a few things that are important to note.
            #
            # 1. Work is queued up and indexed (redis zindex) against the time that it needs to be processed, not when
            #    it was queued. This lets the queue be lazily evaluated and also pull work that needs to be processed
            #    soonest.
            #
            # 2. Work is batched into a worker queue outside of app instances, so it can be processed in parallel. If
            #    we need to scale up workers, we can do so by adjusting the deployment replica count.
            #
            # 3. Work is grabbed in batches that don't need to be uniform, so there is no arbitrary delay. Workers
            #    don't have to wait for 5 jobs to be ready before taking them.
            #
            # 4. If a worker dies, we have the temporary worker queue to recover the work that was in progress. If
            #    needed, we can create a watchdog worker that looks at orphaned worker queues and adds the work back to
            #    the main queue.

            pass

        # print(f"Tick")
        await asyncio.sleep(30)


async def background_tasks(app):
    app[tick_task_app_key] = asyncio.create_task(tick_task(app))

    yield

    app[tick_task_app_key].cancel()
    with contextlib.suppress(asyncio.exceptions.CancelledError):
        await app[tick_task_app_key]


async def shutdown(app):
    await app[DatabaseAppKey].dispose()
    await app[SessionAppKey].close()
    await app[RedisPoolAppKey].aclose()


async def start_web_server(settings: Optional[Settings] = None):

    if settings is None:
        settings = Settings()  # type: ignore

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
            web.get("/internal/alive", handle_internal_alive),
            web.get("/internal/ready", handle_internal_ready),
            web.get("/internal/api/me", handle_internal_me),
            web.get("/internal/api/resolve", handle_internal_resolve),
            web.post("/internal/api/permissions", handle_internal_permissions),
            web.post("/internal/api/app_password", handle_internal_app_password),
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
    app.cleanup_ctx.append(background_tasks)

    return app
