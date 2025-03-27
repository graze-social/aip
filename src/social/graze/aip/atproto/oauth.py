import base64
from datetime import datetime, timezone, timedelta
import hashlib
import secrets
from typing import Optional, Tuple
from aio_statsd import TelegrafStatsdClient
from aiohttp import ClientSession, FormData
from jwcrypto import jwt, jwk
from ulid import ULID
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
import redis.asyncio as redis
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import (
    async_sessionmaker,
    AsyncSession,
)
import sentry_sdk
from social.graze.aip.app.config import Settings, OAUTH_REFRESH_QUEUE
from social.graze.aip.atproto.chain import (
    ChainMiddlewareClient,
    GenerateClaimAssertionMiddleware,
    GenerateDpopMiddleware,
    StatsdMiddleware,
)
from social.graze.aip.atproto.pds import (
    oauth_authorization_server,
    oauth_protected_resource,
)
from social.graze.aip.model.handles import Handle, upsert_handle_stmt
from social.graze.aip.model.oauth import OAuthRequest, OAuthSession
from social.graze.aip.resolve.handle import resolve_subject


def generate_pkce_verifier() -> Tuple[str, str]:
    pkce_token = secrets.token_urlsafe(80)

    hashed = hashlib.sha256(pkce_token.encode("ascii")).digest()
    encoded = base64.urlsafe_b64encode(hashed)
    pkce_challenge = encoded.decode("ascii").rstrip("=")
    return (pkce_token, pkce_challenge)


def validate_oauth_fields(**kwargs):
    """Checks for string fields longer than 512 characters and reports to Sentry."""
    for field, value in kwargs.items():
        if isinstance(value, str) and len(value) > 512:
            sentry_sdk.capture_message(
                f"Field `{field}` exceeds 512 characters", level="error"
            )
            raise ValueError(f"Field `{field}` is too long ({len(value)} characters)")

async def oauth_init(
    settings: Settings,
    statsd_client: TelegrafStatsdClient,
    http_session: ClientSession,
    database_session_maker: async_sessionmaker[AsyncSession],
    subject: str,
):
    signing_key_id = next(iter(settings.active_signing_keys), None)
    if signing_key_id is None:
        raise Exception("No active signing keys configured")

    signing_key = settings.json_web_keys.get_key(signing_key_id)
    if signing_key is None:
        raise Exception("No active signing key available")

    resolved_handle = await resolve_subject(
        http_session, settings.plc_hostname, subject
    )
    if resolved_handle is None:
        raise Exception("Unable to resolve subject")

    state = secrets.token_urlsafe(32)
    (pkce_verifier, code_challenge) = generate_pkce_verifier()

    protected_resource = await oauth_protected_resource(
        http_session, resolved_handle.pds
    )
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

    now = datetime.now(timezone.utc)

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

    data = FormData(
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

    chain_middleware = [
        StatsdMiddleware(statsd_client),
        GenerateDpopMiddleware(
            dpop_key,
            dpop_assertation_header,
            dpop_assertation_claims,
        ),
        GenerateClaimAssertionMiddleware(
            signing_key,
            client_assertion_header,
            client_assertion_claims,
        ),
    ]
    chain_client = ChainMiddlewareClient(
        client_session=http_session, raise_for_status=False, middleware=chain_middleware
    )
    async with chain_client.post(par_url, data=data) as (
        client_response,
        chain_response,
    ):
        if client_response.status != 201:
            raise Exception("Invalid PAR response")

        if isinstance(chain_response.body, dict):
            par_resp = chain_response.body
        else:
            raise ValueError("Invalid PAR response")

    par_expires = par_resp.get("expires_in", 60)
    par_request_uri = par_resp.get("request_uri", None)
    if par_request_uri is None:
        raise Exception("No PAR request URI found")

    # TODO: Use the following redis command to implement a 120 second lock on the resolved subject.
    #       SET "login:{resolved_handle.did}" "1" NX EX 120
    #       https://redis.io/docs/latest/commands/set/

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
                    expires_at=now + timedelta(0, par_expires),
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

    return str(redirect_destination)


async def oauth_complete(
    settings: Settings,
    http_session: ClientSession,
    statsd_client: TelegrafStatsdClient,
    database_session_maker: async_sessionmaker[AsyncSession],
    redis_session: redis.Redis,
    state: Optional[str],
    issuer: Optional[str],
    code: Optional[str],
):
    if state is None or issuer is None or code is None:
        raise Exception("Invalid request")

    service_auth_key_id = next(iter(settings.service_auth_keys), None)
    if service_auth_key_id is None:
        raise Exception("No service auth keys configured")

    service_auth_key = settings.json_web_keys.get_key(service_auth_key_id)
    if service_auth_key is None:
        raise Exception("No service auth key available")

    async with (database_session_maker() as database_session,):

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

        now = datetime.now(timezone.utc)

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

        data = FormData(
            {
                "client_id": client_id,
                "redirect_uri": redirect_url,
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": oauth_request.pkce_verifier,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            }
        )

        chain_middleware = [
            StatsdMiddleware(statsd_client),
            GenerateDpopMiddleware(
                dpop_key,
                dpop_assertation_header,
                dpop_assertation_claims,
            ),
            GenerateClaimAssertionMiddleware(
                signing_key,
                client_assertion_header,
                client_assertion_claims,
            ),
        ]
        chain_client = ChainMiddlewareClient(
            client_session=http_session,
            raise_for_status=False,
            middleware=chain_middleware,
        )
        async with chain_client.post(token_endpoint, data=data) as (
            client_response,
            chain_response,
        ):
            if client_response.status != 200:
                raise Exception("Invalid token response")

            if isinstance(chain_response.body, dict):
                token_response = chain_response.body
            else:
                raise ValueError("Invalid token response")

        access_token = token_response.get("access_token", None)
        if access_token is None:
            raise Exception("No access token")

        refresh_token = token_response.get("refresh_token", None)
        if refresh_token is None:
            raise Exception("No refresh token")

        expires_in = token_response.get("expires_in", 1800)

        session_group = str(ULID())

        async with database_session.begin():
            validate_oauth_fields(
                session_group=session_group,
                issuer=issuer,
                guid=oauth_request.guid,
                access_token=access_token,
                refresh_token=refresh_token,
                secret_jwk_id=oauth_request.secret_jwk_id,
                dpop_jwk=oauth_request.dpop_jwk,
            )

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
                    access_token_expires_at=now + timedelta(0, expires_in),
                    hard_expires_at=now + timedelta(1),
                )
            )

            await database_session.commit()

        # Cache the access token in redis. For users with multiple devices, this just shoves the latest one into the
        # cache keyed on the guid, which is probably fine.
        oauth_session_key = f"auth_session:oauth:{str(oauth_request.guid)}"
        await redis_session.set(oauth_session_key, access_token, ex=(expires_in - 1))

        # Set a queue entry to refresh the token. We don't want to wait until the token is expired to refresh it, so
        # the deadline is 80% of the expires in time from now.
        expires_in_mod = expires_in * 0.8
        refresh_at = now + timedelta(0, expires_in_mod)

        await redis_session.zadd(
            OAUTH_REFRESH_QUEUE,
            {session_group: int(refresh_at.timestamp())},
        )

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

    return str(serialized_auth_token)


async def oauth_refresh(
    settings: Settings,
    http_session: ClientSession,
    statsd_client: TelegrafStatsdClient,
    database_session: AsyncSession,
    redis_session: redis.Redis,
    current_oauth_session: OAuthSession,
):
    service_auth_key_id = next(iter(settings.service_auth_keys), None)
    if service_auth_key_id is None:
        raise Exception("No service auth keys configured")

    service_auth_key = settings.json_web_keys.get_key(service_auth_key_id)
    if service_auth_key is None:
        raise Exception("No service auth key available")

    async with database_session.begin():
        handle_stmt = select(Handle).where(Handle.guid == current_oauth_session.guid)
        handle: Optional[Handle] = (await database_session.scalars(handle_stmt)).first()
        if handle is None:
            raise Exception("Invalid request: no matching handle")

        await database_session.commit()

    signing_key = settings.json_web_keys.get_key(current_oauth_session.secret_jwk_id)
    if signing_key is None:
        raise Exception("No active signing key available")

    dpop_key = jwk.JWK(**current_oauth_session.dpop_jwk)
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

    now = datetime.now(timezone.utc)

    client_assertion_header = {
        "alg": "ES256",
        "kid": current_oauth_session.secret_jwk_id,
    }
    client_assertion_claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": current_oauth_session.issuer,
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

    data = FormData(
        {
            "client_id": client_id,
            "redirect_uri": redirect_url,
            "grant_type": "refresh_token",
            "refresh_token": current_oauth_session.refresh_token,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        }
    )

    chain_middleware = [
        StatsdMiddleware(statsd_client),
        GenerateDpopMiddleware(
            dpop_key,
            dpop_assertation_header,
            dpop_assertation_claims,
        ),
        GenerateClaimAssertionMiddleware(
            signing_key,
            client_assertion_header,
            client_assertion_claims,
        ),
    ]
    chain_client = ChainMiddlewareClient(
        client_session=http_session, raise_for_status=False, middleware=chain_middleware
    )
    async with chain_client.post(token_endpoint, data=data) as (
        client_response,
        chain_response,
    ):
        if client_response.status != 200:
            raise Exception("Invalid token response")

        if isinstance(chain_response.body, dict):
            token_response = chain_response.body
        else:
            raise ValueError("Invalid token response")

    access_token = token_response.get("access_token", None)
    if access_token is None:
        raise Exception("No access token")

    refresh_token = token_response.get("refresh_token", None)
    if refresh_token is None:
        raise Exception("No refresh token")

    expires_in = token_response.get("expires_in", 1800)

    async with database_session.begin():

        update_oauth_session_stmt = (
            update(OAuthSession)
            .where(
                OAuthSession.guid == current_oauth_session.guid,
                OAuthSession.session_group == current_oauth_session.session_group,
            )
            .values(
                access_token=access_token,
                refresh_token=refresh_token,
                access_token_expires_at=now + timedelta(0, expires_in),
            )
        )
        await database_session.execute(update_oauth_session_stmt)

        await database_session.commit()

    # Cache the access token in redis. For users with multiple devices, this just shoves the latest one into the
    # cache keyed on the guid, which is probably fine.
    oauth_session_key = f"auth_session:oauth:{str(current_oauth_session.guid)}"
    await redis_session.set(oauth_session_key, access_token, ex=(expires_in - 1))

    # Set a queue entry to refresh the token. We don't want to wait until the token is expired to refresh it, so
    # the deadline is 80% of the expires in time from now.
    expires_in_mod = expires_in * 0.8
    refresh_at = now + timedelta(0, expires_in_mod)
    await redis_session.zadd(
        OAUTH_REFRESH_QUEUE,
        {current_oauth_session.session_group: int(refresh_at.timestamp())},
    )
