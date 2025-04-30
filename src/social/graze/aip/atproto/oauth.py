"""
AT Protocol OAuth Client Implementation

This module implements a full OAuth 2.0 client specifically adapted for AT Protocol authentication.
It provides the core functionality for initiating OAuth flows, handling callbacks, and refreshing tokens.

The implementation follows these OAuth 2.0 standards and specifications:
- OAuth 2.0 Authorization Code Grant (RFC 6749)
- Proof Key for Code Exchange (PKCE) (RFC 7636)
- OAuth 2.0 DPoP (Demonstrating Proof of Possession) (draft)
- OAuth 2.0 JWT Client Authentication (RFC 7523)
- OAuth 2.0 Pushed Authorization Requests (PAR) (RFC 9126)

The OAuth flow is implemented in three stages:
1. Initialization (`oauth_init`): Resolve user identity, prepare PKCE challenge, 
   create a PAR request, and redirect to authorization server
2. Completion (`oauth_complete`): Exchange authorization code for tokens,
   store tokens, and return a signed auth token
3. Refresh (`oauth_refresh`): Use refresh token to obtain new access token
   before the current one expires

Each stage involves secure cryptographic operations, endpoint discovery from the AT Protocol
PDS (Personal Data Server), and proper token storage with automatic refresh scheduling.
"""

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
    """
    Generate PKCE (Proof Key for Code Exchange) verifier and challenge.
    
    This implements the PKCE extension to OAuth 2.0 (RFC 7636) to prevent
    authorization code interception attacks. It creates a cryptographically
    random verifier and its corresponding S256 challenge.
    
    Returns:
        Tuple[str, str]: A tuple containing (pkce_verifier, pkce_challenge)
        - pkce_verifier: The secret verifier that will be sent in the token request
        - pkce_challenge: The challenge derived from the verifier, sent in the authorization request
        
    Security considerations:
        - The verifier uses recommended 80 bytes of entropy (RFC 7636 section 4.1)
        - The challenge uses SHA-256 for the code challenge method
    """
    pkce_token = secrets.token_urlsafe(80)

    hashed = hashlib.sha256(pkce_token.encode("ascii")).digest()
    encoded = base64.urlsafe_b64encode(hashed)
    pkce_challenge = encoded.decode("ascii").rstrip("=")
    return (pkce_token, pkce_challenge)


async def oauth_init(
    settings: Settings,
    statsd_client: TelegrafStatsdClient,
    http_session: ClientSession,
    database_session_maker: async_sessionmaker[AsyncSession],
    redis_session: redis.Redis,
    subject: str,
    destination: Optional[str] = None,
):
    """
    Initialize OAuth flow with AT Protocol.
    
    This function starts the OAuth authorization code flow:
    1. Resolves the user's handle or DID to canonical form
    2. Discovers the PDS (Personal Data Server) and authorization endpoints
    3. Creates Pushed Authorization Request (PAR)
    4. Generates PKCE verification codes
    5. Stores request data for later verification
    6. Returns a redirect URL to the authorization server
    
    Args:
        settings: Application settings
        statsd_client: Metrics client for tracking requests
        http_session: HTTP session for making requests
        database_session_maker: Database session factory
        subject: User's handle or DID
        destination: Optional redirect URL after authentication
        
    Returns:
        str: URL to redirect the user to for authentication
        
    Raises:
        Exception: Various exceptions for missing configuration or failed requests
        
    Flow:
        1. Key retrieval and validation
        2. Subject resolution
        3. Authorization server discovery
        4. PAR (Pushed Authorization Request)
        5. Database storage of request
        6. URL construction for redirect
    """
    # Get signing key for client authentication
    signing_key_id = next(iter(settings.active_signing_keys), None)
    if signing_key_id is None:
        raise Exception("No active signing keys configured")

    signing_key = settings.json_web_keys.get_key(signing_key_id)
    if signing_key is None:
        raise Exception("No active signing key available")

    # Resolve the subject (handle or DID) to canonical form
    resolved_handle = await resolve_subject(
        http_session, settings.plc_hostname, subject
    )
    if resolved_handle is None:
        raise Exception("Unable to resolve subject")

    # Generate OAuth state parameter and PKCE challenge
    state = secrets.token_urlsafe(32)
    (pkce_verifier, code_challenge) = generate_pkce_verifier()

    # Discover protected resource and authorization server endpoints
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

    # Generate DPoP key for token binding
    dpop_key = jwk.JWK.generate(kty="EC", crv="P-256", kid=str(ULID()), alg="ES256")
    dpop_key_public_key = dpop_key.export_public(as_dict=True)

    # Prepare client identifier and callback URL
    client_id = (
        f"https://{settings.external_hostname}/auth/atproto/client-metadata.json"
    )
    redirect_url = f"https://{settings.external_hostname}/auth/atproto/callback"

    now = datetime.now(timezone.utc)

    # Prepare client assertion for authentication
    client_assertion_header = {"alg": "ES256", "kid": signing_key_id}
    client_assertion_claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": issuer,
        "iat": int(now.timestamp()),
    }

    # Prepare DPoP proof
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

    # Prepare PAR request data
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

    # Set up middleware chain for request authentication and metrics
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
    
    # Make PAR request
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

    # Implement a 120 second lock on the resolved subject to prevent duplicate login attempts
    login_lock_key = f"login:{resolved_handle.did}"
    try:
        lock_acquired = await redis_session.set(login_lock_key, "1", nx=True, ex=120)
        
        if not lock_acquired:
            raise Exception("Another login attempt for this user is in progress")

        # Store request data for later verification
        async with database_session_maker() as database_session:

            async with database_session.begin():
                # Store or update handle information
                stmt = upsert_handle_stmt(
                    resolved_handle.did, resolved_handle.handle, resolved_handle.pds
                )
                guid_result = await database_session.execute(stmt)
                guid = guid_result.scalars().one()

                # Store OAuth request data
                database_session.add(
                    OAuthRequest(
                        oauth_state=state,
                        issuer=issuer,
                        guid=guid,
                        pkce_verifier=pkce_verifier,
                        secret_jwk_id=signing_key_id,
                        dpop_jwk=dpop_key.export(private_key=True, as_dict=True),
                        destination=destination,
                        created_at=now,
                        expires_at=now + timedelta(0, par_expires),
                    )
                )

                await database_session.commit()

    finally:
        # Release the lock when we're done with handle resolution and database operations
        await redis_session.delete(login_lock_key)

    # Construct redirect URL with request URI
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
) -> Tuple[str, str]:
    """
    Complete OAuth flow by exchanging authorization code for tokens.
    
    This function completes the OAuth authorization code flow:
    1. Validates the callback parameters (state, issuer, code)
    2. Retrieves the original OAuth request
    3. Exchanges authorization code for access and refresh tokens
    4. Stores tokens in database and Redis cache
    5. Creates a service auth token for the client
    6. Schedules token refresh
    
    Args:
        settings: Application settings
        http_session: HTTP session for making requests
        statsd_client: Metrics client for tracking requests
        database_session_maker: Database session factory
        redis_session: Redis client for token caching
        state: OAuth state parameter from callback
        issuer: Issuer identifier from callback
        code: Authorization code from callback
        
    Returns:
        Tuple[str, str]: A tuple containing (serialized_auth_token, destination)
        - serialized_auth_token: JWT token for client authentication
        - destination: Redirect URL for the client
        
    Raises:
        Exception: Various exceptions for missing parameters, configuration issues,
                  or failed requests
                  
    Flow:
        1. Parameter validation
        2. OAuth request retrieval
        3. Key preparation
        4. Token endpoint request
        5. Token storage in database and Redis
        6. Refresh scheduling
        7. Service auth token creation
    """
    # Validate callback parameters
    if state is None or issuer is None or code is None:
        raise Exception("Invalid request")

    # Get service auth key for creating client tokens
    service_auth_key_id = next(iter(settings.service_auth_keys), None)
    if service_auth_key_id is None:
        raise Exception("No service auth keys configured")

    service_auth_key = settings.json_web_keys.get_key(service_auth_key_id)
    if service_auth_key is None:
        raise Exception("No service auth key available")

    # Retrieve original OAuth request and handle
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

        # Validate issuer
        if oauth_request.issuer != issuer:
            raise Exception("Invalid request: issuer mismatch")

        # Get signing key and prepare DPoP key
        signing_key = settings.json_web_keys.get_key(oauth_request.secret_jwk_id)
        if signing_key is None:
            raise Exception("No active signing key available")

        dpop_key = jwk.JWK(**oauth_request.dpop_jwk)
        dpop_key_public_key = dpop_key.export_public(as_dict=True)

        # Prepare client identifier and callback URL
        client_id = (
            f"https://{settings.external_hostname}/auth/atproto/client-metadata.json"
        )
        redirect_url = f"https://{settings.external_hostname}/auth/atproto/callback"
        client_assertion_jti = str(ULID())

        # Discover token endpoint
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

        # Prepare client assertion for authentication
        client_assertion_header = {"alg": "ES256", "kid": oauth_request.secret_jwk_id}
        client_assertion_claims = {
            "iss": client_id,
            "sub": client_id,
            "aud": issuer,
            "jti": client_assertion_jti,
            "iat": int(now.timestamp()),
        }

        # Prepare DPoP proof
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

        # Prepare token request data with PKCE verifier
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

        # Set up middleware chain for request authentication and metrics
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
        
        # Make token request
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

        # Extract tokens from response
        access_token = token_response.get("access_token", None)
        if access_token is None:
            raise Exception("No access token")

        refresh_token = token_response.get("refresh_token", None)
        if refresh_token is None:
            raise Exception("No refresh token")

        expires_in = token_response.get("expires_in", 1800)

        # Store tokens in database
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

    # Create service auth token for client
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

    return str(serialized_auth_token), str(oauth_request.destination)


async def oauth_refresh(
    settings: Settings,
    http_session: ClientSession,
    statsd_client: TelegrafStatsdClient,
    database_session: AsyncSession,
    redis_session: redis.Redis,
    current_oauth_session: OAuthSession,
):
    """
    Refresh OAuth tokens before they expire.
    
    This function refreshes OAuth access and refresh tokens:
    1. Uses the current refresh token to obtain new tokens
    2. Updates tokens in database and Redis cache
    3. Schedules the next refresh
    
    This function can be called manually or by a background task that
    processes the refresh queue.
    
    Args:
        settings: Application settings
        http_session: HTTP session for making requests
        statsd_client: Metrics client for tracking requests
        database_session: Database session
        redis_session: Redis client for token caching
        current_oauth_session: Current OAuth session with tokens
        
    Raises:
        Exception: Various exceptions for missing configuration or failed requests
        
    Flow:
        1. Key validation
        2. Endpoint discovery
        3. Refresh token request
        4. Token update in database and Redis
        5. Next refresh scheduling
    """
    # Validate service auth key
    service_auth_key_id = next(iter(settings.service_auth_keys), None)
    if service_auth_key_id is None:
        raise Exception("No service auth keys configured")

    service_auth_key = settings.json_web_keys.get_key(service_auth_key_id)
    if service_auth_key is None:
        raise Exception("No service auth key available")

    # Get handle for current session
    async with database_session.begin():
        handle_stmt = select(Handle).where(Handle.guid == current_oauth_session.guid)
        handle: Optional[Handle] = (await database_session.scalars(handle_stmt)).first()
        if handle is None:
            raise Exception("Invalid request: no matching handle")

        await database_session.commit()

    # Get signing key and prepare DPoP key
    signing_key = settings.json_web_keys.get_key(current_oauth_session.secret_jwk_id)
    if signing_key is None:
        raise Exception("No active signing key available")

    dpop_key = jwk.JWK(**current_oauth_session.dpop_jwk)
    dpop_key_public_key = dpop_key.export_public(as_dict=True)

    # Prepare client identifier and callback URL
    client_id = (
        f"https://{settings.external_hostname}/auth/atproto/client-metadata.json"
    )
    redirect_url = f"https://{settings.external_hostname}/auth/atproto/callback"
    client_assertion_jti = str(ULID())

    # Discover token endpoint
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

    # Prepare client assertion for authentication
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

    # Prepare DPoP proof
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

    # Prepare refresh token request
    data = FormData(
        {
            "client_id": client_id,
            "redirect_uri": redirect_url,
            "grant_type": "refresh_token",
            "refresh_token": current_oauth_session.refresh_token,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        }
    )

    # Set up middleware chain for request authentication and metrics
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
    
    # Make refresh token request
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

    # Extract tokens from response
    access_token = token_response.get("access_token", None)
    if access_token is None:
        raise Exception("No access token")

    refresh_token = token_response.get("refresh_token", None)
    if refresh_token is None:
        raise Exception("No refresh token")

    expires_in = token_response.get("expires_in", 1800)

    # Update tokens in database
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