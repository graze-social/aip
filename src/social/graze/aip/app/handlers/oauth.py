"""
AT Protocol OAuth Handlers

This module implements the web request handlers for OAuth authentication with AT Protocol.
It provides endpoints for initiating authentication, handling callbacks from the AT Protocol
authorization server, refreshing tokens, and debugging authentication information.

OAuth Flow with AT Protocol:
1. User enters their handle/DID in the login form
2. Application initiates OAuth flow by redirecting to AT Protocol authorization server
3. User authenticates with their AT Protocol PDS (Personal Data Server)
4. PDS redirects back to the application with an authorization code
5. Application exchanges the code for access and refresh tokens
6. Application stores tokens and returns an auth token to the client
7. Tokens are refreshed before they expire

The handlers in this module provide the following endpoints:
- GET /auth/atproto - Login form for entering AT Protocol handle/DID
- POST /auth/atproto - Submit login form to initiate OAuth flow
- GET /auth/atproto/callback - OAuth callback from AT Protocol authorization server
- GET /auth/atproto/refresh - Manually refresh tokens
- GET /auth/atproto/debug - Display debug information about authentication
- GET /.well-known/jwks.json - JWKS endpoint for key verification
- GET /auth/atproto/client-metadata.json - OAuth client metadata
"""

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
from social.graze.aip.app.cors import get_cors_headers
from social.graze.aip.atproto.oauth import oauth_complete, oauth_init, oauth_refresh
from social.graze.aip.model.handles import Handle
from social.graze.aip.model.oauth import OAuthSession

logger = logging.getLogger(__name__)


def context_vars(settings):
    """
    Create a context dictionary for template rendering with UI customization settings.
    
    This function extracts UI customization settings from the application settings
    to be passed to the template rendering engine.
    
    Args:
        settings: Application settings object
        
    Returns:
        Dict containing UI customization variables for templates
    """
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
    """
    OAuth 2.0 Client Metadata for AT Protocol integration.
    
    This model represents the client metadata used for OAuth registration with AT Protocol.
    It follows the OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591) with
    additional fields specific to AT Protocol requirements.
    
    The metadata is exposed at the client-metadata.json endpoint and is used by
    AT Protocol authorization servers to validate OAuth requests.
    """
    client_id: str
    """Client identifier URI"""
    
    dpop_bound_access_tokens: bool
    """Whether access tokens are bound to DPoP proofs"""
    
    application_type: str
    """Type of application (web, native)"""
    
    redirect_uris: List[str]
    """List of allowed redirect URIs for this client"""
    
    client_uri: str
    """URI of the client's homepage"""
    
    grant_types: List[str]
    """OAuth grant types supported by this client"""
    
    response_types: List[str]
    """OAuth response types supported by this client"""
    
    scope: str
    """OAuth scopes requested by this client"""
    
    client_name: str
    """Human-readable name of the client application"""
    
    token_endpoint_auth_method: str
    """Authentication method for the token endpoint"""
    
    jwks_uri: str
    """URI of the client's JWKS (JSON Web Key Set)"""
    
    logo_uri: str
    """URI of the client's logo"""
    
    tos_uri: str
    """URI of the client's terms of service"""
    
    policy_uri: str
    """URI of the client's policy document"""
    
    subject_type: str
    """Subject type requested for responses"""
    
    token_endpoint_auth_signing_alg: str
    """Algorithm used for signing token endpoint authentication assertions"""


async def handle_atproto_login(request: web.Request):
    """
    Handle GET request to the AT Protocol login page.
    
    This handler renders the login form where users can enter their
    AT Protocol handle or DID to begin the authentication process.
    
    Args:
        request: HTTP request object
        
    Returns:
        HTTP response with rendered login template
    """
    settings = request.app[SettingsAppKey]
    context = context_vars(settings)

    destination = request.query.get("destination")
    if destination:
        context["destination"] = destination

    return await aiohttp_jinja2.render_template_async(
        "atproto_login.html", request, context=context
    )


async def handle_atproto_login_submit(request: web.Request):
    """
    Handle POST request from the AT Protocol login form.
    
    This handler processes the login form submission and initiates the OAuth flow.
    It extracts the subject (handle or DID) and optional destination from the form,
    then calls oauth_init to start the OAuth process.
    
    Request Parameters:
        subject: AT Protocol handle or DID
        destination: Optional redirect URL after authentication
        
    Args:
        request: HTTP request object
        
    Returns:
        HTTP redirect to the AT Protocol authorization server
        
    Raises:
        HTTPFound: To redirect to authorization server
        
    Flow:
        1. Extract subject and destination from form
        2. Initialize OAuth flow with oauth_init
        3. Redirect user to authorization server
    """
    settings = request.app[SettingsAppKey]
    data = await request.post()
    subject: Optional[str] = data.get("subject", None)  # type: ignore
    destination: Optional[str] = data.get("destination", None)  # type: ignore

    if subject is None:
        return await aiohttp_jinja2.render_template_async(
            "atproto_login.html",
            request,
            context=dict(
                **context_vars(settings), **{"error_message": "No subject provided"}
            ),
        )

    http_session = request.app[SessionAppKey]
    database_session_maker = request.app[DatabaseSessionMakerAppKey]
    statsd_client = request.app[TelegrafStatsdClientAppKey]
    redis_session = request.app[RedisClientAppKey]

    if destination is None:
        destination = settings.default_destination

    try:
        redirect_destination = await oauth_init(
            settings,
            statsd_client,
            http_session,
            database_session_maker,
            redis_session,
            subject,
            destination,
        )
    except Exception as e:
        logger.exception("login error")

        sentry_sdk.capture_exception(e)
        # TODO: Return a localized error message.
        return await aiohttp_jinja2.render_template_async(
            "atproto_login.html",
            request,
            context=dict(**context_vars(settings), **{"error_message": str(e)}),
        )
    raise web.HTTPFound(
        str(redirect_destination),
        headers=get_cors_headers(request.headers.get("Origin"), request.path, settings.debug),
    )


async def handle_atproto_callback(request: web.Request):
    """
    Handle OAuth callback from AT Protocol authorization server.
    
    This handler processes the callback from the AT Protocol authorization server,
    exchanging the authorization code for access and refresh tokens, then redirecting
    the user to their final destination with an auth token.
    
    Query Parameters:
        state: OAuth state parameter to prevent CSRF
        iss: Issuer identifier (authorization server)
        code: Authorization code to exchange for tokens
        
    Args:
        request: HTTP request object
        
    Returns:
        HTTP redirect to the final destination with auth token
        
    Raises:
        HTTPFound: To redirect to final destination
        
    Flow:
        1. Extract state, issuer, and code from query parameters
        2. Complete OAuth flow with oauth_complete
        3. Add auth token to destination URL
        4. Redirect user to final destination
    """
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
    """
    Handle manual token refresh request.
    
    This handler allows for manual refreshing of OAuth tokens. It extracts the
    auth token from the query parameters, validates it, finds the associated
    OAuth session, and refreshes the token.
    
    Query Parameters:
        auth_token: JWT authentication token
        
    Args:
        request: HTTP request object
        
    Returns:
        HTTP redirect to debug page with refreshed token
        
    Raises:
        HTTPFound: To redirect to debug page
        Exception: If auth token is invalid or session not found
        
    Flow:
        1. Extract and validate auth token
        2. Find associated OAuth session
        3. Refresh tokens with oauth_refresh
        4. Redirect to debug page
    """
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
    """
    Handle debug page request showing authentication information.
    
    This handler displays detailed information about the authentication session,
    including the JWT token contents, OAuth session details, and user handle.
    It's primarily used for debugging and development purposes.
    
    Query Parameters:
        auth_token: JWT authentication token
        
    Args:
        request: HTTP request object
        
    Returns:
        HTTP response with rendered debug template
        
    Raises:
        Exception: If auth token is invalid or session/handle not found
    """
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
    """
    Handle JWKS (JSON Web Key Set) endpoint request.
    
    This handler provides the public keys used for verifying JWT signatures.
    It returns a JWKS document containing the public portions of the active signing keys.
    
    Args:
        request: HTTP request object
        
    Returns:
        HTTP JSON response with JWKS document
    """
    settings = request.app[SettingsAppKey]
    results: List[Dict[str, Any]] = []
    for kid in settings.active_signing_keys:
        key = settings.json_web_keys.get_key(kid)
        if key is None:
            continue
        results.append(key.export_public(as_dict=True))
    return web.json_response({"keys": results})


async def handle_atproto_client_metadata(request: web.Request):
    """
    Handle OAuth client metadata endpoint request.
    
    This handler provides OAuth client metadata according to the OAuth 2.0
    Dynamic Client Registration Protocol (RFC 7591). It returns a JSON document
    describing this client to AT Protocol authorization servers.
    
    The metadata includes client identification, capabilities, endpoints,
    and authentication methods.
    
    Args:
        request: HTTP request object
        
    Returns:
        HTTP JSON response with client metadata
    """
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