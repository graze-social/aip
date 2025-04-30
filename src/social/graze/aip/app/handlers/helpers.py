from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
from typing import (
    Optional,
    Dict,
)
from aio_statsd import TelegrafStatsdClient
from aiohttp import web
from jwcrypto import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
)
import sentry_sdk

from social.graze.aip.app.config import (
    SettingsAppKey,
)
from social.graze.aip.model.app_password import AppPasswordSession
from social.graze.aip.model.handles import Handle
from social.graze.aip.model.oauth import OAuthSession, Permission

logger = logging.getLogger(__name__)


@dataclass(repr=False, eq=False)
class AuthToken:
    """
    Represents an authenticated token with user identity and session information.
    
    This class contains both the authenticating user's information (guid, subject, handle)
    and the context for the current request (which may be different if using permissions
    to act on behalf of another user).
    
    Attributes:
        guid: The guid of the authenticating user
        subject: The DID of the authenticating user
        handle: The handle of the authenticating user
        
        context_service: The service URL for the context of the request
        context_guid: The guid for the context of the request
        context_subject: The DID for the context of the request
        context_pds: The PDS URL for the context of the request
        
        oauth_session: The OAuth session if authenticated via OAuth
        app_password_session: The App Password session if authenticated via App Password
    """
    guid: str
    subject: str
    handle: str

    context_service: str
    context_guid: str
    context_subject: str
    context_pds: str

    oauth_session: Optional[OAuthSession] = None
    app_password_session: Optional[AppPasswordSession] = None


class AuthenticationException(Exception):
    """
    Exception raised for authentication failures.
    
    This exception class provides static methods for creating specific
    authentication failure instances with appropriate error messages.
    """

    @staticmethod
    def jwt_subject_missing() -> "AuthenticationException":
        """JWT is missing the required 'sub' claim."""
        return AuthenticationException("error-auth-helper-1000 JWT missing subject")

    @staticmethod
    def jwt_session_group_missing() -> "AuthenticationException":
        """JWT is missing the required 'grp' claim."""
        return AuthenticationException(
            "error-auth-helper-1001 JWT missing session group"
        )

    @staticmethod
    def session_not_found() -> "AuthenticationException":
        """No valid session was found for the authenticated user."""
        return AuthenticationException(
            "error-auth-helper-1002 No valid session found"
        )

    @staticmethod
    def session_expired() -> "AuthenticationException":
        """The session has expired and is no longer valid."""
        return AuthenticationException(
            "error-auth-helper-1003 Session has expired"
        )

    @staticmethod
    def handle_not_found() -> "AuthenticationException":
        """No handle record was found for the authenticated user."""
        return AuthenticationException(
            "error-auth-helper-1004 Handle record not found"
        )

    @staticmethod
    def permission_denied() -> "AuthenticationException":
        """User does not have permission to perform the requested action."""
        return AuthenticationException(
            "error-auth-helper-1005 Permission denied"
        )

    @staticmethod
    def unexpected(msg: str = "") -> "AuthenticationException":
        """An unexpected error occurred during authentication."""
        return AuthenticationException(
            f"error-auth-helper-1999 Unexpected authentication error: {msg}"
        )


async def auth_token_helper(
    database_session: AsyncSession,
    statsd_client: TelegrafStatsdClient,
    request: web.Request,
    allow_permissions: bool = True,
) -> Optional[AuthToken]:
    """
    Authenticate a request and return an AuthToken with user and context information.
    
    This helper enforces the following policies:
    * All API calls must be authenticated and require an `Authorization` header with a bearer token.
    * The `X-Subject` header can optionally specify the subject of the request. The value must be a known guid.
    * The `X-Service` header can optionally specify the hostname of the service providing the invoked XRPC method.
    
    The function validates the JWT token, retrieves the associated session information, and checks permissions
    if the request is acting on behalf of another user.
    
    Args:
        database_session: SQLAlchemy async session for database queries
        statsd_client: Statsd client for metrics
        request: The HTTP request to authenticate
        allow_permissions: Whether to allow acting on behalf of another user via permissions
    
    Returns:
        An AuthToken object if authentication succeeds, None otherwise
        
    Raises:
        AuthenticationException: If there's a specific authentication failure that should be reported
    """

    # Check for Authorization header with Bearer token
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
        # Validate the JWT token
        validated_auth_token = jwt.JWT(
            jwt=serialized_auth_token, key=settings.json_web_keys, algs=["ES256"]
        )
        
        # Parse and validate claims
        auth_token_claims: Dict[str, str] = json.loads(validated_auth_token.claims)

        auth_token_subject: Optional[str] = auth_token_claims.get("sub", None)
        if auth_token_subject is None:
            raise AuthenticationException.jwt_subject_missing()

        auth_token_session_group: Optional[str] = auth_token_claims.get("grp", None)
        if auth_token_session_group is None:
            raise AuthenticationException.jwt_session_group_missing()

        now = datetime.now(timezone.utc)

        async with database_session.begin():

            # 1. Get the OAuthSession from the database and validate it
            oauth_session_stmt = select(OAuthSession).where(
                OAuthSession.guid == auth_token_subject,

                # Sessions are not limited to the same session group because we
                # don't actually care about which session we end up getting. The
                # only requirement is that it's valid.
                # OAuthSession.session_group == auth_token_session_group,

                OAuthSession.access_token_expires_at > now,
                OAuthSession.hard_expires_at > now
            ).order_by(OAuthSession.created_at.desc())
            
            oauth_session: Optional[OAuthSession] = (
                await database_session.scalars(oauth_session_stmt)
            ).first()

            if oauth_session is None:
                raise AuthenticationException.session_not_found()

            # 2. Get the Handle from the database and validate it
            oauth_session_handle_stmt = select(Handle).where(
                Handle.guid == auth_token_subject
            )
            oauth_session_handle_result = await database_session.scalars(oauth_session_handle_stmt)
            oauth_session_handle = oauth_session_handle_result.first()
            
            if oauth_session_handle is None:
                raise AuthenticationException.handle_not_found()

            # 3. Get the X-Subject header, defaulting to the current oauth session handle's guid
            x_subject: str = request.headers.getone(
                "X-Subject", oauth_session_handle.guid
            )

            # If the subject of the request is the same as the subject of the auth token,
            # then we have everything we need and can return a fully formed AuthToken
            if x_subject == oauth_session_handle.guid:
                x_service: str = request.headers.getone(
                    "X-Service", oauth_session_handle.pds
                )

                # Look up app password session if it exists
                app_password_session_stmt = select(AppPasswordSession).where(
                    AppPasswordSession.guid == oauth_session.guid,
                )
                app_password_session: Optional[AppPasswordSession] = (
                    await database_session.scalars(app_password_session_stmt)
                ).first()

                return AuthToken(
                    oauth_session=oauth_session,
                    app_password_session=app_password_session,
                    guid=oauth_session_handle.guid,
                    subject=oauth_session_handle.did,
                    handle=oauth_session_handle.handle,
                    context_service=x_service,
                    context_guid=oauth_session_handle.guid,
                    context_subject=oauth_session_handle.did,
                    context_pds=oauth_session_handle.pds,
                )

            # If permissions are not allowed but the subject differs, deny the request
            if allow_permissions is False:
                raise AuthenticationException.permission_denied()

            # 4. Get the permission record for the oauth session handle to the x_repository guid
            permission_stmt = select(Permission).where(
                Permission.guid == oauth_session_handle.guid,
                Permission.target_guid == x_subject,
                Permission.permission > 0,
            )
            permission: Optional[Permission] = (
                await database_session.scalars(permission_stmt)
            ).first()

            # If no permission is found, deny access
            if permission is None:
                raise AuthenticationException.permission_denied()

            # Get the handle for the target subject
            subject_handle_stmt = select(Handle).where(
                Handle.guid == permission.target_guid
            )
            subject_handle_result = await database_session.scalars(subject_handle_stmt)
            subject_handle = subject_handle_result.first()
            
            if subject_handle is None:
                raise AuthenticationException.handle_not_found()

            # Get the app password session for the target subject if it exists
            app_password_session_stmt = select(AppPasswordSession).where(
                AppPasswordSession.guid == subject_handle.guid,
            )
            app_password_session: Optional[AppPasswordSession] = (
                await database_session.scalars(app_password_session_stmt)
            ).first()

            # Get a valid OAuth session for the target subject
            target_oauth_session_stmt = select(OAuthSession).where(
                OAuthSession.guid == subject_handle.guid,
                OAuthSession.access_token_expires_at > now,
                OAuthSession.hard_expires_at > now
            ).order_by(OAuthSession.created_at.desc())
            
            target_oauth_session: Optional[OAuthSession] = (
                await database_session.scalars(target_oauth_session_stmt)
            ).first()

            # Get the service endpoint from the X-Service header or use the subject's PDS
            x_service: str = request.headers.getone("X-Service", subject_handle.pds)

            await database_session.commit()

            return AuthToken(
                oauth_session=target_oauth_session,
                app_password_session=app_password_session,
                guid=oauth_session_handle.guid,
                subject=oauth_session_handle.did,
                handle=oauth_session_handle.handle,
                context_service=x_service,
                context_guid=subject_handle.guid,
                context_subject=subject_handle.did,
                context_pds=subject_handle.pds,
            )
    except AuthenticationException as e:
        sentry_sdk.capture_exception(e)
        raise
    except Exception as e:
        sentry_sdk.capture_exception(e)
        statsd_client.increment(
            "aip.auth.exception",
            1,
            tag_dict={"exception": type(e).__name__},
        )
        logger.exception("auth_token_helper: Exception")
        return None