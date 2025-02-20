from dataclasses import dataclass
import json
import logging
from typing import (
    Final,
    Optional,
    Dict,
)
from aiohttp import web
from jwcrypto import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
)

from social.graze.aip.app.config import (
    SettingsAppKey,
)
from social.graze.aip.model.app_password import AppPasswordSession
from social.graze.aip.model.handles import Handle
from social.graze.aip.model.oauth import OAuthSession, Permission

logger = logging.getLogger(__name__)


@dataclass(repr=False, eq=False)
class AuthToken:
    guid: str
    subject: str
    handle: str

    context_service: str
    context_guid: str
    context_subject: str
    context_pds: str

    oauth_session: Optional[OAuthSession] = None
    app_password_session: Optional[AppPasswordSession] = None


class EncodedException(Exception):
    pass


class AuthHelperException(EncodedException):
    CODE: Final[str] = "error-auth-5000"


async def auth_token_helper(
    request: web.Request, database_session: AsyncSession, allow_permissions: bool = True
) -> Optional[AuthToken]:
    """
    This helper enforces the following policies:
    * All API calls must be authenticated and require an `Authorization` header with a bearer token.
    * The `X-Subject` header can optionally specify the subject of the request. The value must be a known guid.
    * The `X-Service` header can optionally specify the hostname of the service providing the invoked XRPC method.
    """

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

    except Exception:
        logging.exception("auth_token_helper: exception")
        raise AuthHelperException()

    try:
        async with database_session.begin():

            # 1. Get the OAuthSession from the database and validate it.

            oauth_session_stmt = select(OAuthSession).where(
                OAuthSession.guid == auth_token_subject,
                OAuthSession.session_group == auth_token_session_group,
            )
            oauth_session: Optional[OAuthSession] = (
                await database_session.scalars(oauth_session_stmt)
            ).first()

            if oauth_session is None:
                raise Exception("auth_token invalid: oauth_session not found")

            # 2. Get the Handle from the database and validate it.

            oauth_session_handle_stmt = select(Handle).where(
                Handle.guid == auth_token_subject
            )
            oauth_session_handle: Handle = (
                await database_session.scalars(oauth_session_handle_stmt)
            ).one()

            # 3. Get the X-Repository header, defaulting to the current oauth session handle's guid.
            x_subject: str = request.headers.getone(
                "X-Subject", oauth_session_handle.guid
            )

            # If the subject of the request is the same as the subject of the auth token, then we have everything we
            # need and can return a full formed AuthToken.
            if x_subject == oauth_session_handle.guid:
                x_service: str = request.headers.getone(
                    "X-Service", oauth_session_handle.pds
                )

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

            if allow_permissions is False:
                raise Exception("policy violation: permissions not allowed")

            # 4. Get the permission record for the oauth session handle to the x_repository guid.
            permission_stmt = select(Permission).where(
                Permission.guid == oauth_session_handle.guid,
                Permission.target_guid == x_subject,
                Permission.permission > 0,
            )
            permission: Optional[Permission] = (
                await database_session.scalars(permission_stmt)
            ).first()

            # If no permission is found, then the oauth session handle does not have permission to make calls on behalf
            # of that guid.
            if permission is None:
                raise Exception("policy violation: access denied")

            subject_handle_stmt = select(Handle).where(
                Handle.guid == permission.target_guid
            )
            subject_handle: Handle = (
                await database_session.scalars(subject_handle_stmt)
            ).one()

            app_password_session_stmt = select(AppPasswordSession).where(
                AppPasswordSession.guid == subject_handle.guid,
            )
            app_password_session: Optional[AppPasswordSession] = (
                await database_session.scalars(app_password_session_stmt)
            ).first()

            # TODO: Select a "valid" oauth session.
            target_oauth_session_stmt = select(OAuthSession).where(
                OAuthSession.guid == subject_handle.guid,
            )
            target_oauth_session: Optional[OAuthSession] = (
                await database_session.scalars(target_oauth_session_stmt)
            ).first()

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
    except Exception:
        logging.exception("auth_token_helper: exception")
        raise AuthHelperException()
