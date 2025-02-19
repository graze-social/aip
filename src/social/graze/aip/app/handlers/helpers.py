import json
import logging
from typing import (
    Final,
    Optional,
    Dict,
)
from aiohttp import web
from jwcrypto import jwt
from pydantic import BaseModel, ConfigDict
import redis.asyncio as redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
)

from social.graze.aip.app.config import (
    SettingsAppKey,
)
from social.graze.aip.model.handles import Handle
from social.graze.aip.model.oauth import OAuthSession, Permission

logger = logging.getLogger(__name__)


class AuthToken(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    oauth_session: Optional[OAuthSession] = None
    app_password_session: Optional[str] = None

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
) -> Optional[OAuthSession]:
    try:
        async with database_session.begin():
            # is_self = auth_token.subject == auth_token.context_subject

            # TODO: Make these redis calls whole-object caches of the auth session. The issuer, DPoP key, etc. is
            # needed, so just caching the access token isn't enough to practically use it as-is.

            # # 1. Get an app-password session from redis if it exists. This is a cheap operation, so get it out of
            # #    the way up front.
            # app_password_key = f"auth_session:app-password:{auth_token.context_guid}"
            # cached_app_password_value: bytes = await redis_session.get(app_password_key)
            # if cached_app_password_value is not None:
            #     # TODO: Deccrypt the value
            #     return cached_app_password_value.decode("utf-8")

            # # 2. If is_self, then get an oauth session from redis if it exists.
            # if is_self:
            #     oauth_session_key = f"auth_session:oauth:{auth_token.context_guid}"
            #     cached_oauth_session_value: bytes = await redis_session.get(
            #         oauth_session_key
            #     )
            #     if cached_oauth_session_value is not None:
            #         # TODO: Deccrypt the value
            #         return cached_oauth_session_value.decode("utf-8")

            # if attempt_refresh is False:
            #     return None

            # TODO: Make the above redis calls a single mget operation.

            # 3. If not is_self, then get the app-password from the DB, create a session, cache it, and return it.
            # TODO: Implement this.

            # 4. If not is_self, return an error because a valid app-password session is required.
            # if not is_self:
            #     return None

            # 5. If is_self, then get an oauth session from the database if it exists.
            # TODO: Implement this.

            oauth_session_stmt = select(OAuthSession).where(
                OAuthSession.guid == auth_token.context_guid
            )
            oauth_session: Optional[OAuthSession] = (
                await database_session.scalars(oauth_session_stmt)
            ).first()
            await database_session.commit()

            return oauth_session
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
            x_repository: str = request.headers.getone(
                "X-Repository", oauth_session_handle.guid
            )

            # If the subject of the request is the same as the subject of the auth token, then we have everything we
            # need and can return a full formed AuthToken.
            if x_repository == oauth_session_handle.guid:
                x_pds: str = request.headers.getone("X-Pds", oauth_session_handle.pds)
                return AuthToken(
                    oauth_session=oauth_session,
                    guid=oauth_session_handle.guid,
                    subject=oauth_session_handle.did,
                    handle=oauth_session_handle.handle,
                    pds=oauth_session_handle.pds,
                    context_guid=oauth_session_handle.guid,
                    context_subject=oauth_session_handle.did,
                    context_pds=x_pds,
                )

            if allow_permissions is False:
                raise Exception("policy violation: permissions not allowed")

            # 4. Get the permission record for the oauth session handle to the x_repository guid.
            permission_stmt = select(Permission).where(
                Permission.guid == oauth_session_handle.guid,
                Permission.target_guid == x_repository,
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

            x_pds: str = request.headers.getone("X-Pds", subject_handle.pds)

            await database_session.commit()

            return AuthToken(
                oauth_session=oauth_session,
                guid=oauth_session_handle.guid,
                subject=oauth_session_handle.did,
                handle=oauth_session_handle.handle,
                pds=oauth_session_handle.pds,
                context_guid=subject_handle.guid,
                context_subject=subject_handle.did,
                context_pds=x_pds,
            )
    except Exception:
        logging.exception("auth_token_helper: exception")
        raise AuthHelperException()
