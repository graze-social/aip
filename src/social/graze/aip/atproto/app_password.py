from datetime import datetime, timezone, timedelta
import logging
from typing import Any, Dict, Optional
from aiohttp import ClientSession
import redis.asyncio as redis
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import (
    async_sessionmaker,
    AsyncSession,
)
from sqlalchemy.dialects.postgresql import insert
import sentry_sdk
from social.graze.aip.model.app_password import AppPassword, AppPasswordSession
from social.graze.aip.model.handles import Handle
from social.graze.aip.app.config import APP_PASSWORD_REFRESH_QUEUE, Settings

logger = logging.getLogger(__name__)


async def populate_session(
    http_session: ClientSession,
    database_session_maker: async_sessionmaker[AsyncSession],
    redis_session: redis.Redis,
    subject_guid: str,
    settings: Optional[Settings] = None,
) -> None:
    now = datetime.now(timezone.utc)
    async with database_session_maker() as database_session:
        async with database_session.begin():
            # 1. Get the handle by guid
            handle_stmt = select(Handle).where(Handle.guid == subject_guid)
            handle: Optional[Handle] = (
                await database_session.scalars(handle_stmt)
            ).first()

            if handle is None:
                raise ValueError(f"Handle not found for guid: {subject_guid}")

            # 2. Get the AppPassword by guid
            app_password_stmt = select(AppPassword).where(
                AppPassword.guid == subject_guid
            )
            app_password: Optional[AppPassword] = (
                await database_session.scalars(app_password_stmt)
            ).first()

            if app_password is None:
                raise ValueError(f"App password not found for guid: {subject_guid}")

            # 3. Get optional AppPasswordSession by guid
            app_password_session_stmt = select(AppPasswordSession).where(
                AppPasswordSession.guid == subject_guid
            )
            app_password_session: Optional[AppPasswordSession] = (
                await database_session.scalars(app_password_session_stmt)
            ).first()

            start_over = False
            access_token: str | None = None

            # Use settings if provided, otherwise use defaults
            access_token_expiry = settings.app_password_access_token_expiry if settings else 720
            refresh_token_expiry = settings.app_password_refresh_token_expiry if settings else 7776000
            
            # TODO: Pull this from the access token JWT claims payload
            access_token_expires_at = now + timedelta(0, access_token_expiry)

            refresh_token: str | None = None

            # TODO: Pull this from the refresh token JWT claims payload
            refresh_token_expires_at = now + timedelta(0, refresh_token_expiry)

            # 4. If AppPasswordSession exists: refresh it, update row, and return
            if app_password_session is not None:
                try:
                    refresh_url = f"{handle.pds}/xrpc/com.atproto.server.refreshSession"
                    headers = {
                        "Authorization": f"Bearer {app_password_session.refresh_token}"
                    }
                    # This could fail if the app password was revoked or if the server isn't honoring the expiration
                    # time of the refresh token. It's more likely that a user will remove / replace an app password.
                    # When that happens, we want to start over and create a new session.
                    async with http_session.post(
                        refresh_url, headers=headers
                    ) as response:
                        if response.status != 200:
                            raise Exception(
                                f"Failed to refresh session: {response.status}"
                            )

                        body: Dict[str, Any] = await response.json()
                        access_token = body.get("accessJwt", None)
                        refresh_token = body.get("refreshJwt", None)
                        is_active = body.get("active", False)
                        found_did = body.get("did", "")

                        if found_did != handle.did:
                            start_over = True

                        if not is_active:
                            start_over = True

                except Exception as e:
                    sentry_sdk.capture_exception(e)
                    logger.exception("Error refreshing session")
                    start_over = True

                if (
                    access_token is not None
                    and refresh_token is not None
                    and not start_over
                ):
                    update_session_stmt = (
                        update(AppPasswordSession)
                        .where(
                            AppPasswordSession.guid == app_password_session.guid,
                        )
                        .values(
                            access_token=access_token,
                            access_token_expires_at=access_token_expires_at,
                            refresh_token=refresh_token,
                            refresh_token_expires_at=refresh_token_expires_at,
                        )
                    )
                    await database_session.execute(update_session_stmt)

                    refresh_ratio = settings.token_refresh_before_expiry_ratio if settings else 0.8
                    expires_in_mod = access_token_expiry * refresh_ratio
                    refresh_at = now + timedelta(0, expires_in_mod)
                    await redis_session.zadd(
                        APP_PASSWORD_REFRESH_QUEUE,
                        {handle.guid: int(refresh_at.timestamp())},
                    )

            if app_password_session is None or start_over:
                try:
                    refresh_url = f"{handle.pds}/xrpc/com.atproto.server.createSession"
                    headers = {}
                    payload = {
                        "identifier": handle.did,
                        "password": app_password.app_password,
                    }
                    async with http_session.post(
                        refresh_url, headers=headers, json=payload
                    ) as response:
                        if response.status != 200:
                            raise Exception(
                                f"Failed to refresh session: {response.status}"
                            )

                        body: Dict[str, Any] = await response.json()
                        access_token = body.get("accessJwt", None)
                        refresh_token = body.get("refreshJwt", None)
                        is_active = body.get("active", False)
                        found_did = body.get("did", "")

                        # It'd be pretty wild if this didn't match the handle, but would also lead to some really
                        # unexpected behavior.
                        if found_did != handle.did:
                            raise ValueError(
                                f"Handle did does not match found did: {handle.did} != {found_did}"
                            )

                        if not is_active:
                            raise ValueError("Handle is not active.")

                except Exception as e:
                    sentry_sdk.capture_exception(e)
                    logger.exception("Error creating session")

                # 5. Create new AppPasswordSession
                if access_token is not None and refresh_token is not None:
                    update_session_stmt = (
                        insert(AppPasswordSession)
                        .values(
                            [
                                {
                                    "guid": handle.guid,
                                    "access_token": access_token,
                                    "access_token_expires_at": access_token_expires_at,
                                    "refresh_token": refresh_token,
                                    "refresh_token_expires_at": refresh_token_expires_at,
                                    "created_at": now,
                                }
                            ]
                        )
                        .on_conflict_do_update(
                            index_elements=["guid"],
                            set_={
                                "access_token": access_token,
                                "access_token_expires_at": access_token_expires_at,
                                "refresh_token": refresh_token,
                                "refresh_token_expires_at": refresh_token_expires_at,
                            },
                        )
                    )
                    await database_session.execute(update_session_stmt)

                    refresh_ratio = settings.token_refresh_before_expiry_ratio if settings else 0.8
                    expires_in_mod = access_token_expiry * refresh_ratio
                    refresh_at = now + timedelta(0, expires_in_mod)
                    await redis_session.zadd(
                        APP_PASSWORD_REFRESH_QUEUE,
                        {handle.guid: int(refresh_at.timestamp())},
                    )
