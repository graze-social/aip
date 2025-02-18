from datetime import datetime, timezone, timedelta
import json
import logging
from typing import Optional
from aiohttp import web
from pydantic import BaseModel, ValidationError, field_validator
import redis.asyncio as redis
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert

from social.graze.aip.app.config import (
    APP_PASSWORD_REFRESH_QUEUE,
    DatabaseSessionMakerAppKey,
    RedisPoolAppKey,
)
from social.graze.aip.app.handlers.helpers import auth_token_helper
from social.graze.aip.model.app_password import AppPassword


logger = logging.getLogger(__name__)


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
        # TODO: Fix the returned error message when JSON fails because of pydantic validation functions.
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

            now = datetime.now(timezone.utc)

            async with database_session.begin():
                if app_password_operation.value is None:
                    stmt = delete(AppPassword).where(
                        AppPassword.guid == auth_token.guid
                    )
                    await database_session.execute(stmt)
                    await redis_session.zrem(
                        APP_PASSWORD_REFRESH_QUEUE, auth_token.guid
                    )
                else:
                    stmt = (
                        insert(AppPassword)
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

                    refresh_at = now + timedelta(0, 5)

                    await redis_session.zadd(
                        APP_PASSWORD_REFRESH_QUEUE,
                        {auth_token.guid: int(refresh_at.timestamp())},
                    )

                await database_session.commit()

            app_password_key = f"auth_session:app-password:{auth_token.guid}"
            await redis_session.delete(app_password_key)

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
