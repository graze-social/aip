import datetime
import logging
from typing import (
    Literal,
    Optional,
    Dict,
    List,
    Any,
)
from aiohttp import web
from pydantic import BaseModel, PositiveInt, RootModel, ValidationError
from sqlalchemy import delete, select
import sentry_sdk

from social.graze.aip.app.config import (
    DatabaseSessionMakerAppKey,
    TelegrafStatsdClientAppKey,
)
from social.graze.aip.app.handlers.helpers import auth_token_helper
from social.graze.aip.model.oauth import (
    Permission,
    upsert_permission_stmt,
)

logger = logging.getLogger(__name__)


class PermissionOperation(BaseModel):
    op: Literal["test", "add", "remove", "replace"]
    path: str

    # TODO: Make these permission values mean something.
    value: Optional[PositiveInt] = None


PermissionOperations = RootModel[list[PermissionOperation]]


async def handle_internal_permissions(request: web.Request) -> web.Response:
    database_session_maker = request.app[DatabaseSessionMakerAppKey]
    statsd_client = request.app[TelegrafStatsdClientAppKey]

    # TODO: Support GET requests that returns paginated permission objects.

    try:
        data = await request.read()
        operations = PermissionOperations.model_validate_json(data)
    except (OSError, ValidationError) as e:
        sentry_sdk.capture_exception(e)
        return web.Response(text="Invalid JSON", status=400)

    try:
        async with (database_session_maker() as database_session,):
            auth_token = await auth_token_helper(
                database_session, statsd_client, request, allow_permissions=False
            )
            if auth_token is None:
                return web.json_response(status=401, data={"error": "Not Authorized"})

            # TODO: Fail with error if the user does not have an app-password set.

            now = datetime.datetime.now(datetime.timezone.utc)

            async with database_session.begin():
                results: List[Dict[str, Any]] = []

                for operation in operations.root:
                    guid = operation.path.removeprefix("/")
                    if guid == auth_token.guid:
                        return web.json_response(
                            status=400, data={"error": "Invalid permission"}
                        )

                    if (
                        operation.op == "add" or operation.op == "replace"
                    ) and operation.value is not None:

                        # TODO: Fail if the guid is unknown. Clients should use /internal/api/resolve on all subjects
                        #       prior to setting permissions.

                        stmt = upsert_permission_stmt(
                            guid=guid,
                            target_guid=auth_token.guid,
                            permission=operation.value,
                            created_at=now,
                        )
                        await database_session.execute(stmt)

                    if operation.op == "remove":
                        stmt = delete(Permission).where(
                            Permission.guid == guid,
                            Permission.target_guid == auth_token.guid,
                        )
                        await database_session.execute(stmt)

                    if operation.op == "test":
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
        sentry_sdk.capture_exception(e)
        logging.exception("handle_internal_permissions: web.HTTPException")
        raise e
    except Exception as e:
        sentry_sdk.capture_exception(e)
        logging.exception("handle_internal_permissions: Exception")
        return web.json_response(status=500, data={"error": "Internal Server Error"})
