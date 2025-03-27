import asyncio
import contextlib
import os
import logging
from time import time
from typing import (
    Optional,
)
from aio_statsd import TelegrafStatsdClient
import jinja2
from aiohttp import web
import aiohttp_jinja2
import aiohttp
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
)
import sentry_sdk
from sentry_sdk.integrations.aiohttp import AioHttpIntegration

from social.graze.aip.app.config import (
    DatabaseAppKey,
    DatabaseSessionMakerAppKey,
    HealthGaugeAppKey,
    RedisClientAppKey,
    RedisPoolAppKey,
    SessionAppKey,
    Settings,
    SettingsAppKey,
    AppPasswordRefreshTaskAppKey,
    OAuthRefreshTaskAppKey,
    TelegrafStatsdClientAppKey,
    TickHealthTaskAppKey,
)
from social.graze.aip.app.handlers.app_password import handle_internal_app_password
from social.graze.aip.app.handlers.credentials import handle_internal_credentials
from social.graze.aip.app.handlers.internal import (
    handle_internal_alive,
    handle_internal_me,
    handle_internal_ready,
    handle_internal_resolve,
)
from social.graze.aip.app.handlers.oauth import (
    handle_atproto_callback,
    handle_atproto_client_metadata,
    handle_atproto_debug,
    handle_atproto_login,
    handle_atproto_login_submit,
    handle_atproto_refresh,
    handle_jwks,
)
from social.graze.aip.app.handlers.permissions import handle_internal_permissions
from social.graze.aip.app.handlers.proxy import handle_xrpc_proxy
from social.graze.aip.app.tasks import (
    oauth_refresh_task,
    tick_health_task,
    app_password_refresh_task,
)
from social.graze.aip.model.health import HealthGauge

logger = logging.getLogger(__name__)


async def handle_index(request: web.Request):
    return await aiohttp_jinja2.render_template_async("index.html", request, context={})


async def background_tasks(app):
    logger.info("Starting up")
    settings: Settings = app[SettingsAppKey]

    engine = create_async_engine(str(settings.pg_dsn))
    app[DatabaseAppKey] = engine
    database_session = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    app[DatabaseSessionMakerAppKey] = database_session

    trace_config = aiohttp.TraceConfig()

    if settings.debug:

        async def on_request_start(
            session, trace_config_ctx, params: aiohttp.TraceRequestStartParams
        ):
            logging.info("Starting request: %s", params)

        async def on_request_chunk_sent(
            session, trace_config_ctx, params: aiohttp.TraceRequestChunkSentParams
        ):
            logging.info("Chunk sent: %s", str(params.chunk))

        async def on_request_end(session, trace_config_ctx, params):
            logging.info("Ending request: %s", params)

        trace_config.on_request_start.append(on_request_start)
        trace_config.on_request_end.append(on_request_end)
        trace_config.on_request_chunk_sent.append(on_request_chunk_sent)

    app[SessionAppKey] = aiohttp.ClientSession(trace_configs=[trace_config])

    app[RedisPoolAppKey] = redis.ConnectionPool.from_url(str(settings.redis_dsn))

    app[RedisClientAppKey] = redis.Redis(
        connection_pool=redis.ConnectionPool.from_url(str(settings.redis_dsn))
    )

    statsd_client = TelegrafStatsdClient(
        host=settings.statsd_host, port=settings.statsd_port, debug=settings.debug
    )
    await statsd_client.connect()
    app[TelegrafStatsdClientAppKey] = statsd_client

    logger.info("Startup complete")

    app[TickHealthTaskAppKey] = asyncio.create_task(tick_health_task(app))
    app[OAuthRefreshTaskAppKey] = asyncio.create_task(oauth_refresh_task(app))
    app[AppPasswordRefreshTaskAppKey] = asyncio.create_task(
        app_password_refresh_task(app)
    )

    yield

    print("Shutting down background tasks")

    app[TickHealthTaskAppKey].cancel()
    app[OAuthRefreshTaskAppKey].cancel()
    app[AppPasswordRefreshTaskAppKey].cancel()

    with contextlib.suppress(asyncio.exceptions.CancelledError):
        await app[TickHealthTaskAppKey]

    with contextlib.suppress(asyncio.exceptions.CancelledError):
        await app[OAuthRefreshTaskAppKey]

    with contextlib.suppress(asyncio.exceptions.CancelledError):
        await app[AppPasswordRefreshTaskAppKey]

    await app[DatabaseAppKey].dispose()
    await app[SessionAppKey].close()
    await app[RedisPoolAppKey].aclose()
    await app[TelegrafStatsdClientAppKey].close()

@web.middleware
async def sentry_middleware(request: web.Request, handler):
    request_method: str = request.method
    request_path = request.path

    try:
        response = await handler(request)
        return response
    except Exception as e:
        sentry_sdk.capture_exception(e)
        raise e

@web.middleware
async def statsd_middleware(request: web.Request, handler):
    statsd_client = request.app[TelegrafStatsdClientAppKey]
    request_method: str = request.method
    request_path = request.path

    start_time: float = time()
    response_status_code = 0

    try:
        response = await handler(request)
        response_status_code = response.status
        return response
    except Exception as e:
        statsd_client.increment(
            "aip.server.request.exception",
            1,
            tag_dict={
                "exception": type(e).__name__,
                "path": request_path,
                "method": request_method,
            },
        )
        raise e
    finally:
        statsd_client.timer(
            "aip.server.request.time",
            time() - start_time,
            tag_dict={"path": request_path, "method": request_method},
        )
        statsd_client.increment(
            "aip.server.request.count",
            1,
            tag_dict={
                "path": request_path,
                "method": request_method,
                "status": response_status_code,
            },
        )


async def shutdown(app):
    await app[DatabaseAppKey].dispose()
    await app[SessionAppKey].close()
    await app[RedisPoolAppKey].aclose()
    await app[TelegrafStatsdClientAppKey].close()


async def start_web_server(settings: Optional[Settings] = None):

    if settings is None:
        settings = Settings()  # type: ignore
    if settings.sentry_dsn:
        sentry_sdk.init(
            dsn=settings.sentry_dsn,
            send_default_pii=True,
            integrations=[AioHttpIntegration()]
        )
    app = web.Application(middlewares=[statsd_middleware, sentry_middleware])

    app[SettingsAppKey] = settings
    app[HealthGaugeAppKey] = HealthGauge()

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
    app.add_routes([web.get("/auth/atproto/refresh", handle_atproto_refresh)])

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
            web.get("/internal/api/credentials", handle_internal_credentials),
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

    # app.on_startup.append(startup)
    # app.on_cleanup.append(shutdown)
    app.cleanup_ctx.append(background_tasks)

    return app
