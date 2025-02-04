import os
import logging
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import jinja2
from aiohttp import web
import aiohttp_jinja2
import aiohttp

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from social.graze.aip.app.config import Settings, SettingsAppKey
from social.graze.aip.resolve.handle import resolve_subject

logger = logging.getLogger(__name__)
DatabaseAppKey = web.AppKey("database", AsyncEngine)
SessionAppKey = web.AppKey("http_session", aiohttp.ClientSession)

async def handle_index(request):
    return await aiohttp_jinja2.render_template_async("index.html", request, context={})


async def handle_atproto_login(request):
    return await aiohttp_jinja2.render_template_async(
        "atproto_login.html", request, context={}
    )


async def handle_atproto_login_submit(request):
    return await aiohttp_jinja2.render_template_async(
        "atproto_login.html", request, context={}
    )


async def handle_atproto_callback(request):
    raise web.HTTPFound("/auth/atproto/debug")


async def handle_atproto_debug(request):
    return await aiohttp_jinja2.render_template_async(
        "atproto_debug.html", request, context={}
    )


async def handle_jwks(request):
    return await aiohttp_jinja2.render_template_async(
        "atproto_debug.html", request, context={}
    )


async def handle_atproto_client_metadata(request):
    return await aiohttp_jinja2.render_template_async(
        "atproto_debug.html", request, context={}
    )


async def handle_settings(request):
    return await aiohttp_jinja2.render_template_async(
        "settings.html", request, context={}
    )


async def handle_set_app_password(request):
    return await aiohttp_jinja2.render_template_async(
        "settings.html", request, context={}
    )


async def handle_change_permission(request):
    return await aiohttp_jinja2.render_template_async(
        "settings.html", request, context={}
    )


async def handle_internal_me(request):
    return await aiohttp_jinja2.render_template_async(
        "settings.html", request, context={}
    )


async def handle_internal_ready(request):
    return await aiohttp_jinja2.render_template_async(
        "settings.html", request, context={}
    )


async def handle_internal_alive(request):
    return await aiohttp_jinja2.render_template_async(
        "settings.html", request, context={}
    )

async def handle_internal_resolve(request):
    subjects = request.query.getall("subject", [])

    # TODO: Use a pydantic list structure for this.
    results = []
    for subject in subjects:
        resolved_subject = await resolve_subject(request.app[SessionAppKey], subject)
        if resolved_subject is None:
            continue
        results.append(resolved_subject.dict())
    return web.json_response(results)

async def handle_xrpc_proxy(request):
    return await aiohttp_jinja2.render_template_async(
        "settings.html", request, context={}
    )

async def startup(app):
    settings = app[SettingsAppKey]

    app[DatabaseAppKey] = create_async_engine(str(settings.pg_dsn))

    app[SessionAppKey] = aiohttp.ClientSession()

async def shutdown(app):
    await app[DatabaseAppKey].dispose()
    await app[SessionAppKey].close()


async def start_web_server(settings: Optional[Settings] = None):

    if settings is None:
        settings = Settings()

    app = web.Application()

    app[SettingsAppKey] = settings

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
    app.add_routes(
        [web.get("/auth/atproto/client-metadata.json", handle_atproto_client_metadata)]
    )

    app.add_routes(
        [
            web.get("/settings", handle_settings),
            web.post("/settings/app_password", handle_set_app_password),
            web.post("/settings/permissions", handle_change_permission),
        ]
    )

    app.add_routes(
        [
            web.get("/internal/alive", handle_internal_me),
            web.get("/internal/ready", handle_internal_me),
            web.get("/internal/api/me", handle_internal_me),
            web.get("/internal/api/resolve", handle_internal_resolve),
        ]
    )

    app.add_routes(
        [
            web.get("/xrpc/{method}", handle_xrpc_proxy),
            web.post("/xrpc/{method}", handle_xrpc_proxy),
        ]
    )

    jinja_env = aiohttp_jinja2.setup(
        app,
        enable_async=True,
        loader=jinja2.FileSystemLoader(os.path.join(os.getcwd(), "templates")),
    )

    app["static_root_url"] = "/static"

    app.on_startup.append(startup)
    app.on_cleanup.append(shutdown)

    return app
