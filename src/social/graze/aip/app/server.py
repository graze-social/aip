import os
import logging
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import jinja2
from aiohttp import web
import aiohttp_jinja2

logger = logging.getLogger(__name__)

async def handle_index(request):
    return await aiohttp_jinja2.render_template_async(
        "index.html", request, context={}
    )

async def start_web_server():
    app = web.Application()

    app.add_routes([web.static("/static", os.path.join(os.getcwd(), "static"), append_version=True)])

    app.add_routes([web.get("/", handle_index)])
    app.add_routes([web.get("/auth/", handle_index)])
    app.add_routes([web.get("/", handle_index)])

    jinja_env = aiohttp_jinja2.setup(
        app, enable_async=True, loader=jinja2.FileSystemLoader(os.path.join(os.getcwd(), "templates"))
    )

    app["static_root_url"] = "/static"

    return app
