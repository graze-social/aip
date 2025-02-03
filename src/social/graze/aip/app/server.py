import os
import logging

logger = logging.getLogger(__name__)

async def handle_index(request):
    return await aiohttp_jinja2.render_template_async(
        "index.html", request, context={}
    )

async def start_web_server():
    app = web.Application()

    app.add_routes([web.static("/static", os.path.join(os.getcwd(), "static"), append_version=True)])

    app.add_routes([web.get("/", handle_index, name="surge")])

    jinja_env = aiohttp_jinja2.setup(
        app, enable_async=True, loader=jinja2.FileSystemLoader(os.path.join(os.getcwd(), "templates"))
    )
    jinja_env.globals.update(
        {
            "url": url_with_globals,
        }
    )

    app["static_root_url"] = "/static"

    return app
