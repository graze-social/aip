import os
from aiohttp import web

from social.graze.aip.app.config import configure_logging
from social.graze.aip.app.server import start_web_server


def invoke():
    configure_logging()
    web.run_app(start_web_server())


if __name__ == "__main__":
    invoke()
