import os
from aiohttp import web
import logging
from logging.config import dictConfig
import json


def configure_logging():
    logging_config_file = os.getenv("LOGGING_CONFIG_FILE", "")

    if len(logging_config_file) > 0:
        with open(logging_config_file) as fl:
            dictConfig(json.load(fl))
        return

    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)


def invoke():
    configure_logging()

    from social.graze.aip.app.server import start_web_server

    web.run_app(start_web_server())


if __name__ == "__main__":
    invoke()
