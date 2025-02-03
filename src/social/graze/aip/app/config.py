import logging
import os
import json
from logging.config import dictConfig


def configure_logging():
    logging_config_file = os.getenv("LOGGING_CONFIG_FILE", "")

    if len(logging_config_file) > 0:
        with open(logging_config_file) as fl:
            dictConfig(json.load(fl))
        return

    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
