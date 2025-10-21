import os

os.system("")

import logging
import logging.config

import yaml
from poochbotold.poochbot import PoochBot

logger = logging.getLogger("poochbot")

with open("support/logging.yml", "r") as f:
    logging.config.dictConfig(yaml.load(f, Loader=yaml.SafeLoader))

if __name__ == "__main__":
    pb = PoochBot()
    pb.start()
