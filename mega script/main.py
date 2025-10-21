import os

os.system("")

import logging
import logging.config

import yaml
from poochbot.poochbot import PoochBot

logger = logging.getLogger("poochbot")

with open("support/logging.yml", "r") as f:
    logging.config.dictConfig(yaml.load(f, Loader=yaml.SafeLoader))

print("")

if __name__ == "__main__":
    pb = PoochBot()
    pb.start()
