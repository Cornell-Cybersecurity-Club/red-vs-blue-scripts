import json

import rich
import rich.prompt
import rich.table

from poochbot.utils import *
from poochbot.options import *

class OptionsCommands():
    
    def do_options(self, arg: str) -> None:
        """Set options required for a modules to run."""

        self._toplevel_subcommand("options", arg)

    def _do_options_list(self) -> None:
        """Prints list of PoochBot options with their current values"""

        rich.print(json.dumps(OPTIONS, indent=4))

    def _do_options_set(self, option: str) -> None:
        """Sets an option to a given value using the given string format: `PATH.TO.OPTION=VALUE`"""

        if "=" in option:
            # split keys and values as lists if needed
            key, value = option.split("=")

            key = key.upper().split(".")
            if "," in value:
                value = value.split(",")

            # make sure options path is valid
            def checkoption(opschem, i):
                if i < len(key) - 1:
                    if not isinstance(opschem[key[i]], dict):
                        raise Exception()

                    checkoption(opschem[key[i]], i + 1)
                else:
                    if not key[i] in opschem or isinstance(opschem[key[i]], dict):
                        raise Exception()

            try:
                checkoption(OPTIONS_SCHEMA, 0)
            except:
                op = option.split("=")[0]
                logger.error(f"option '{op}' does not exist")
                return

            # set the value
            def setoption(op, i):
                if i == len(key) - 1:
                    op[key[i]] = value
                else:
                    setoption(op[key[i]], i + 1)
            
            setoption(OPTIONS, 0)

            # make sure values are in correct type
            match_types(OPTIONS, OPTIONS_SCHEMA, OPTIONS_DEFAULTS)

            rich.print("Option successfully set\n")

        else:
            logger.error("To use this command you need an '='")

    def _do_options_revert(self) -> None:
        """Reverts all options to defaults (Except OS and OS VERSION)"""

        ostemp = OPTIONS["OS"]
        osversiontemp = OPTIONS["OS_VERSION"]

        resetoptionsfile()
        load_options()
        OPTIONS["OS"] = ostemp
        OPTIONS["OS_VERSION"] = osversiontemp
        save_options()

        rich.print("Options successfully reverted to defaults\n")

    def _do_options_save(self) -> None:
        """Save options to json file C:/PoochBot/Data/options.json"""

        save_options()

        rich.print("Options successfully saved\n")

    def _do_options_load(self) -> None:
        """Load options from json file C:/PoochBot/Data/options.json"""

        load_options()

        rich.print("Options successfully loaded\n")
