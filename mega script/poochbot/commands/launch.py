import logging
import subprocess
from poochbot.utils import *

logger = logging.getLogger(__name__)

class LaunchCommands():

    def do_launch(self, program: str) -> None:
        """
        Launch a program that is bundled with PoochBot.

        pa:   Policy Analyzer
        bcu:  Bulk Crap Uninstaller (installer)
        proc: Process Explorer
        ar:   Auto Runs
        ae:   Access Enum
        bc:   Beyond Compare

        Usage:
        `launch <program>`

        Example:
        `(PoochBot) > launch proc`
        """

        launchers = {
            "Policy Analyzer": lambda: subprocess.Popen(
                ".\\support\\windows\\programs\\PolicyAnalyzer_40\\PolicyAnalyzer.exe"
            ),
            "Bulk Crap Uninstaller": lambda: subprocess.Popen(
                ".\\support\\windows\\programs\\BCUSetup.exe"
            ),
            "Process Explorer": lambda: subprocess.Popen(
                ".\\support\\windows\\programs\\SysinternalsSuite\\procexp.exe"
            ),
            "Auto Runs": lambda: subprocess.Popen(
                ".\\support\\windows\\programs\\SysinternalsSuite\\Autoruns.exe"
            ),
            "Access Enum": lambda: subprocess.Popen(
                ".\\support\\windows\\programs\\SysinternalsSuite\\AccessEnum.exe"
            ),
            "Beyond Compare": lambda: subprocess.Popen(
                ".\\support\\windows\\programs\\BCompare-5.0.4.30422.exe"
            ),
        }
        aliases = {
            "pa": "Policy Analyzer",
            "bcu": "Bulk Crap Uninstaller",
            "proc": "Process Explorer",
            "ar": "Auto Runs",
            "ae": "Access Enum",
            "bc": "Beyond Compare",
        }

        name = aliases.get(program)
        if not name:
            logger.error("Could not find program.")
            return

        try:
            logger.info(f"Opening {name}.")
            launchers[name]()
        except:
            logger.exception(f"Could not open {name}.")