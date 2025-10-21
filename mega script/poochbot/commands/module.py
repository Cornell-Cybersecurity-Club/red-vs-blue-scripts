import logging
import rich
from poochbot.utils import *

logger = logging.getLogger(__name__)

from poochbot.modules.util.parsereadme import parsereadme
from poochbot.modules.windows.useraudit import useraudit
from poochbot.modules.windows.lgpo import lgpo
from poochbot.modules.windows.baseline import baseline
from poochbot.modules.windows.sysinfo import sysinfo
from poochbot.modules.windows.services import services

modules = {
    "parsereadme": parsereadme,
    "pr": parsereadme,
    "useraudit": useraudit,
    "ua": useraudit,
    "lgpo": lgpo,
    "gp": lgpo,
    "baseline": baseline,
    "bl": baseline,
    "sysinfo": sysinfo,
    "si": sysinfo,
    "services": services,
    "sv": services,
}

class ModuleCommands():
    
    def do_module(self, arg: str) -> None:
        """Run specific modules to fix vulnrabilities"""

        self._toplevel_subcommand("module", arg)

    def _do_module_list(self) -> None:
        """List all available modules"""
        rich.print("Module List:")
        rich.print(" - parsereadme (pr): Parses the readme into options")
        rich.print(" - useraudit (ua): Automates auditing and securing users")
        rich.print(" - lgpo (gp): Backup and import GPO settings")
        rich.print(" - baseline (bl): Compare current system information and lists against baselines")
        rich.print(" - sysinfo (si): Show information on the system")
        rich.print(" - services (sv): Sets most commonly changed service settings")

    def _do_module_run(self, modulename: str) -> None:
        """Runs the specified module"""
        if modulename in modules:
            modules[modulename]()
        else:
            logger.error(f"module {modulename} does not exist")
