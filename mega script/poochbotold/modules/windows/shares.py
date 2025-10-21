import logging
from dataclasses import dataclass

import rich
import rich.table

from poochbotold import module
from poochbotold.utils import *

logger = logging.getLogger(__name__)

@dataclass
class Share:
    name: str
    path: str
    description: str

class Shares(module.Module):
    """Checks and prompts you to remove shares on the computer."""

    name: str = "windows.shares"
    aliases = ["shares", "share"]
    applies_to: list[OperatingSystem] = [
        OperatingSystem.WINDOWS,
        OperatingSystem.WINDOWS_SERVER,
    ]
    shares: list[Share]

    def do_show_shares(self, arg: str):
        """Show a list of shares. Does not analyze them."""

        self._get_shares()
        self._display_shares()

    def run(self):
        """Show a list of shares and analyzes them."""

        self._get_shares()
        self._display_shares()
        self._analyze_shares()

    def _get_shares(self):
        """Gets the current list of shares"""

        values = {}
        for name, output in (
            (
                "name",
                cmdshell('powershell -c "get-smbshare | select-object name'),
            ),
            (
                "path",
                cmdshell('powershell -c "get-smbshare | select-object path'),
            ),
            (
                "description",
                cmdshell('powershell -c "get-smbshare | select-object description'),
            ),
        ):
            values[name] = []
            flag = False
            for line in output.splitlines()[:-2]:
                if flag:
                    values[name] += [line.rstrip()]

                if "-" in line:
                    flag = True

        self.shares = []
        for name, path, description in zip(
            values["name"],
            values["path"],
            values["description"],
        ):
            self.shares += [Share(name, path, description)]

    def _display_shares(self):
        """Shows a list of shares"""

        table = rich.table.Table("Name", "Path", "Description", title="Shares")
        for share in self.shares:
            table.add_row(share.name, share.path, share.description)
        rich.print(table)

    def _analyze_shares(self):
        """Analyzes the list of shares"""

        for share in self.shares:
            if share.name not in ["ADMIN$", "C$", "IPC$"]:
                logger.info(
                    f"Detected a potentially unauthorized share.\nName: {share.name}\nPath: {share.path}\nDescription: {share.description}"
                )
                rich.print("[bold]Remove this share? (y/N) [/]", end="")
                if input().lower() == "y":
                    try:
                        cmdshell(f"net share {share.name} /delete")
                    except:
                        logger.error(f"Failed removing {share.name}.")
                    else:
                        logger.info(f"Removed {share.name}.")
                else:
                    logger.info("Aborting.")
