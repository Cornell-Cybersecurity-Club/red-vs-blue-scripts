import logging
from dataclasses import dataclass

import rich
import rich.table
from poochbotold import module
from poochbotold.options import OPTIONS
from poochbotold.utils import *

logger = logging.getLogger(__name__)

@dataclass
class Service:
    name: str
    display_name: str
    startup_type: str
    status: str

import poochbotold.defaults

class Services(module.Module):
    """Compares services installed on the computer with known good services."""

    name: str = "windows.services"
    aliases = ["services", "svc", "s"]
    applies_to: list[OperatingSystem] = [
        OperatingSystem.WINDOWS,
        OperatingSystem.WINDOWS_SERVER,
    ]
    services: list[Service]

    def __init__(self) -> None:
        super().__init__()
        self.services = []

    def _gen_services(self) -> None:
        """Get the list of services installed on the machine"""

        list = psshell(
            'Get-Service | select -Property "Name", "DisplayName", "StartType", "Status" | Format-List'
        )
        for service_group in list.strip().split("\n\n"):
            lines = service_group.splitlines()
            name = lines[0].split(":")[1].strip()
            display_name = lines[1].split(":")[1].strip()
            startup_type = lines[2].split(":")[1].strip()
            status = lines[3].split(":")[1].strip()

            self.services.append(Service(name, display_name, startup_type, status))

    def _gen_table(self) -> rich.table.Table:
        """Creates a rich table showing comparisons between current services and default services"""

        defaults: list[Service]
        match OPTIONS["OS"].value:
            case OperatingSystem.WINDOWS:
                defaults = poochbotold.defaults.WINDOWS_10_21H1_SERVICES
            case OperatingSystem.WINDOWS_SERVER:
                defaults = poochbotold.defaults.WINDOWS_SERVER_2019_SERVICES

        table = rich.table.Table(
            "Name", "Display Name", "Startup Type", "Status", title="Services"
        )
        for existing_service in self.services:
            name = existing_service.name
            display_name = existing_service.display_name
            startup_type = existing_service.startup_type
            status = existing_service.status

            default_comparison: Service = None  # this is the "default" version of the existing service on the computer.
            # user services have _xxxxxx at the end which is different
            for default in defaults:
                if (
                    default.name == existing_service.name
                    or default.name.split("_")[0] == existing_service.name.split("_")[0]
                ):
                    default_comparison = default

            if default_comparison == None:
                name = f"[dark_orange]{name}[/]"
                display_name = f"[dark_orange]{display_name}[/]"
                startup_type = f"[dark_orange]{startup_type}[/]"
                status = f"[dark_orange]{status}[/]"
            else:
                if existing_service.startup_type != default_comparison.startup_type:
                    startup_type = f"[red]{startup_type}[/]"
                if existing_service.status != default_comparison.status:
                    status = f"[red]{status}[/]"

            table.add_row(name, display_name, startup_type, status)
        return table

    def run(self) -> None:
        """Prints a table showing the comparison of services installed on this machine and the defaults"""

        self._gen_services()
        rich.print(self._gen_table())
