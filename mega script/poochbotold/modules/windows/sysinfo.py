import logging
import os
import platform

import rich

from poochbotold import module
from poochbotold.utils import *

logger = logging.getLogger(__name__)

class SysInfo(module.Module):
    """Collects and displays system information."""

    name: str = "windows.sysinfo"
    aliases = ["sysinfo", "si"]
    applies_to: list[OperatingSystem] = [
        OperatingSystem.WINDOWS,
        OperatingSystem.WINDOWS_SERVER,
    ]

    def run(self) -> None:
        """Collects and displays system information."""

        rich.print(
            "\n".join(
                [
                    "[bold]System Info[/]",
                    f"Platform: {platform.platform()}",
                    f"Machine Type: {platform.machine()}",
                    f"Processor: {platform.processor()}",
                    f"System: {platform.system()}",
                    f"Release: {platform.release()}",
                    f"Version: {platform.version()}",
                    f"Win32 Version: {platform.win32_ver()}",
                    f"Win32 Edition: {platform.win32_edition()}",
                ]
            )
        )
