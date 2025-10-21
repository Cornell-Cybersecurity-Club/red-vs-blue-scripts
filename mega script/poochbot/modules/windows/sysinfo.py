import logging
import platform

import rich

from poochbot.utils import *

logger = logging.getLogger(__name__)

def sysinfo() -> None:
    """Displays information on the system"""

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
