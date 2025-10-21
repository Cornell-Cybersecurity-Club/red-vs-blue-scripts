import logging
import platform
import traceback

from poochbot import interpreter
from poochbot.options import *
from poochbot.utils import *

from poochbot.commands import checklist
from poochbot.commands import launch
from poochbot.commands import options
from poochbot.commands import module

logger = logging.getLogger(__name__)

# to add commands just make a new commands class in commands folder then add to implement list below. -Nolan
class PoochBot(interpreter.Interpreter,
               checklist.ChecklistCommands,
               launch.LaunchCommands,
               options.OptionsCommands,
               module.ModuleCommands):
    """Main class for instantiating PoochBot. Holds setup logic and implements all other command classes."""

    #region init

    def start(self) -> None:
        """Starts PoochBot init process and trys to start cmd loop"""

        initoptionsfile()
        self.loadchecklists()
        self.determineOS()
        self.initgenerated()
        
        logger.info("Starting Command Loop")
        self.printbanner()
        rich.print("[bold]Don't know where to start? Try 'help'[/]\n")

        while True:
            try:
                self.cmdloop()
            except (ExitException, KeyboardInterrupt):
                print("Thank you for using PoochBot.\n")
                return
            except Exception:
                logger.exception(f"An uncaught error has occurred:")
                traceback.print_exc()

    def determineOS(self) -> None:
        """Determines what operating system PoochBot is running on"""
        
        match platform.system():
            case "Windows":
                import ctypes

                try:
                    if ctypes.windll.shell32.IsUserAnAdmin():
                        logger.info("PoochBot is running as Administrator.")
                    else:
                        logger.critical(
                            "PoochBot is not running as Administrator. Certain functions will fail. \n"
                            'Restart by right clicking VS Code and choosing "Run as Administrator".'
                        )
                        input("Press enter to continue.\n")
                        exit(1)
                except AttributeError:
                    logger.error(
                        "Could not check if PoochBot is running as Administrator."
                    )

                match platform.win32_edition():
                    case "Enterprise" | "Professional" | "EnterpriseS" | "Core":
                        OPTIONS["OS"] = OperatingSystem.WINDOWS
                        logger.info("Detected Windows.")
                    case "Server" | "ServerStandard" | "ServerStandardEval":
                        OPTIONS["OS"] = OperatingSystem.WINDOWS_SERVER
                        logger.info("Detected Windows Server.")
                    case _:
                        logger.critical("Cannot determine edition of Windows.")
            case "Linux":
                try:
                    if cmdshell("whoami").rstrip() == "root":
                        logger.info("PoochBot is running as root.")
                    else:
                        logger.critical(
                            "PoochBot is not running as root. Certain functions will fail. \n"
                            "Restart by running the shell script with sudo."
                        )
                        input("Press enter to continue.\n")
                        exit(1)
                except:
                    logger.error("Could not check if PoochBot is running as root.")

                import distro

                match distro.id():
                    case "ubuntu":
                        OPTIONS["OS"] = OperatingSystem.UBUNTU
                        logger.info("Detected Ubuntu.")
                    case "debian":
                        OPTIONS["OS"] = OperatingSystem.DEBIAN
                        logger.info("Detected Debian.")
                    case _:
                        logger.critical("Cannot determine distribution of Linux.")

        if not OPTIONS["OS"].value:
            logger.critical(
                "Cannot determine operating system. Certain functions will be unavailable, but you can still view checklists."
            )
            
            inp = ""
            while not inp in ["W", "WS", "U", "D", "F"]:
                inp = input(
                    "Please enter W/WS/U/D/F to indicate your operating system. "
                ).upper()

            match inp:
                case "W":
                    OPTIONS["OS"] = OperatingSystem.WINDOWS
                case "WS":
                    OPTIONS["OS"] = OperatingSystem.WINDOWS_SERVER
                case "U":
                    OPTIONS["OS"] = OperatingSystem.UBUNTU
                case "D":
                    OPTIONS["OS"] = OperatingSystem.DEBIAN
                case "F":
                    OPTIONS["OS"] = OperatingSystem.FEDORA
                case _:
                    logger.critical("Could not determine operating system. Exiting.")

    def initgenerated(self):
        def initfolder(folder: str):
            try:
                cmdshell(f"mkdir C:\\PoochBot\\{folder}")
            except:
                ignore = "don't care"
        
        logger.info("Initializing generated folder structure")
        initfolder("generated")
        initfolder("generated\\baselines")
        initfolder("generated\\reports")
        initfolder("generated\\BackupWindowsGPO")

    def printbanner(self) -> None:
        """Prints fancy banner so PoochBot seems cool"""

        rich.print("""
[bold blue]   8888888b.                            888      888888b.            888      [/]
[bold blue]   888   Y88b                           888      888  "88b           888      [/]
[bold blue]   888    888                           888      888  .88P           888      [/]
[bold blue]   888   d88P .d88b.   .d88b.   .d8888b 88888b.  8888888K.   .d88b.  888888   [/]
[bold blue]   8888888P" d88""88b d88""88b d88P"    888 "88b 888  "Y88b d88""88b 888      [/]
[bold blue]   888       888  888 888  888 888      888  888 888    888 888  888 888      [/]
[bold blue]   888       Y88..88P Y88..88P Y88b.    888  888 888   d88P Y88..88P Y88b.    [/]
[bold blue]   888        "Y88P"   "Y88P"   "Y8888P 888  888 8888888P"   "Y88P"   "Y888   [/]

[gold3]                            Written by Nolan Jones                            [/]
[gold3]                       Carmel High Cyber Patriot Team 1                       [/]
[gold3]                                    CP-XVII                                   [/]\n""")

    #endregion
