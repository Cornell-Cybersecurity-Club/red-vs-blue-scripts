import logging
import os
import platform
import subprocess
import rich
import rich.prompt
import rich.table

import poochbotold.modules.windows.user_auditing
import poochbotold.modules.windows.files
import poochbotold.modules.windows.group_policy
import poochbotold.modules.windows.services
import poochbotold.modules.windows.shares
import poochbotold.modules.windows.sysinfo

import poochbotold.modules.ubuntu.user_auditing
import poochbotold.modules.ubuntu.files
import poochbotold.modules.ubuntu.baselines

import poochbotold.modules.util.parse_readme

from poochbotold import constants, interpreter
from poochbotold.module import Module
from poochbotold.options import OPTIONS
from poochbotold.utils import *
from poochbotold.parsing import parser

logger = logging.getLogger(__name__)

class PoochBot(interpreter.Interpreter):
    prompt = "[bold green](poochbot) >[/]"
    checklists: dict[str, parser.Checklist]
    modules: list[Module] = [
        poochbotold.modules.windows.user_auditing.UserAuditing,
        poochbotold.modules.windows.files.Files,
        poochbotold.modules.windows.group_policy.GroupPolicy,
        poochbotold.modules.windows.services.Services,
        poochbotold.modules.windows.shares.Shares,
        poochbotold.modules.windows.sysinfo.SysInfo,
        
        poochbotold.modules.ubuntu.user_auditing.UserAuditing,
        poochbotold.modules.ubuntu.files.Files,
        poochbotold.modules.ubuntu.baselines.Baselines,

        poochbotold.modules.util.parse_readme.ParseReadme,
    ]

    #region init

    def start(self) -> None:
        """Starts PoochBot init process and trys to start cmd loop"""

        self._determine_os()
        self._load_checklists()
        while True:
            try:
                self.cmdloop()
            except ExitException:
                print("Thank you for using PoochBot.")
                return
            except KeyboardInterrupt:
                print('\nType "exit" to exit.')
            except Exception:
                logger.exception("An uncaught error has occurred.")

    def _determine_os(self) -> None:
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
                        OPTIONS["OS"].set_value(OperatingSystem.WINDOWS)
                        logger.info("Detected Windows.")
                    case "Server" | "ServerStandard" | "ServerStandardEval":
                        OPTIONS["OS"].set_value(OperatingSystem.WINDOWS_SERVER)
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
                        OPTIONS["OS"].set_value(OperatingSystem.UBUNTU)
                        logger.info("Detected Ubuntu.")
                        match distro.major_version():
                            case "22":
                                OPTIONS["OS_VERSION"].set_value(
                                    OperatingSystemVersion.UBUNTU_22
                                )
                                logger.info("Detected Ubuntu version 22.")
                            case "20":
                                OPTIONS["OS_VERSION"].set_value(
                                    OperatingSystemVersion.UBUNTU_20
                                )
                                logger.info("Detected Ubuntu version 20.")
                    case "debian":
                        OPTIONS["OS"].set_value(OperatingSystem.DEBIAN)
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
                    OPTIONS["OS"].set_value(OperatingSystem.WINDOWS)
                case "WS":
                    OPTIONS["OS"].set_value(OperatingSystem.WINDOWS_SERVER)
                case "U":
                    OPTIONS["OS"].set_value(OperatingSystem.UBUNTU)
                case "D":
                    OPTIONS["OS"].set_value(OperatingSystem.DEBIAN)
                case "F":
                    OPTIONS["OS"].set_value(OperatingSystem.FEDORA)
                case _:
                    logger.critical("Could not determine operating system. Exiting.")

        match OPTIONS["OS"].value:
            case OperatingSystem.WINDOWS:
                intro = constants.WINDOWS_BANNER
            case OperatingSystem.WINDOWS_SERVER:
                intro = constants.WINDOWS_SERVER_BANNER
            case OperatingSystem.UBUNTU:
                intro = constants.UBUNTU_BANNER
            case OperatingSystem.DEBIAN:
                intro = constants.DEBIAN_BANNER
            case OperatingSystem.FEDORA:
                intro = constants.FEDORA_BANNER
            case _:
                intro = None

        if intro:
            rich.print(intro)

    def _load_checklists(self) -> None:
        """Loads checklist information into self.checklists"""

        self.checklists = {}
        logger.info("Loading checklists.")
        for dirname, subdirnames, filenames in os.walk("checklist", topdown=True):
            for filename in filenames:
                if ".yml" in filename:
                    joined_path = os.path.join(dirname, filename)
                    # if your filename is checklists\windows\gp_audit.yml, the trimmed name is windows/gp_audit.
                    name = (
                        joined_path.replace(".yml", "")
                        .replace("\\", "/")
                        .replace("checklist/", "")
                    )
                    # if the trimmed name is windows/gp_audit, the filename is gp_audit.
                    trimmed_filename = name.split("/")[-1]
                    try:
                        self.checklists[name] = parser.Checklist(
                            joined_path, trimmed_filename
                        )
                    except:
                        logger.exception(f"Failed loading {joined_path}.")

        logger.info("Checklists loaded.")

    #endregion

    #region exit

    def do_exit(self, arg: str) -> None:
        """Exit the shell."""

        raise ExitException

    #endregion

    #region modules

    def do_modules(self, arg: str) -> None:
        """Interact with installed reconnaissance and vulnerability remediation modules."""

        self._toplevel_subcommand("modules", arg)

    def _do_modules_list(self) -> None:
        """
        List all of the modules that can currently be used.
        This is dependent on operating system. Items in parentheses are aliases for the module, you can refer to the module using any of those shortened forms.

        Usage:
        `modules list`

        Example:
        `(PoochBot) > modules list`
        parse_readme (pr)
        windows.files (files)
        windows.group_policy (group_policy, gp)
        windows.user_auditing (user_auditing, ua)

        For the module `windows.user_auditing`, you can run:
        `(PoochBot) > modules load windows.user_auditing`
        `(PoochBot) > modules load user_auditing`
        `(PoochBot) > modules load ua`
        These all perform the same task.
        """

        for module in self.modules:
            if OPTIONS["OS"].value in module.applies_to:
                print(module.name, f'({", ".join(module.aliases)})')

    def _do_modules_load(self, module_name: str) -> None:
        """
        Load a module. See the modules that you can load by running `modules list`.
        You can also load modules with their aliases (the items shown in parentheses for each module in `modules list`)

        Usage:
        `modules load <module_name>`

        Example:
        `modules load ua`
        """

        mod = self._get_module(module_name)
        if mod:
            logger.info(f"Loading {mod.name}.")
            mod.prompt = f"[bold blue](PoochBot) ({mod.name}) >[/]"
            try:
                mod.cmdloop(intro="")
            except (ExitException, KeyboardInterrupt):
                logger.info(f"Exiting {mod.name}.")
                return
            except:
                logger.exception("Module failed.")

    def _do_modules_run(self, module_name) -> None:
        """
        A shortcut for running modules.
        Identical to running `modules load ___`, then `run`.

        Usage:
        `modules run <module_name>`

        Example:
        `modules run ua`
        """
        
        mod = self._get_module(module_name)
        if mod:
            mod.run()

    def _get_module(self, query) -> Module | None:
        """Gets a module object by name or alias"""

        selected_module: Module = None
        for module in self.modules:
            if OPTIONS["OS"].value in module.applies_to:
                if query in [module.name] + module.aliases:
                    selected_module = module()

        if not selected_module:
            logger.error("Could not find module.")
            return
        return selected_module

    #endregion

    #region checklist

    def do_checklist(self, arg: str) -> None:
        """
        Interact with checklists. These are placed in the ./checklist folder, and follow a schema outlined in ./checklist/vulnerabilities.schema.json.
        """

        self._toplevel_subcommand("checklist", arg)

    def _do_checklist_list(self) -> None:
        """
        Lists every checklist that is accessible.

        Usage:
        `checklist list`
        """

        print("\n".join([checklist_name for checklist_name in self.checklists.keys()]))

    def _do_checklist_view(self, checklist_name: str) -> None:
        """
        View a checklist. Shows a list of every vulnerability in it.

        Usage:
        `checklist view <checklist_name>`

        Example:
        `(PoochBot) > checklist view linux/ssh`
        """

        try:
            checklist = self.checklists[checklist_name]
        except:
            logger.error("Checklist does not exist.")
            return

        checklist.select_vulnerabilities()

        table = rich.table.Table(
            "Checklist ID", "Category", "Policy", title=checklist.name
        )
        for vulnerability in checklist.selected_vulnerabilities:
            table.add_row(
                vulnerability["cid"], vulnerability["category"], vulnerability["policy"]
            )
        rich.print(table)

    def _do_checklist_run(self, checklist_name: str) -> None:
        """
        Run the fixes for every vulnerability in an entire checklist.

        Usage:
        `checklist run <checklist_name>`

        Example:
        `(PoochBot) > checklist run linux/ssh`
        """

        try:
            checklist = self.checklists[checklist_name]
        except:
            logger.error("Checklist does not exist.")
            return

        rich.print(f"[bold green]Running {checklist_name}.[/]")
        checklist.parse()
        checklist.execute()
        logger.info(f"[bold green]Finished running {checklist_name}.[/]")

    def _do_checklist_runid(self, checklist_name: str, cid: str) -> None:
        """
        Run the fixes for a single vulnerability in a checklist.

        Usage:
        `checklist runid <checklist_name> <cid>`

        Example:
        `(PoochBot) > checklist run linux/ssh C-UDF-SSH-1`
        """

        try:
            checklist = self.checklists[checklist_name]
        except:
            logger.error("Checklist does not exist.")
            return

    #endregion

    #region launch

    def do_launch(self, program: str) -> None:
        """
        Launch a program that is bundled with PoochBot.

        ninite|n:     Ninite
        proc:         Process Explorer
        bcu:          Bulk Crap Uninstaller
        everything|e: Everything

        Usage:
        `launch <program>`

        Example:
        `(PoochBot) > launch n`
        """
        # ninite has: 7Zip Firefox Malwarebytes Notepad Revo

        launchers = {
            "Ninite": lambda: subprocess.Popen(
                ".\\support\\windows\\programs\\ninite.exe"
            ),
            "Process Explorer": lambda: subprocess.Popen(
                ".\\support\\windows\\programs\\procexp.exe"
            ),
            "Bulk Crap Uninstaller": lambda: cmd(
                [
                    "start",
                    "",  # this is to make cmd happy
                    "https://github.com/Klocman/Bulk-Crap-Uninstaller/releases/download/v5.4/BCUninstaller_5.4_setup.exe",
                ]
            ),
            "Everything": lambda: subprocess.Popen(
                ".\\support\\windows\\programs\\Everything.exe"
            ),
        }
        aliases = {
            "ninite": "Ninite",
            "n": "Ninite",
            "proc": "Process Explorer",
            "bcu": "Bulk Crap Uninstaller",
            "everything": "Everything",
            "e": "Everything",
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

    #endregion

    #region auto

    def do_auto(self, arg: str) -> None:
        """Run PoochBot autonomously. Please read all prompts carefully."""

        full_auto = False
        rich.print(
            "[bold]You have selected to run PoochBot autonomously. You will be prompted for all steps, so please press enter or type Y to continue. Type N to skip a step, and Q to quit autonomous operation.[/]"
        )
        if arg == "auto":
            rich.print(
                'You have selected the hidden, undocumented option to run PoochBot Auto [bold red1]with no prompts to continue[/]. This is very dangerous. Are you sure you would like to proceed? Please type "proceed" to continue.'
            )
            if input() != "proceed":
                return
            full_auto = True
        rich.print("[green]Beginning auto mode...[/]")
        command_list: dict[OperatingSystem, list[str]] = {
            OperatingSystem.WINDOWS: [
                "modules run pr",
                "modules run gp",
                "modules run ua",
                "checklist run windows/exploit_protection",
                "checklist run windows/gp_audit",
                "checklist run windows/gp_firewall",
                "checklist run windows/gp_network",
                "checklist run windows/gp_plugins",
                "checklist run windows/gp_security",
                "checklist run windows/gp_system",
                "checklist run windows/gp_user",
                "checklist run windows/gp_wincomp_av",
                "checklist run windows/gp_wincomp_eventlog",
                "checklist run windows/gp_wincomp_misc",
                "checklist run windows/gp_wincomp_rds",
                "checklist run windows/gp_wincomp_update",
                "checklist run windows/user_auditing",
                "modules run shares",
                "checklist run windows/services",
                "modules run files",
                "launch ninite",
                "launch proc",
                "launch bcu",
            ],
            OperatingSystem.WINDOWS_SERVER: [
                "modules run pr",
                "modules run gp",
                "modules run ua",
                "checklist run windows/exploit_protection",
                "checklist run windows/gp_audit",
                "checklist run windows/gp_firewall",
                "checklist run windows/gp_network",
                "checklist run windows/gp_plugins",
                "checklist run windows/gp_security",
                "checklist run windows/gp_system",
                "checklist run windows/gp_user",
                "checklist run windows/gp_wincomp_av",
                "checklist run windows/gp_wincomp_eventlog",
                "checklist run windows/gp_wincomp_misc",
                "checklist run windows/gp_wincomp_rds",
                "checklist run windows/gp_wincomp_update",
                "checklist run windows/user_auditing",
                "modules run shares",
                "checklist run windows/services",
                "modules run files",
                "launch ninite",
                "launch proc",
                "launch bcu",
            ],
            OperatingSystem.UBUNTU: [
                "modules run pr",
                "checklist run linux/passwords",
                "modules run ua",
                "checklist run linux/fstab",
                "checklist run linux/apt",
                "checklist run linux/audit",
                "checklist run linux/folder_file_permissions",
                "checklist run linux/gdm3",
                "checklist run linux/grub",
                "checklist run linux/misc",
                "checklist run linux/modprobe",
                "checklist run linux/pam",
                "checklist run linux/passwords",
                "checklist run linux/prohibited_software",
                "checklist run linux/services",
                "checklist run linux/sudo",
                "checklist run linux/sysctl",
                "checklist run linux/systemd",
                "checklist run linux/ufw",
                "checklist run linux/ssh",
                "modules run files",
            ],
        }

        for command in command_list[OPTIONS["OS"].value]:

            if full_auto:
                logger.info(f"Running command: {command}.")
                try:
                    self.onecmd(command)
                except:
                    logger.exception(f"Failed to run command: {command}.")
                    if (
                        rich.prompt.Prompt.ask(
                            "Do you want to quit autonomous mode? (y/N) "
                        ).lower()
                        == "y"
                    ):
                        logger.critical("Exiting autonomous mode.")
                        return
            else:
                logger.info(f"About to run command: {command}.")
                match rich.prompt.Prompt.ask("Continue? (Y/n/q) ").lower():
                    case "y" | "":
                        logger.info("Running command.")
                        try:
                            self.onecmd(command)
                        except:
                            logger.exception(f"Failed to run command: {command}.")
                            if (
                                rich.prompt.Prompt.ask(
                                    "Do you want to quit autonomous mode? (y/N) "
                                ).lower()
                                == "y"
                            ):
                                logger.critical("Exiting autonomous mode.")
                                return
                    case "q":
                        logger.critical("Exiting autonomous mode.")
                        return
                    case _:
                        logger.info("Skipping command.")
                        continue
        logger.info("Completed autonomous mode.")

    #endregion

    #region stats

    def do_stats(self, arg: str) -> None:
        """Prints the number of vulnerabilities PoochBot has accumulated."""

        rich.print(
            f"[bold]Total Vulnerabilities:[/] {sum([len(checklist.vulnerabilities) for checklist in self.checklists.values()])}"
        )

        for checklist in self.checklists.values():
            checklist.select_vulnerabilities()
        rich.print(
            f"[bold]Pertaining Vulnerabilities:[/] {sum([len(checklist.selected_vulnerabilities) for checklist in self.checklists.values()])}"
        )

        rich.print("[bold]By Subdirectory:[/]")
        for subdirectory in [f.name for f in os.scandir("checklist") if f.is_dir()]:
            rich.print(
                f"   [italic]{subdirectory}:[/] {sum([len(checklist.vulnerabilities) for checklist in self.checklists.values() if checklist.subdirectory == subdirectory])}"
            )

        rich.print("[bold]By Checklist:[/]")
        for checklist in self.checklists.values():
            rich.print(
                f"   [italic]{checklist.subdirectory}/{checklist.filename}:[/] {len(checklist.vulnerabilities)}"
            )

    #endregion