import logging
import rich
import rich.prompt
import rich.table
import os

from poochbot.parsing import parser

logger = logging.getLogger(__name__)

class ChecklistCommands():

    #region Init

    checklists: dict[str, parser.Checklist]

    def loadchecklists(self) -> None:
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

    def do_checklist(self, arg: str) -> None:
        """
        Interact with checklists. These are placed in the ./checklist folder.
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

        table = rich.table.Table(
            "Checklist ID", "Category", "Policy", title=checklist.name
        )
        for vulnerability in checklist.vulnerabilities:
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
    
    def _do_checklist_stats(self, *args) -> None:
        """
        Prints the number of vulnerabilities PoochBot has accumulated.

        Usage:
        `checklist stats`
        `checklist stats <checklist_name>`
        `checklist stats <checklist_folder>`

        Examples:
        `checklist stats`
        `checklist stats windows/gp_user`
        `checklist stats windows`
        """

        if len(args) == 0:
            # If no args print all stats

            rich.print(
                f"[bold]Total Vulnerabilities:[/] {sum([len(checklist.vulnerabilities) for checklist in self.checklists.values()])}"
            )

            rich.print(
                f"[bold]Pertaining Vulnerabilities:[/] {sum([len(checklist.vulnerabilities) for checklist in self.checklists.values()])}"
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
        else:
            arg = args[0]

            if arg in [f.name for f in os.scandir("checklist") if f.is_dir()]:
                # get stats for checklist folder

                rich.print(f"[bold]Total Vulnerabilities:[/] {sum([len(checklist.vulnerabilities) for checklist in self.checklists.values() if checklist.subdirectory == arg])}")

                rich.print("[bold]By Checklist:[/]")
                for checklist in self.checklists.values():
                    if checklist.subdirectory == arg:
                        rich.print(
                            f"   [italic]{checklist.subdirectory}/{checklist.filename}:[/] {len(checklist.vulnerabilities)}"
                        )

            elif arg in [f"{checklist.subdirectory}/{checklist.filename}" for checklist in self.checklists.values()]:
                # get stats for specific checklist

                checklist = next(filter(lambda cl: f"{cl.subdirectory}/{cl.filename}" == arg, self.checklists.values()), None)
                if checklist:
                    rich.print(f"[bold]Total Vulnerabilities:[/] {len(checklist.vulnerabilities)}")

            else:
                logger.error(f"arg: {arg} is not a valid checklist or checklist folder")
