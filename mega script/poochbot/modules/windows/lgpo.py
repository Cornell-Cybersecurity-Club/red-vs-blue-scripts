import logging

import os

from poochbot.utils import *

logger = logging.getLogger(__name__)

lgpopath: str = "C:\\PoochBot\\support\\windows\\programs\\LGPO.exe"

bestgpopath: str = "C:\\PoochBot\\support\\windows\\BestWindowsGPO"
backupgpopath: str = "C:\\PoochBot\\generated\\BackupWindowsGPO"

registryimportspath: str = "C:\\PoochBot\\support\\windows\\RegistryImports"

def lgpo() -> None:
    """Lets user do any of the following: import and backup GPO, import registry files"""

    gpo()
    reg()

def gpo() -> None:
    """Full action path to get a backup of the current GPO and import one of the preset GPOS, a previous backup, or a unique GPO"""

    # ask for path to import GPO from
    def getgpopath() -> str:
        if input("Use best GPO? (Y/n) ").lower() == "n":
            if input("Use backup GPO? (Y/n) ").lower() != "n":
                return backupgpopath
            else:
                return input("Enter path to desired GPO: ")
        else:
            return bestgpopath

    # export GPO backup
    def exportgpobackup() -> None:
        logger.info("Exporting GPO backup")
        
        try:
            cmdshell(f"{lgpopath} /b {backupgpopath}")
        except:
            logger.error(f"Failed Backing up current GPO. Aborting GPO import.")
            return
        else:
            logger.info(f"Back up current GPO to: {backupgpopath}.")
    
    # import new GPO
    def importgpo(gpopath: str) -> None:
        logger.info("Importing new GPO")
        try:
            cmdshell(f"{lgpopath} /g {gpopath}")
            cmdshell("gpupdate /force")
        except:
            logger.error(f"Failed importing new GPO. (usually misleading see if you got points)")
            return
        else:
            logger.info(f"Imported new GPO from: {gpopath}.")

    # ask if user wants to do gpo action path
    if input("Import GPO? (Y/n) ").lower() == "n":
        return
    
    # do full gpo action path
    gpopath = getgpopath()
    exportgpobackup()
    importgpo(gpopath)

def reg() -> None:
    """Asks user which of the .reg file in """

    # Gets all files from all directories stated by user
    def getfullfilelist() -> list[str]:

        # Gets all files in the specified folder
        def getfilelist(mypath: str) -> list[str]:
            return [os.path.join(dirpath,f) for (dirpath, dirnames, filenames) in os.walk(mypath) for f in filenames]

        filelist = []

        # Get default reg files that come with PoochBot
        if input("Include PoochBot default .reg list? (Y/n) ").lower() == "y":
            try:
                filelist.extend(f for f in getfilelist(registryimportspath) if ".reg" in f)
                logger.info(f"Found {len(filelist)} reg files in default directory")
            except:
                logger.error("Failed to get reg files from defaults directory")
        
        # Get any custom reg files if needed
        if input("Include custom .reg lists? (Y/n) ").lower() == "y":
            lastinput = "y"

            while lastinput == "y":
                try:
                    prevsize = len(filelist)
                    filelist.extend(f for f in getfilelist(input("Enter full path to folder with .reg files: ")) if ".reg" in f)
                    logger.info(f"Found {len(filelist) - prevsize} new reg files from that directory")
                except:
                    logger.error("Failed to get reg files from that directory")

                lastinput = input("Include another custom .reg list? (Y/n) ").lower()
        
        return filelist

    # Displays all fils in current list
    def displayfullfilelist(filelist: list[str]) -> None:
        rich.print("[bold]All Found reg Files:[/]")
        for f in filelist:
            rich.print(
                f"   [italic]{f}[/]"
            )

    # Actually imports all the reg files
    def importregistry(filelist: list[str]) -> None:
        if input("Do you want to proceed with importing all of the .reg files listed above? (Y/n) ").lower() == "n":
            return

        logger.info("Starting registry import")
        for f in filelist:
            try:
                if ".user.reg" in f:
                    cmdshell(f"{lgpopath} /u {f}")
                else:
                    cmdshell(f"{lgpopath} /m {f}")
            except:
                logger.error(f"Failed to imported registry data from: {f}.")
                return
            else:
                logger.info(f"Imported registry data from: {f}.")

    # ask if user wants to do registry action path
    if input("Import .reg files to registry? (Y/n) ").lower() == "n":
        return
    
    # do full registry action path
    filelist = getfullfilelist()
    displayfullfilelist(filelist)
    importregistry(filelist)
