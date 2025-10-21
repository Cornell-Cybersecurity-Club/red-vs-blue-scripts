from enum import Enum
import logging
import subprocess

import rich
import rich.table

logger = logging.getLogger(__name__)

class ExitException(Exception):
    pass

#region run command functions

def cmd(cmd: str) -> str:
    """
    Runs given command in console.

    Returns console output as string.
    """

    logger.debug(f"Running command: {cmd}")
    return subprocess.run(
        cmd,
        capture_output=True,
        check=True,
        text=True,
    ).stdout

def cmdshell(cmd: str) -> str:
    """
    Runs given command in shell.
    
    Returns shell output as string.
    """

    logger.debug(f"Running command: {cmd}")
    return subprocess.run(
        cmd, shell=True, capture_output=True, check=True, text=True, errors="ignore"
    ).stdout

def psshell(cmd: str) -> str:
    """
    Runs given command in powershell.
    
    Returns powershell output as string.
    """

    logger.debug(f"Running command: {cmd}")
    return subprocess.run(
        f'powershell.exe /c "{cmd}"',
        shell=True,
        capture_output=True,
        check=True,
        text=True,
    ).stdout

def cmdfull(cmd: str) -> subprocess.CompletedProcess:
    """
    Runs given command in console.
    
    Returns console CompletedProcess object.
    """

    logger.debug(f"Running command: {cmd}")
    return subprocess.run(
        cmd,
        capture_output=True,
        check=True,
        text=True,
    )

def cmdrc(cmd: str) -> int:
    """
    Runs given command in console.
    
    Returns console return code as int.
    """

    logger.debug(f"Running command: {cmd}")
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    ).returncode

#endregion

#region enums

class OperatingSystem(str, Enum):
    NONE = "NONE"
    WINDOWS = "WINDOWS"
    WINDOWS_SERVER = "WINDOWS_SERVER"
    UBUNTU = "UBUNTU"
    DEBIAN = "DEBIAN"
    FEDORA = "FEDORA"

class OperatingSystemVersion(str, Enum):
    NONE = "NONE"
    UBUNTU_20 = "UBUNTU_20"
    UBUNTU_22 = "UBUNTU_22"

class CriticalService(str, Enum):
    RDP = "RDP"
    SMB = "SMB"
    SSH = "SSH"
    SAMBA = "SAMBA"
    MAIL = "MAIL"
    OPENVPN = "OPENVPN"
    AD = "AD"
    APACHE2 = "APACHE2"
    FTP = "FTP"
    MYSQL = "MYSQL"
    PHP = "PHP"
    DNS = "DNS"
    IIS = "IIS"

#endregion

#region dictionaries

class Colors:
    N = "\033[m"  # native
    R = "\033[31m"  # red
    G = "\033[32m"  # green
    Y = "\033[33m"  # yellow
    B = "\033[34m"  # blue
    M = "\033[35m"  # magenta
    C = "\033[36m"  # cyan
    W = "\033[37m"  # white
    O = "\033[38;5;208m"  # orange, 256-color
    BOLD = "\033[1m"  # bold

    CRITICAL = "\033[91m"
    ERROR = "\033[31m"
    WARNING = "\033[33m"
    INFO = "\033[34m"
    DEBUG = ""

#endregion

#region formatters

class ConsoleLogFormatter(logging.Formatter):
    REPLACEMENTS = {
        "CRITICAL": f"{Colors.CRITICAL}[!!]{Colors.N}",
        "ERROR": f"{Colors.ERROR}[!]{Colors.N}",
        "EXCEPTION": f"{Colors.ERROR}[!]{Colors.N}",
        "WARNING": f"{Colors.WARNING}[/]{Colors.N}",
        "INFO": f"{Colors.INFO}[*]{Colors.N}",
        "DEBUG": f"{Colors.DEBUG}[.]{Colors.N}",
    }

    def __init__(self, fmt=None, datefmt=None, style="%", validate=True):
        super().__init__(fmt, datefmt, style, validate)

    def format(self, record: logging.LogRecord):
        formatted = f"{record.levelname} {record.msg}"
        if record.exc_info:
            formatted += f" {record.exc_info[0].__name__}: {record.exc_info[1]}"
        for r in self.REPLACEMENTS.keys():
            formatted = formatted.replace(r, self.REPLACEMENTS[r])
        return formatted

#endregion

#region comparisons

def getdifftable(
    current: list[tuple[str]] | list[str],
    defaults: list[tuple[str]] | list[str],
    headings: tuple[str] = None,
) -> rich.table.Table:
    """
    Creates a rich table that shows the differences between two lists of items.
    
    Key:
    white = Same
    green = Only in Current
    yellow + orange = Current -> Baseline
    red = Only in baseline
    """

    table = rich.table.Table(*headings)

    onlycurrent = []
    inboth = []
    onlynew = []

    # get what is in both and what is only in current
    for cur_item in current:
        try:
            def_item = [i for i in defaults if i[0] == cur_item[0]][0]
        except:
            # only in current
            onlycurrent.append([f"[green](NEW) {val}[/]" for val in cur_item])
        else:
            # in both
            table_values = []
            for current_val, new_val in zip(cur_item, def_item):
                # show both if different otherwise just show it normally
                if current_val != new_val:
                    table_values.append(f"[yellow]{current_val}[/] -> [orange3]{new_val}[/]")
                else:
                    table_values.append(current_val)
            inboth.append(table_values)

    # get what is only in new
    for def_item in defaults:
        try:
            cur_item = [i for i in current if i[0] == def_item[0]][0]
        except:
            onlynew.append([f"[red](MISSING) {val}[/]" for val in def_item])

    # build and return final table
    for row in onlycurrent:
        table.add_row(*row)
    for row in inboth:
        table.add_row(*row)
    for row in onlynew:
        table.add_row(*row)
    
    return table

def getchangedifftable(
    current: list[tuple[str]] | list[str],
    defaults: list[tuple[str]] | list[str],
    headings: tuple[str] = None,
) -> rich.table.Table:
    """
    Creates a rich table that shows the change differences between two lists of items.
    
    Key:
    white = Same
    yellow + orange = Current -> Baseline
    """

    table = rich.table.Table(*headings)

    inboth = []

    # get what is in both but has changes
    for cur_item in current:
        try:
            def_item = [i for i in defaults if i[0] == cur_item[0]][0]
        except:
            continue
        else:
            # in both
            hasdiff = False
            table_values = []
            for current_val, new_val in zip(cur_item, def_item):
                # show both if different otherwise just show it normally
                if current_val != new_val:
                    table_values.append(f"[yellow]{current_val}[/] -> [orange3]{new_val}[/]")
                    hasdiff = True
                else:
                    table_values.append(current_val)

            if hasdiff:
                inboth.append(table_values)

    # build and return final table
    for row in inboth:
        table.add_row(*row)
    
    return table

#endregion
