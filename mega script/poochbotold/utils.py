import enum
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

class OperatingSystem(enum.IntEnum):
    WINDOWS = enum.auto()
    WINDOWS_SERVER = enum.auto()
    UBUNTU = enum.auto()
    DEBIAN = enum.auto()
    FEDORA = enum.auto()

class OperatingSystemVersion(enum.IntEnum):
    UBUNTU_20 = enum.auto()
    UBUNTU_22 = enum.auto()

class CriticalService(enum.IntEnum):
    RDP = enum.auto()
    SMB = enum.auto()
    SSH = enum.auto()
    SAMBA = enum.auto()
    MAIL = enum.auto()
    OPENVPN = enum.auto()
    AD = enum.auto()
    APACHE2 = enum.auto()
    FTP = enum.auto()
    MYSQL = enum.auto()
    PHP = enum.auto()
    DNS = enum.auto()
    IIS = enum.auto()

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

def diff(
    current: list[tuple[str]] | list[str],
    defaults: list[tuple[str]] | list[str],
    headings: tuple[str] = None,
) -> rich.table.Table:
    """Creates a diff-like table that shows the differences between two lists of items.

    Args:
        current: The current list of items on the system.
            This a list of tuples, and the number of items in each
            tuple should be consistent between this and `defaults`.
            The first item in the tuple will be used as a key.
        defaults: The default list of items gathered from a clean system.
        headings: The headings to use for the table.
            This should have the same number of items as the tuples in `current` and `defaults`. Defaults to None.

    Returns:
        A rich.table.Table with the differences.
        The whole row being red means that the item is not found on the default system,
        and any orange fields mean that that value is different from the default.
    """
    table = rich.table.Table(*headings)
    for cur_item in current:
        try:
            def_item = [i for i in defaults if i[0] == cur_item[0]][0]
        except:  # means that item does not exist in defaults
            table.add_row(
                *[f"[red]{val}[/]" for val in cur_item]
            )  # unpacks the item into the row
        else:
            table_values = []
            for current_val, new_val in zip(cur_item, def_item):
                if current_val != new_val:
                    table_values.append(f"[yellow]{current_val}[/]")
                else:
                    table_values.append(current_val)
            table.add_row(*table_values)
    return table

#endregion

#region serializers

def serialize_ascii_table(unf: list[str], headings: tuple[str]) -> list[tuple[str]]:
    items = []
    indices = [unf[0].index(a) for a in headings]
    for line in unf:
        items.append(
            tuple(
                line[
                    indices[i] : indices[i + 1]
                    if not i + 1 == len(indices)
                    else len(line)
                ].strip()
                for i in range(len(indices))
            )
        )
    return items

#endregion