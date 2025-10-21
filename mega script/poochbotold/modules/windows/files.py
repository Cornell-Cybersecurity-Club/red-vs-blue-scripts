import logging
import os

import rich
import rich.progress
import rich.table

from poochbotold import module
from poochbotold.utils import *

logger = logging.getLogger(__name__)

class Files(module.Module):
    """Parse through and analyze the files on the system."""

    name = "windows.files"
    aliases = ["files"]
    applies_to: list[OperatingSystem] = [
        OperatingSystem.WINDOWS,
        OperatingSystem.WINDOWS_SERVER,
    ]
    # fmt: off
    file_extensions = {
        "audio": [
            "mp3", "aac", "ac3", "wav", "wma", "ogg", "midi", "mid", "cda", "aif", "mpa", "avi", "wmv"
        ],
        "video": [
            "mp4", "mkv", "avi", "mpeg", "mpg", "mov", "m4v", "flv", "3gp", "wmv", "vob"
        ],
        "image": [
            "jpeg", "jpg", "png", "gif", "psd", "ai", "tif", "tiff", "bmp", "heic", "eps", "svg"
        ],
        "document": [
            "doc", "docx", "pdf", "txt", "xls", "xlsx", "xlsm", "ppt", "pps", "pptx", "csv", "rtf", "xml", "log", "obj", "db", "sql", "fnt", "fon", "otf", "ttf", "tmp"
        ],
        "archive": [
            "tar", "gz", "zip", "7z", "deb", "pkg", "rar", "tar.gz", "zipx", "bin", "dmg", "iso",
        ],
        "executable": [
            "apk", "app", "bat", "cgi", "com", "exe", "gadget", "jar", "wsf", "vbs", "sh",
        ],
        "web": [
            "asp", "aspx", "cer", "cfm", "css", "htm", "html", "js", "jsp", "php", "xhtml", "crx",
        ],
        "code": [
            "c", "class", "cpp", "cs", "dtd", "fla", "h", "java", "lua", "m", "pl", "py", "sh", "sln", "swift", "vb", "vcxproj", "xcodeproj"
        ],
    }
    # fmt: on

    modifications = {
        "ignore": [
            "AppData",
            "ini",
            "ntuser",
            ".vscode",
            "All Users",
            "AccountPictures",
            "WinSxS",
            "PoochBot",
            "CyberPatriot",
        ],
        "hide": ["Windows", "Program Files", "ProgramData", "Recovery", "PoochBot"],
    }

    def do_get_files(self, arg: str = None) -> None:
        """Get a list of all files that currently exist on the machine."""

        with rich.progress.Progress(transient=True) as progress:
            progress.add_task("Working...", start=False, total=None)
            files = cmd(["cmd.exe", "/r", "dir", "C:\\", "/a", "/s", "/b"])
            try:
                os.makedirs("data/files")
            except OSError:
                pass
            with open("data/files/fulllist.txt", "w") as f:
                f.write(files)
            progress.stop()
        logger.info(
            "Finished getting all files. List saved in data/files/fulllist.txt. You may now run analysis commands."
        )

    def do_users(self, arg: str = None) -> None:
        """Lists all files under each user directory. Does not check by file extension."""

        files = cmd(["cmd.exe", "/r", "dir", "C:\\Users", "/a-d", "/s", "/b"])

        paths = [
            path
            for path in files.split("\n")
            if not any(x.lower() in path.lower() for x in self.modifications["ignore"])
        ][:-1]
        table = rich.table.Table("Filename", title="User Files")
        for path in paths:
            table.add_row(path)

        rich.print(table)

    def do_analyze(self, file_type: str | None = None) -> None:
        """Analyze all known file types. This will display files that were found, and generate lists in data/files/ that contain extra results."""

        if not file_type:
            logger.info("Analyzing all file types.")
            to_analyze = self.file_extensions.keys()
        else:
            if file_type not in self.file_extensions.keys():
                logger.error("Invalid analysis type.")
                return

            to_analyze = [file_type]

        for ft in to_analyze:
            logger.info(f"Analyzing {ft} files.")
            try:
                with open("data/files/fulllist.txt", "r") as f:
                    file_list = f.read().splitlines()
            except FileNotFoundError:
                logger.error("Function get_files must be run before running this.")
                return

            all_paths = []
            truncated_paths = []
            for line in file_list:
                if any(
                    [line.endswith("." + ext) for ext in self.file_extensions[ft]]
                ) and not any(
                    [x.lower() in line.lower() for x in self.modifications["ignore"]]
                ):
                    all_paths += [line]

                    if not any(
                        [x.lower() in line.lower() for x in self.modifications["hide"]]
                    ):
                        truncated_paths += [line]

            if truncated_paths:
                logger.info(
                    f"Finished analyzing {ft} files. Found {len(all_paths)} results. Found {len(truncated_paths)} important results. List saved in data/files/{ft}.txt. Showing important results."
                )

                table = rich.table.Table("Filename", title=f"{ft.title()} Files")
                for path in truncated_paths:
                    table.add_row(path)
                rich.print(table)
            else:
                logger.info(
                    f"Finished analyzing {ft} files. Found {len(all_paths)} results. Found 0 important results. List saved in data/files/{ft}.txt."
                )

            os.makedirs("./data/files", exist_ok=True)
            with open(f"data/files/{ft}.txt", "w") as f:
                f.write("\n".join(all_paths) + "\n")

    def run(self):
        """Gets all files in the file system and displays suspicious files"""
        
        logger.info("Getting files.")
        self.do_get_files()
        logger.info("Showing user files.")
        self.do_users()
        logger.info("Analyzing files.")
        self.do_analyze()