import logging
import os

import rich
import rich.table

from poochbotold import module
from poochbotold.utils import *

logger = logging.getLogger(__name__)


class Files(module.Module):
    """Parse through and analyze the files on the system."""

    name: str = "ubuntu.files"
    aliases = ["files"]
    applies_to: list[OperatingSystem] = [
        OperatingSystem.UBUNTU,
        OperatingSystem.DEBIAN,
    ]

    modifications = {
        "ignore": [".cache", "PoochBot"],
        "hide": [
            "/snap",
            "/usr/src/",
            "/usr/share",
            "/usr/lib",
            "/var/cache",
            "/var/lib",
        ],
    }

    # fmt: off
    file_extensions = {
        "audio": [
            "mp3", "aac", "ac3", "wav", "wma", "ogg", "midi", "mid", "cda", "aif", "mpa", "avi", "flac", "sid", "aiff", "snd", "au", "mpega", "abs", "mp2", "mod"
        ],
        "video": [
            "mp4", "mkv", "avi", "mpeg", "mpg", "mov", "m4v", "flv", "3gp", "wmv", "vob", "mpe", "dl", "movie", "movi", "mv", "iff", "anim5", "anim3", "anim7", "vfw", "avx", "fli", "flc", "qt", "spl", "swf", "dcr", "dir", "dxr", "rpm", "rm", "smi", "ra", "ram", "rv", "wmx" 
        ],
        "image": [
            "jpeg", "jpg", "png", "gif", "psd", "ai", "tif", "tiff", "bmp", "heic", "eps", "svg", "rs", "im1", "jpe", "rgb", "xwd", "xpm", "ppm", "pbm", "pcx", "svgz"
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

    def do_update_db(self) -> None:
        """Utility function to update the database used by the locate command."""
        cmdshell("updatedb")

    def do_home(self, arg: str = None) -> None:
        """Show all files in home directories."""
        files = cmdshell("find /home -type f")
        paths = [
            path
            for path in files.split("\n")[:-1]
            if not any(x.lower() in path.lower() for x in self.modifications["ignore"])
        ][::-1]

        table = rich.table.Table("Filename", title="User Files")
        for path in paths:
            table.add_row(path)

        rich.print(table)

    def run(self, file_type: str = None) -> None:
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

            exts = " ".join(f"*.{ext}" for ext in self.file_extensions[ft])
            file_list = cmdshell(f"locate {exts}").splitlines()

            all_paths = []
            truncated_paths = []
            for line in file_list:
                if not any(
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
