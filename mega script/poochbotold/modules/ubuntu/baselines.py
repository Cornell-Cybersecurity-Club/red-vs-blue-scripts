import json
import logging
import os
import os.path

import rich
import rich.table
from poochbotold import module
from poochbotold.utils import *

logger = logging.getLogger(__name__)


class Baselines(module.Module):
    """Compare the effective state of the system with a baseline of a Ubuntu 22.04 system."""

    name: str = "ubuntu.baselines"
    aliases = ["files"]
    applies_to: list[OperatingSystem] = [OperatingSystem.UBUNTU]
    baseline_directory = "./support/linux/baselines/ubu22"
    fromimage_directory = "./generated/fromimage"

    def __init__(self):
        super().__init__()
        os.makedirs("generated/reports/hashdeep", exist_ok=True)
        os.makedirs("generated/fromimage", exist_ok=True)

    def do_debsums(self, arg: str = None):
        logger.info(f"Debsums")
        out = cmdshell(f"debsums -ac")
        table = rich.table.Table(title=f"Debsums")
        for line in out.splitlines():
            table.add_row(line)
        rich.print(table)

        with open("generated/debsums.txt", "w") as f:
            f.write(out)

    def do_hashdeep(self, arg: str = None):
        # hashdeep -k <file> -x /etc
        logger.info(
            "The hashdeep baseliner does not store image data for future use, "
            "it instead stores the *results* from the first time you "
            "run it in ./generated/reports/hashdeep."
        )
        for file, path in [
            ("bin.txt", "/bin"),
            ("etc.txt", "/etc"),
            ("sbin.txt", "/sbin"),
            ("usrbin.txt", "/usr/bin"),
            ("usrsbin.txt", "/usr/sbin"),
            ("usrshare.txt", "/usr/share"),
        ]:
            logger.info(f"Hashdeep: {path}")
            out = cmdshell(
                f"hashdeep -r -k {self.baseline_directory}/hashdeep/{file} -x {path}"
            )
            table = rich.table.Table(title=f"Hashdeep: {path}")
            for line in out.splitlines():
                table.add_row(line)
            rich.print(table)

            if not os.path.exists(f"generated/reports/hashdeep/{file}"):
                with open(f"generated/reports/hashdeep/{file}", "w") as f:
                    f.write(out)

    def do_apt_repos(self, arg: str = None):
        logger.info("APT Repos")

        if os.path.exists(f"{self.fromimage_directory}/apt_repos.json"):
            logger.info("Using saved image data.")
            with open(f"{self.fromimage_directory}/apt_repos.json", "r") as f:
                repo_list = json.load(f)
        else:
            repo_list = [(i,) for i in cmdshell("add-apt-repository -L").splitlines()]
            with open(f"{self.fromimage_directory}/apt_repos.json", "w") as f:
                json.dump(repo_list, f)

        with open(f"{self.baseline_directory}/apt_repos.txt", "r") as f:
            def_repo_list = [(i,) for i in f.read().splitlines()]

        table, ascii_table = diff(repo_list, def_repo_list, ("Repository",))
        rich.print(table)
        with open(f"generated/reports/aptrepos.txt", "w") as f:
            rich.print(ascii_table, file=f)

    def do_apt_sources_list(self, arg: str = None):
        logger.info("APT sources.list")

        if os.path.exists(f"{self.fromimage_directory}/sources.json"):
            logger.info("Using saved image data.")
            with open(f"{self.fromimage_directory}/sources.json", "r") as f:
                sources_list = json.load(f)
        else:
            with open("/etc/apt/sources.list", "r") as f:
                sources_list = [(i,) for i in f.read().splitlines()]
            with open(f"{self.fromimage_directory}/sources.json", "w") as f:
                json.dump(sources_list, f)

        with open(f"{self.baseline_directory}/sources.list", "r") as f:
            def_sources_list = [(i,) for i in f.read().splitlines()]

        table, ascii_table = diff(sources_list, def_sources_list, ("Line",))
        rich.print(table)

        with open(f"generated/aptrepos.txt", "w") as f:
            rich.print(ascii_table, file=f)

    def do_aptmark(self, arg: str = None):
        logger.info("Manually installed packages with apt-mark")

        if os.path.exists(f"{self.fromimage_directory}/aptmark.json"):
            logger.info("Using saved image data.")
            with open(f"{self.fromimage_directory}/aptmark.json", "r") as f:
                pkg_list = [(i,) for i in cmdshell("apt-mark showmanual").splitlines()]
        else:
            pkg_list = [(i,) for i in cmdshell("apt-mark showmanual").splitlines()]
            with open(f"{self.fromimage_directory}/aptmark.json", "w") as f:
                json.dump(pkg_list, f)

        with open(f"{self.baseline_directory}/aptmark.txt", "r") as f:
            def_pkg_list = [(i,) for i in f.read().splitlines()]

        table, ascii_table = diff(pkg_list, def_pkg_list, ("Package Name",))
        rich.print(table)

        os.makedirs("generated/reports", exist_ok=True)
        with open(f"generated/reports/aptmark.txt", "w") as f:
            rich.print(ascii_table, file=f)

    def do_dpkg(self, arg: str = None):
        logger.info("All packages installed with dpkg")

        headings = ("Name", "Version", "Architecture", "Description")

        if os.path.exists(f"{self.fromimage_directory}/dpkg.json"):
            logger.info("Using saved image data.")
            with open(f"{self.fromimage_directory}/dpkg.json", "r") as f:
                pkg_list = json.load(f)
        else:
            pkg_list = serialize_ascii_table(
                cmdshell("dpkg -l --no-pager").splitlines()[3:],
                headings,
            )
            with open(f"{self.fromimage_directory}/dpkg.json", "w") as f:
                json.dump(pkg_list, f)

        with open(f"{self.baseline_directory}/dpkg.txt", "r") as f:
            def_pkg_list_unf = f.read().splitlines()

        def_pkg_list = serialize_ascii_table(def_pkg_list_unf[3:], headings)

        table, ascii_table = diff(pkg_list, def_pkg_list, headings)
        rich.print(table)

        with open(f"generated/reports/dpkg.txt", "w") as f:
            rich.print(ascii_table, file=f)

    def do_snap(self, arg: str = None):
        logger.info("All packages installed with snap")

        headings = ("Name", "Version", "Rev", "Tracking", "Publisher", "Notes")

        if os.path.exists(f"{self.fromimage_directory}/snap.json"):
            logger.info("Using saved image data.")
            with open(f"{self.fromimage_directory}/snap.json", "r") as f:
                snap_list = json.load(f)
        else:
            snap_list = serialize_ascii_table(
                cmdshell("snap list").splitlines(), headings
            )
            with open(f"{self.fromimage_directory}/snap.json", "w") as f:
                json.dump(snap_list, f)

        with open(f"{self.baseline_directory}/snap.txt", "r") as f:
            def_snap_list = f.read().splitlines()

        def_snap_list = serialize_ascii_table(def_snap_list, headings)

        table, ascii_table = diff(snap_list, def_snap_list, headings)
        rich.print(table)

        with open(f"generated/reports/snap.txt", "w") as f:
            rich.print(ascii_table, file=f)

    # def do_grubcfg(self, arg: str = None):
    #     logger.info("Grub configuration")
    #     c = f"diff --color /boot/grub/grub.cfg {self.baseline_directory}/grub.cfg"

    #     out = cmdshell(c)
    #     os.system(c)

    #     with open(f"generated/reports/grubcfg.txt", "w") as f:
    #         f.write(out)

    # def do_kernmodules(self, arg: str = None):
    #     pass

    # def do_netstat(self, arg: str = None):
    #     pass

    def do_basicservices(self, arg: str = None):
        def _format_srvs(unf: list[str]) -> list[tuple[str]]:
            srvs = []
            for i in unf:
                state, name = i.strip().split("  ")
                state = state.removeprefix("[ ").removesuffix(" ]")
                state = {"+": "+ Running", "-": "- Exited"}[state]
                srvs.append((name, state))
            return srvs

        logger.info("Basic Services")

        if os.path.exists(f"{self.fromimage_directory}/services.json"):
            logger.info("Using saved image data.")
            with open(f"{self.fromimage_directory}/services.json", "r") as f:
                srvs = json.load(f)
        else:
            srvs = _format_srvs(cmdshell("service --status-all").splitlines())
            with open(f"{self.fromimage_directory}/services.json", "w") as f:
                json.dump(srvs, f)

        with open(f"{self.baseline_directory}/services.txt", "r") as f:
            def_srvs = _format_srvs(f.read().splitlines())

        table, ascii_table = diff(srvs, def_srvs, ("Name", "State"))
        rich.print(table)

        with open("generated/reports/services.txt", "w") as f:
            rich.print(ascii_table, file=f)

    def do_services(self, arg: str = None):
        logger.info("Systemd Services")

        headings = ("UNIT", "LOAD", "ACTIVE", "SUB", "DESCRIPTION")

        if os.path.exists(f"{self.fromimage_directory}/systemctl-services.json"):
            logger.info("Using saved image data.")
            with open(f"{self.fromimage_directory}/systemctl-services.json", "r") as f:
                srvs = json.load(f)
        else:
            srvs = serialize_ascii_table(
                cmdshell("systemctl list-units --type=service --no-pager").splitlines(),
                headings,
            )[2:-7]
            with open(f"{self.fromimage_directory}/systemctl-services.json", "w") as f:
                json.dump(srvs, f)

        with open(f"{self.baseline_directory}/systemctl-services.txt", "r") as f:
            def_srvs = f.read().splitlines()

        def_srvs = serialize_ascii_table(def_srvs, headings)[2:-6]

        table, ascii_table = diff(srvs, def_srvs, headings)
        rich.print(table)

        with open(f"generated/reports/systemctl-services.txt", "w") as f:
            rich.print(ascii_table, file=f)

    def run(self, arg: str = None) -> None:
        self.do_debsums()
        self.do_hashdeep()
        self.do_apt_repos()
        self.do_apt_sources_list()
        self.do_aptmark()
        self.do_dpkg()
        self.do_snap()
        self.do_basicservices()
        self.do_services()
