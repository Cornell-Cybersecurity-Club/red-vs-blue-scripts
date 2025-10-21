import codecs
import csv
import json
import logging
import os
import os.path
import re
import shutil
from abc import ABC, abstractmethod
import rich

from poochbotold.options import OPTIONS
from poochbotold.utils import *

logger = logging.getLogger(__name__)

LGPO_PATH = ".\\support\\windows\\programs\\LGPO.exe"
SUPPORTING_FILE_DIR: str = "./generated/"

#region backups

def make_file_backup(filename: str):
    if os.path.exists(filename) and not os.path.exists(f"{filename}.bak"):
        logger.debug(f"Backing up file: {filename}.")
        shutil.copy(filename, f"{filename}.bak")

#endregion

#region base parsers

class CombinedFixParser(ABC):
    fix_type: str
    checklist_name: str
    vulnerabilities: list[dict[str, str]]

    def __init__(self, checklist_name: str):
        self.checklist_name = checklist_name
        self.vulnerabilities = []

    @property
    @abstractmethod
    def fix_type(self):
        pass

    @abstractmethod
    def add_vuln(self, vulnerability: dict[str, str], fix: dict = None):
        self.vulnerabilities += [vulnerability]

    @abstractmethod
    def execute(self):
        pass

class OneTimeFixParser(ABC):
    fix_type: str
    vulnerability: dict[str, str]

    @property
    @abstractmethod
    def fix_type(self):
        pass

    @abstractmethod
    def parse(self, vulnerability: dict[str, str], fix: dict = None):
        self.vulnerability = vulnerability

    @abstractmethod
    def execute(self):
        pass

#endregion

#region combined fix parsers

class ConfigFileParser(CombinedFixParser):
    fix_type: str = "config_file"
    items: dict[str, list[tuple[str, str]]]

    def __init__(self, checklist_name: str):
        super().__init__(checklist_name)
        self.items = {}

    def add_vuln(self, vulnerability: dict[str, str], fix: dict):
        super().add_vuln(vulnerability)
        if not self.items.get(fix["file"]):
            self.items[fix["file"]] = []

        self.items[fix["file"]] += [(vulnerability["cid"], fix["text"])]

    def execute(self):
        for config_file, values in self.items.items():
            # copy the backup file back to the original
            if os.path.exists(config_file + ".bak"):
                shutil.copy(config_file + ".bak", config_file)

            if os.path.exists(config_file):
                with open(config_file, "r") as f:
                    contents = f.read().splitlines()
                make_file_backup(config_file)
            else:
                contents = []

            for cid, item in values:
                try:
                    k, v = re.split(r"[ =]", item)
                    assert item[0] != "-"
                except:
                    if item not in contents:
                        contents.append(
                            "\n"
                            + "\n".join(
                                [
                                    "### PoochBot Addition ###",
                                    f"# {cid}",
                                    item,
                                ]
                            )
                        )
                else:
                    for idx, line in enumerate(contents):
                        if k in line:
                            contents[idx] = "\n" + "\n".join(
                                [
                                    "### PoochBot Edit ###",
                                    f"# {cid}",
                                    f"# [EDITED FROM: {contents[idx]}]",
                                    item,
                                ]
                            )
                            break
                    else:
                        contents.append(
                            "\n"
                            + "\n".join(
                                [
                                    "### PoochBot Addition ###",
                                    f"# {cid}",
                                    item,
                                ]
                            )
                        )
            contents += "\n"
            os.makedirs(os.path.dirname(os.path.abspath(config_file)), exist_ok=True)
            with open(config_file, "w") as f:
                f.write("\n".join(contents))

class ConfigFileMknewParser(CombinedFixParser):
    fix_type: str = "config_file_mknew"
    items: dict[str, list[tuple[str, str]]]

    def __init__(self, checklist_name: str):
        super().__init__(checklist_name)
        self.items = {}

    def add_vuln(self, vulnerability: dict[str, str], fix: dict):
        super().add_vuln(vulnerability)
        if not self.items.get(fix["file"]):
            self.items[fix["file"]] = []

        self.items[fix["file"]] += [(vulnerability["cid"], fix["text"])]

    def execute(self):
        for config_file, values in self.items.items():
            make_file_backup(config_file)

            contents = []
            for cid, item in values:
                contents.append(
                    "\n"
                    + "\n".join(
                        [
                            "### PoochBot Addition ###",
                            f"# {cid}",
                            item,
                        ]
                    )
                )
            contents += "\n"
            os.makedirs(os.path.dirname(os.path.abspath(config_file)), exist_ok=True)
            with open(config_file, "w") as f:
                f.write("\n".join(contents))

class ConfigFileMknewInlineParser(CombinedFixParser):
    fix_type: str = "config_file_mknew_inlinetext"
    items: dict[str, tuple[str, str]]

    def __init__(self, checklist_name: str):
        super().__init__(checklist_name)
        self.items = {}

    def add_vuln(self, vulnerability: dict[str, str], fix: dict):
        super().add_vuln(vulnerability)
        self.items[fix["file"]] = (vulnerability["cid"], fix["text"])

    def execute(self):
        for config_file, (cid, text) in self.items.items():
            make_file_backup(config_file)
            contents = [
                "\n".join(
                    [
                        "### PoochBot Addition ###",
                        f"# {cid}",
                        text,
                    ]
                )
            ]
            contents += "\n"
            os.makedirs(os.path.dirname(os.path.abspath(config_file)), exist_ok=True)
            with open(config_file, "w") as f:
                f.write("\n".join(contents))

class ConfigFileMknewTomlParser(CombinedFixParser):
    fix_type: str = "config_file_mknew_toml"
    items: dict[str, dict[str, list[tuple[str, str]]]]

    def __init__(self, checklist_name: str):
        super().__init__(checklist_name)
        self.items = {}

    def add_vuln(self, vulnerability: dict[str, str], fix: dict):
        super().add_vuln(vulnerability)
        if not self.items.get(fix["file"]):
            self.items[fix["file"]] = {}

        if not self.items[fix["file"]].get(fix["key"]):
            self.items[fix["file"]][fix["key"]] = []

        self.items[fix["file"]][fix["key"]].append((vulnerability["cid"], fix["value"]))

    def execute(self):
        for config_file, groups in self.items.items():
            print(groups)
            contents = ""
            make_file_backup(config_file)

            for key, values in groups.items():
                print(key, values)
                contents += f"{key}\n"
                for cid, item in values:
                    contents += f"#{cid}\n{item}\n\n"
            contents += "\n"

            os.makedirs(os.path.dirname(os.path.abspath(config_file)), exist_ok=True)
            with open(config_file, "w") as f:
                f.write(contents)

class ConfigFileCopyoverParser(CombinedFixParser):
    fix_type: str = "config_file_copyover"
    items: dict[str, tuple[str, str]]

    def __init__(self, checklist_name: str):
        super().__init__(checklist_name)
        self.items = {}

    def add_vuln(self, vulnerability: dict[str, str], fix: dict):
        super().add_vuln(vulnerability)
        self.items[fix["file"]] = (vulnerability["cid"], fix["source"])

    def execute(self):
        for config_file, (cid, source) in self.items.items():
            # print(config_file, cid, source)
            # print(type(config_file), cid, source)
            make_file_backup(config_file)

            with open(source, "r") as f:
                source_contents = f.read()

            contents = [
                "\n".join(
                    [
                        "### PoochBot File Overwrite ###",
                        f"# {cid}",
                        source_contents,
                    ]
                )
            ]
            contents += "\n"
            os.makedirs(os.path.dirname(os.path.abspath(config_file)), exist_ok=True)
            with open(config_file, "w") as f:
                f.write("\n".join(contents))

class GroupPolicyParser(CombinedFixParser):
    fix_type: str = "group_policy"
    items: list[list[str]]
    checklist_name: str

    def __init__(self, checklist_name: str):
        super().__init__(checklist_name)
        self.items = []

    def add_vuln(self, vulnerability: dict[str, str], fix: dict):
        super().add_vuln(vulnerability)
        self.items += [
            "\n".join(
                [
                    f"; {vulnerability['cid']}",
                    f"; {fix['path']}",
                    f"; {fix['name']}",
                    f"; {fix['value']}",
                    fix["registry_hive"],
                    fix["registry_path"],
                    fix["registry_key"],
                    fix["registry_action"],
                ]
            )
        ]

    def build_file(self, file_path: str):
        if not os.path.exists(os.path.dirname(file_path)):
            os.mkdir(os.path.dirname(file_path))

        with open(file_path, "w") as f:
            f.write("\n\n".join(self.items))

    def execute(self):
        full_file_path = os.path.join(SUPPORTING_FILE_DIR, self.checklist_name + ".txt")
        windows_path = full_file_path.replace("/", "\\")
        self.build_file(full_file_path)
        cmdshell(f"{LGPO_PATH} /t {windows_path}")

class GroupPolicySecParser(CombinedFixParser):
    fix_type: str = "group_policy_sec"
    layout: dict[str, list]
    checklist_name: str

    def __init__(self, checklist_name: str):
        super().__init__(checklist_name)
        self.layout = {
            "Unicode": ["Unicode=yes"],
            "System Access": [],
            "Event Audit": [],
            "Registry Values": [],
            "Privilege Rights": [],
            "Service General Setting": [],
            "Version": ['signature="$CHICAGO$"', "Revision=1"],
        }
        self.checklist_name = checklist_name

    def add_vuln(self, vulnerability: dict[str, str], fix: dict):
        super().add_vuln(vulnerability)
        text = [
            f"; {vulnerability['cid']}",
            f"; {fix['path']}",
            f"; {fix['name']}",
            f"; {fix['value']}",
            fix["text"],
        ]

        self.layout[fix["category"]] += ["\n".join(text)]

    def build_file(self, file_path: str):
        if not os.path.exists(os.path.dirname(file_path)):
            os.mkdir(os.path.dirname(file_path))

        text = ""
        for key in self.layout.keys():
            # if the key has any values (we don't want to make sections with no policies)
            if self.layout[key]:
                text += (
                    f"[{key}]\n" + "\n\n".join(self.layout[key]) + "\n\n"
                )  # creating the toml config
                text += (
                    "; " + "-" * 120 + "\n"
                ) * 3 + "\n"  # separator for readability purposes

        text = text.replace("\n", "\r\n")
        with codecs.open(file_path, mode="w", encoding="utf_16_le") as f:
            f.write(text)

    def execute(self):
        full_file_path = os.path.join(SUPPORTING_FILE_DIR, self.checklist_name + ".inf")
        windows_path = full_file_path.replace("/", "\\")
        self.build_file(full_file_path)
        cmdshell(f"{LGPO_PATH} /s {windows_path}")

class GroupPolicyAuditParser(CombinedFixParser):
    fix_type: str = "group_policy_aaud"
    fields: list[str] = [
        "Machine Name",
        "Policy Target",
        "Subcategory",
        "Subcategory GUID",
        "Inclusion Setting",
        "Exclusion Setting",
        "Setting Value",
    ]
    items: list[list[str]]

    def __init__(self, checklist_name: str):
        super().__init__(checklist_name)
        self.items = []

    def add_vuln(self, vulnerability: dict[str, str], fix: dict):
        super().add_vuln(vulnerability)
        self.items.append(
            [
                "",
                fix["policy_target"],
                fix["subcategory"],
                fix["subcategory_guid"],
                fix["inclusion_setting"],
                fix["exclusion_setting"],
                fix["setting_value"],
            ]
        )

    def execute(self):
        full_file_path = os.path.join(SUPPORTING_FILE_DIR, self.checklist_name + ".csv")
        windows_path = full_file_path.replace("/", "\\")
        with open(windows_path, "w") as f:
            writer = csv.writer(f, lineterminator="\r\n")
            writer.writerow(self.fields)
            writer.writerows(self.items)
        cmdshell(f"{LGPO_PATH} /ac {windows_path}")

class WindowsServiceParser(GroupPolicySecParser, CombinedFixParser):
    fix_type: str = "windows_service"

    def add_vuln(self, vulnerability: dict[str, str], fix: dict):
        super().add_vuln(vulnerability)
        text = [
            f"; {vulnerability['cid']}",
            f"; {fix['display_name']} ({fix['name']})",
            f"; {fix['startup_type']}",
            fix["text"],
        ]

        self.layout["Service General Setting"] += ["\n".join(text)]

class FirefoxParser(CombinedFixParser):
    fix_type: str = "firefox"
    policy_map: dict[str]

    def __init__(self, checklist_name: str):
        super().__init__(checklist_name)
        self.policy_map = {"policies": {}}

    def add_vuln(self, vulnerability: dict[str, str], fix: dict):
        super().add_vuln(vulnerability)
        if not fix.get("preference"):
            self.policy_map["policies"][fix["key"]] = fix["value"]
        else:
            if self.policy_map["policies"].get("Preferences") == None:
                self.policy_map["policies"]["Preferences"] = {}
            self.policy_map["policies"]["Preferences"][fix["key"]] = fix["value"]

    def build_file(self, file_path: str):
        with open(file_path, "w") as f:
            json.dump(self.policy_map, f)

    def execute(self):
        self.build_file("./generated/policies.json")
        match OPTIONS["OS"].value:
            case OperatingSystem.WINDOWS | OperatingSystem.WINDOWS_SERVER:
                if os.path.exists(
                    "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe"
                ):
                    path = "C:\\Program Files (x86)\\Mozilla Firefox"

                elif os.path.exists("C:\\Program Files\\Mozilla Firefox\\firefox.exe"):
                    path = "C:\\Program Files\\Mozilla Firefox"
                else:
                    logger.error("No firefox installation detected.")
                    return
                path = os.path.join(path, "distribution")
            case OperatingSystem.UBUNTU | OperatingSystem.DEBIAN | OperatingSystem.FEDORA:
                path = "/etc/firefox/policies"

        os.makedirs(path, exist_ok=True)
        shutil.copy("./generated/policies.json", path)

#endregion

#region one time fix parsers

class CommandParser(OneTimeFixParser):
    fix_type: str = "command"
    command: str

    def parse(self, vulnerability: dict[str, str], fix: dict):
        super().parse(vulnerability)
        self.command = fix["command"]

    def execute(self):
        for command in self.command.splitlines():
            logger.info(f"Running {command}.")
            try:
                cmdshell(command)
            except:
                logger.exception(f"Failed running {command}.")
            else:
                logger.info(f"Ran {command}.")

class LinuxPermissionsParser(OneTimeFixParser):
    fix_type: str = "linux_permissions"
    target: str
    owner: str
    group: str
    mode: str

    def parse(self, vulnerability: dict[str, str], fix: dict):
        super().parse(vulnerability)
        self.target = fix["target"]
        self.owner = fix.get("owner")
        self.group = fix.get("group")
        self.mode = fix.get("mode")

    def execute(self):
        logger.info(f"Changing permissions for {self.target}.")
        if self.owner:
            try:
                cmdshell(f"chown {self.owner} {self.target}")
            except:
                logger.exception(f"Failed changing owner for {self.target}.")
            else:
                logger.info(f"Changed owner for {self.target}.")
        if self.group:
            try:
                cmdshell(f"chgrp {self.group} {self.target}")
            except:
                logger.exception(f"Failed changing group for {self.target}.")
            else:
                logger.info(f"Changed group for {self.target}.")
        if self.mode:
            try:
                cmdshell(f"chmod {self.mode} {self.target}")
            except:
                logger.exception(f"Failed changing mode for {self.target}.")
            else:
                logger.info(f"Changed mode for {self.target}.")

class ManualParser(OneTimeFixParser):
    fix_type: str = "manual"
    policy: str
    steps: str

    def parse(self, vulnerability: dict[str], fix: dict):
        super().parse(vulnerability)
        self.policy = vulnerability["policy"]
        self.steps = fix["steps"]

    def execute(self):
        formatted_solve_steps = "        " + "\n        ".join(self.steps.splitlines())
        rich.print(
            "\n".join(
                [
                    "        [bold red]Manual Vulnerability[/]",
                    f"        [bold orange1]Solve Steps[/]:\n{formatted_solve_steps}",
                ]
            )
        )
        input(
            "    Please press Enter when you have completed solving this vulnerability. "
        )

class AutomatedModuleParser(OneTimeFixParser):
    fix_type: str = "automated_module"

    def parse(self, vulnerability: dict[str, str], fix: dict):
        super().parse(vulnerability)
        pass

    def execute(self):
        pass

class OtherVulnerabilityParser(OneTimeFixParser):
    fix_type: str = "other_vulnerability"

    def parse(self, vulnerability: dict[str, str], fix: dict):
        super().parse(vulnerability)
        pass

    def execute(self):
        pass

#endregion
