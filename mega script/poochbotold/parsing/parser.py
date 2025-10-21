import logging
import yaml

from poochbotold.options import CriticalService
from poochbotold.parsing.fix_parsers import *

logger = logging.getLogger(__name__)

class InvalidFixTypeException(Exception):
    pass

#region maps

PARSE_MAP: dict[str, CombinedFixParser | OneTimeFixParser] = {
    "config_file": ConfigFileParser,
    "config_file_mknew": ConfigFileMknewParser,
    "config_file_mknew_inlinetext": ConfigFileMknewInlineParser,
    "config_file_mknew_toml": ConfigFileMknewTomlParser,
    "config_file_copyover": ConfigFileCopyoverParser,
    "command": CommandParser,
    "group_policy": GroupPolicyParser,
    "group_policy_sec": GroupPolicySecParser,
    "windows_service": WindowsServiceParser,
    "group_policy_aaud": GroupPolicyAuditParser,
    "linux_permissions": LinuxPermissionsParser,
    "manual": ManualParser,
    "automated_module": AutomatedModuleParser,
    "other_vulnerability": OtherVulnerabilityParser,
    "firefox": FirefoxParser,
}

APPLIES_TO_MAP: dict[str, CriticalService] = {
    "RDP": CriticalService.RDP,
    "SMB": CriticalService.SMB,
    "SSH": CriticalService.SSH,
    "Samba": CriticalService.SAMBA,
    "Mail": CriticalService.MAIL,
    "OpenVPN": CriticalService.OPENVPN,
    "AD": CriticalService.AD,
    "apache2": CriticalService.APACHE2,
    "FTP": CriticalService.FTP,
    "MYSQL": CriticalService.MYSQL,
    "PHP": CriticalService.PHP,
    "DNS": CriticalService.DNS,
    "IIS": CriticalService.IIS,
}

OS_MAP: dict[str, OperatingSystem] = {
    "Windows": OperatingSystem.WINDOWS,
    "Windows Server": OperatingSystem.WINDOWS_SERVER,
    "Ubuntu": OperatingSystem.UBUNTU,
    "Ubuntu 20": OperatingSystem.UBUNTU,
    "Ubuntu 22": OperatingSystem.UBUNTU,
    "Debian": OperatingSystem.DEBIAN,
    "Fedora": OperatingSystem.FEDORA,
}

OS_VERSION_MAP: dict[str, OperatingSystemVersion] = {
    "Ubuntu 20": OperatingSystemVersion.UBUNTU_20,
    "Ubuntu 22": OperatingSystemVersion.UBUNTU_22,
}

#endregion

#region Checklist

class Checklist:
    name: str
    filename: str
    subdirectory: str
    vulnerabilities: list[dict]
    selected_vulnerabilities: list[dict]
    supporting_file_dir: str = "./generated/"
    combined_fix_parsers: list[CombinedFixParser]
    one_time_fix_parsers: list[OneTimeFixParser]

    def __init__(self, checklist_filename: str, trimmed_name: str):
        logger.debug(f"Loading checklist: {checklist_filename}.")
        with open(checklist_filename, "r", encoding="utf-8") as f:
            checklist = yaml.safe_load(f)
            if checklist["version"] == 1.0:
                self.name = checklist["name"]
                self.filename = trimmed_name
                self.subdirectory = checklist_filename.split("\\")[1]
                self.vulnerabilities = checklist["vulnerabilities"]
            elif checklist["version"] == 1.1:
                self.name = checklist["name"]
                self.filename = trimmed_name
                self.subdirectory = checklist_filename.split("\\")[1]
                self.vulnerabilities = []
                for group in checklist["groups"]:
                    for vulnerability in group["vulnerabilities"]:
                        vulnerability["category"] = group["category"]
                        self.vulnerabilities.append(vulnerability)
            else:
                logger.error("Checklist does not have a version.")

    def _get_parser(self, fix_type: str) -> CombinedFixParser | OneTimeFixParser:
        """Gets the parser for a given fix and adds it to current parsers list"""
        
        parser_cls: CombinedFixParser | OneTimeFixParser = PARSE_MAP.get(fix_type)
        if parser_cls == None:
            raise InvalidFixTypeException(fix_type)
        if issubclass(parser_cls, CombinedFixParser):
            for parser in self.combined_fix_parsers:
                if fix_type == parser.fix_type:
                    return parser
            parser: CombinedFixParser = parser_cls(self.filename)
            self.combined_fix_parsers.append(parser)
            return parser
        elif issubclass(parser_cls, OneTimeFixParser):
            parser: OneTimeFixParser = parser_cls()
            self.one_time_fix_parsers.append(parser)
            return parser
        else:
            raise InvalidFixTypeException(fix_type)

    def select_vulnerabilities(self) -> None:
        """Select list of vulnerabilities"""
        
        self.selected_vulnerabilities = []
        for vulnerability in self.vulnerabilities:
            skip = False
            applies_to: list[str] = vulnerability.get("applies_to", [])
            # for at in applies_to:
            #     if "Not " in at:
            #         at = at.replace("Not ", "")
            #         if APPLIES_TO_MAP[at] in OPTIONS["SERVICES"].value:
            #             skip = True
            #             break
            #     else:
            #         if APPLIES_TO_MAP[at] not in OPTIONS["SERVICES"].value:
            #             skip = True
            #             break
            # if OPTIONS["OS"].value not in [
            #     OS_MAP.get(os_str)
            #     for os_str in vulnerability.get("operating_systems", [])
            # ]:
            #     skip = True

            # if "Ubuntu 20" in vulnerability.get("operating_systems", []):
            #     if OPTIONS["OS_VERSION"].value != OperatingSystemVersion.UBUNTU_20:
            #         skip = True

            # if "Ubuntu 22" in vulnerability.get("operating_systems", []):
            #     if OPTIONS["OS_VERSION"].value != OperatingSystemVersion.UBUNTU_22:
            #         skip = True

            # if OPTIONS["OS_VERSION"].value and OPTIONS["OS_VERSION"].value not in [
            #     OS_VERSION_MAP.get(osv_str)
            #     for osv_str in vulnerability.get("operating_system_versions", [])
            # ]:
            #     skip = True

            if not skip:
                self.selected_vulnerabilities.append(vulnerability)

    def parse(self) -> None:
        """Creates parsers for all selected vulnerabilities"""
        
        self.select_vulnerabilities()
        self.combined_fix_parsers = []
        self.one_time_fix_parsers = []
        for vulnerability in self.selected_vulnerabilities:
            for fix in vulnerability["fix"]:
                parser = self._get_parser(fix["fix_type"])
                if isinstance(parser, CombinedFixParser):
                    parser.add_vuln(vulnerability, fix)
                elif isinstance(parser, OneTimeFixParser):
                    parser.parse(vulnerability, fix)
                else:
                    logger.error("An error occured in creating the fix parser.")

    def execute(self) -> None:
        """Runs all fixes for the current parsers"""
        
        for parser in self.one_time_fix_parsers:
            v = parser.vulnerability
            rich.print(f"    [bold white][{v['cid']}][/] [bold blue]{v['policy']}[/]")
            parser.execute()

        for parser in self.combined_fix_parsers:
            for v in parser.vulnerabilities:
                rich.print(
                    f"    [bold white][{v['cid']}][/] [bold blue]{v['policy']}[/]e"
                )
            parser.execute()

#endregion
