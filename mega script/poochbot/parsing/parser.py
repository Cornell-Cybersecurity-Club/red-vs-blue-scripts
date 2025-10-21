import logging
import yaml

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

#endregion

#region Checklist

class Checklist:
    name: str
    filename: str
    subdirectory: str
    vulnerabilities: list[dict]
    supporting_file_dir: str = "./generated/"
    combined_fix_parsers: list[CombinedFixParser]
    one_time_fix_parsers: list[OneTimeFixParser]

    def __init__(self, checklist_filename: str, trimmed_name: str):
        logger.debug(f"Loading checklist: {checklist_filename}.")
        with open(checklist_filename, "r", encoding="utf-8") as f:
            
            # load basic information about checklist
            checklist = yaml.safe_load(f)
            self.name = checklist["name"]
            self.filename = trimmed_name
            try: #for windows filepaths with '\'
                self.subdirectory = checklist_filename.split("\\")[1]
            except: #for windows filepaths with '/'
                self.subdirectory = checklist_filename.split("/")[1]

            # load vulns in checklist depending on version
            if checklist["version"] == 1.0:
                self.vulnerabilities = checklist["vulnerabilities"]
            elif checklist["version"] == 1.1:
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

    def parse(self) -> None:
        """Creates parsers for all selected vulnerabilities"""
        
        self.combined_fix_parsers = []
        self.one_time_fix_parsers = []
        for vulnerability in self.vulnerabilities:
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
