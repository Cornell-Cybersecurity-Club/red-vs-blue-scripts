import logging
import re

import requests
import rich
from bs4 import BeautifulSoup

from poochbotold import module
from poochbotold.options import OPTIONS
from poochbotold.utils import *

logger = logging.getLogger(__name__)

TEXT_TO_SERVICE: dict[str, CriticalService] = {
    "Remote Desktop": CriticalService.RDP,
    "SMB": CriticalService.SMB,
    "SSH": CriticalService.SSH,
    "Samba": CriticalService.SAMBA,
    "Mail": CriticalService.MAIL,
    "Active Directory": CriticalService.AD,
    "apache2": CriticalService.APACHE2,
    "FTP": CriticalService.FTP,
    "MySQL": CriticalService.MYSQL,
    "PHP": CriticalService.PHP,
    "DNS": CriticalService.DNS,
}


class ParseReadme(module.Module):
    """
    Parses the README in a CyberPatriot image to extract image data and optionally save to global module options.
    """

    name: str = "parse_readme"
    aliases = ["pr"]
    applies_to: list[OperatingSystem] = [
        OperatingSystem.WINDOWS,
        OperatingSystem.WINDOWS_SERVER,
        OperatingSystem.UBUNTU,
        OperatingSystem.DEBIAN,
        OperatingSystem.FEDORA,
    ]
    warnings: list = ["Review data before saving to options to avoid image penalties."]

    def run(self) -> None:
        soup = self._get_readme_soup()
        self._get_options_from_soup(soup)

    def do_planb(self, arg: str) -> None:
        url = input("Please paste the URL of the README, then press enter: ")
        r = requests.get(url)
        self._get_options_from_soup(BeautifulSoup(r.content, "html.parser"))

    def do_planc(self, arg: str) -> None:

        print(
            "Paste a complete copy of the user list, starting from Authorized Administrators to the last user. Press Ctrl-D (Linux) or Ctrl-Z (Windows) to save it."
        )
        contents = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            contents.append(line)

        admins_users_list = "\n".join(contents)
        print(admins_users_list)
        admins_list, users_list = admins_users_list.split("Authorized Users:\n")

        active, *admins = [
            line.replace(" (you)", "")
            for line in admins_list.replace(
                "Authorized Administrators:\n", ""
            ).splitlines()
            if len(line) > 0 and "password:" not in line
        ]
        admins.insert(0, active)
        users = users_list.splitlines()
        rich.print(
            f"\n[bold]Options:[/]\nActive User: {active}\nAdmin Users: {admins}\nStandard Users: {users}"
        )
        if input("Is it OK to set these options? (Y/n) ").lower() != "n":
            logger.info("Setting options.")
            OPTIONS["USERS"]["ACTIVE_USER"].set_value(active)
            OPTIONS["USERS"]["ADMIN_USERS"].set_value(admins)
            OPTIONS["USERS"]["STD_USERS"].set_value(users)
        else:
            logger.critical("Aborting.")

    def _get_readme_soup(self) -> BeautifulSoup:
        match OPTIONS["OS"].value:
            case OperatingSystem.WINDOWS | OperatingSystem.WINDOWS_SERVER:
                with open("C:\CyberPatriot\README.url", "r") as f:
                    url = (
                        f.read().splitlines()[1].replace("URL=", "")
                    )  # second line, starts with "URL=" then the URL
            case OperatingSystem.UBUNTU | OperatingSystem.DEBIAN:
                with open("/opt/CyberPatriot/README.desktop", "r") as f:
                    url = (
                        f.read()
                        .splitlines()[3]
                        .replace("Exec=x-www-browser ", "")
                        .replace('"', "")
                    )  # fourth line, starts with "Exec=x-www-browser " and has quotes
        r = requests.get(url)
        return BeautifulSoup(r.content, "html.parser")

    def _get_options_from_soup(self, soup: BeautifulSoup) -> None:
        admins_users_list = soup.body.body.pre.text

        admins_list, users = [
            x.lstrip().rstrip().splitlines()
            for x in admins_users_list.split("Authorized Users:")
        ]

        active, *admins = [
            line.rstrip(" (you)")
            for line in admins_list[1:]
            if len(line) > 0 and line[0] != "\t"  # ignore the password line
        ]
        admins.insert(0, active)
        services: list[str] = [
            li.text
            for li in soup.body.body.find(string=re.compile("Critical Services:"))
            .parent.parent.findNext("ul")
            .findAll("li")
        ]

        parsed_services = []
        for service in services:
            for s, c in TEXT_TO_SERVICE.items():
                if s.lower() in service.lower():
                    parsed_services += [c]

        print(
            "\n".join(
                [
                    "Options:",
                    f"Active User: {active}",
                    f"Admin Users: {admins}",
                    f"Standard Users: {users}",
                    f"Critical Services: {services}",
                    f"Parsed Critical Services: {parsed_services}",
                ]
            )
        )

        if input("Is it OK to set these options? (Y/n) ").lower() != "n":
            OPTIONS["USERS"]["ACTIVE_USER"].set_value(active)
            OPTIONS["USERS"]["ADMIN_USERS"].set_value(admins)
            OPTIONS["USERS"]["STD_USERS"].set_value(users)
            OPTIONS["SERVICES"].set_value(parsed_services)
        else:
            logger.critical("Aborting.")


if __name__ == "__main__":
    m = ParseReadme()
    m.run()
