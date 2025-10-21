import logging
import re

import requests
from bs4 import BeautifulSoup

from poochbot.options import OPTIONS
from poochbot.utils import *

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

def parsereadme() -> None:
    soup = get_readme_soup()
    get_options_from_soup(soup)

def get_readme_soup() -> BeautifulSoup:
    match OPTIONS["OS"]:
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

def get_options_from_soup(soup: BeautifulSoup) -> None:
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
    #admins.insert(0, active)
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
        OPTIONS["USERS"]["ACTIVE_USER"] = active
        OPTIONS["USERS"]["ADMIN_USERS"] = admins
        OPTIONS["USERS"]["STD_USERS"] = users
        OPTIONS["SERVICES"] = parsed_services
    else:
        logger.critical("Aborting.")
