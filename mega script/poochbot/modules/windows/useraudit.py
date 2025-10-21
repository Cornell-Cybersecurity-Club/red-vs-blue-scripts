import logging

import re
import rich

from poochbot.options import OPTIONS
from poochbot.utils import *

logger = logging.getLogger(__name__)

pwd: str = "QWERTYasdfgh!!!"

ignoredusers: list = [
    "nolan",
    "nolanjones",
    "poochbot",
]

builtinusers: list[str] = [
    "Administrator",
    "Guest",
    "WDAGUtilityAccount",
    "DefaultAccount",
]

def useraudit() -> None:
    users = getusers()
    users = addremoveusers(users)
    groups = getgroups()

    rich.print("[bold]Hardening users[/]")
    for user in users:
        hardenuser(user, groups)

    hardenbuiltinaccounts()

    rich.print("[bold]Completed user audit[/]")

#region getting info

def getusers() -> list[str]:
    users = []
    net_user_result = cmdshell("net user")
    flag = False
    for line in net_user_result.split("\n"):
        if "The command completed successfully" in line:
            break
        if flag:
            for username in re.findall(r"\w+", line):
                # ignore ignored users, builtin users, and active user (builtin will all be disabled anyway)
                if username not in [*ignoredusers, *builtinusers, OPTIONS["USERS"]["ACTIVE_USER"]]:
                    users.append(username)
        if "-" in line:
            flag = True

    return users

def getgroups() -> dict[str, str]:
    groups = {}
    group_result = cmdshell("net localgroup")
    flag = False
    for line in group_result.split("\n"):
        if "The command completed successfully" in line:
            break
        if flag:
            groupname = line.replace("*", "")
            groups[groupname[:20]] = groupname
        if "----" in line:
            flag = True
    return groups

#endregion

#region verify users

def addremoveusers(users: list[str]) -> list[str]:
    usersnew = users

    def checkabsentusers() -> None:
        absent_usernames = [
            username
            for username in [
                *OPTIONS["USERS"]["ADMIN_USERS"],
                *OPTIONS["USERS"]["STD_USERS"],
            ]
            if username not in users
        ]
        if absent_usernames:
            logger.info("Absent users detected. Creating these users.")
            for username in absent_usernames:
                try:
                    cmdshell(f"net user {username} {pwd} /add")
                except:
                    logger.error(f"Failed adding {username}.")
                else:
                    logger.info(
                        f"Added {username} with password {pwd}"
                    )
                    usersnew.append(username)
        else:
            logger.info("No absent users detected.")

    def checkunauthorizedusers() -> None:
        unauthorized_usernames = [
            username
            for username in users
            if username
            not in [
                *OPTIONS["USERS"]["ADMIN_USERS"],
                *OPTIONS["USERS"]["STD_USERS"],
            ]
        ]
        if unauthorized_usernames:
            logger.info("Unauthorized users detected. Disabling these users.")
            for username in unauthorized_usernames:
                try:
                    cmdshell(f"net user {username} /active:no")
                except:
                    logger.error(f"Failed disabling {username}.")
                else:
                    logger.info(f"Disabled {username}.")
                    usersnew.remove(username)
        else:
            logger.info("No unauthorized users detected.")

    rich.print("[bold]Correcting user list[/]")
    checkabsentusers()
    checkunauthorizedusers()

    return usersnew

#endregion

#region normal and admin accounts

def setactive(user: str) -> None:
    try:
        cmdshell(f"net user {user} /active:yes")
    except:
        logger.error(f"Failed activating {user}.")
    else:
        logger.info(f"Activated {user}.")

def setpassword(user: str) -> None:
    try:
        cmdshell(f"net user {user} {pwd}")
    except:
        logger.error(f"Failed setting password for {user}.")
    else:
        logger.info(f"Set {user}'s password to {pwd}")

    try:
        cmdshell(
            f"wmic useraccount where \"Name='{user}'\" set PasswordExpires=true"
        )
    except:
        logger.error(f"Failed enabling password expiry for {user}.")
    else:
        logger.info(f"Enabled password expiry for {user}.")

    try:
        cmdshell(
            f"wmic useraccount where \"Name='{user}'\" set PasswordChangeable=true"
        )
    except:
        logger.error(f"Failed enabling password changeable for {user}.")
    else:
        logger.info(f"Enabled password changeable for {user}.")

def setgroups(user: str, usergroups: list[str]) -> None:
    isadmin = "Administrators" in usergroups
    shouldbeadmin = user in OPTIONS["USERS"]["ADMIN_USERS"]

    # fix admin status
    if isadmin and not shouldbeadmin:
        logger.info(
            f"{user} should not be administrator"
        )

        try:
            cmdshell(f"net localgroup Administrators {user} /delete")
        except:
            logger.error(f"Failed demoting {user}.")
        else:
            logger.info(f"Demoted {user} from Administrator.")
            usergroups.remove("Administrators")
    elif not isadmin and shouldbeadmin:
        logger.info(
            f"{user} should be administrator"
        )
                    
        try:
            cmdshell(f"net localgroup Administrators {user} /add")
        except:
            logger.error(f"Failed promoting {user}.")
        else:
            logger.info(f"Promoted {user} to Administrator.")
    elif isadmin:
        usergroups.remove("Administrators")

    # all uesrs should be in Users
    try:
        usergroups.remove("Users")
    except:
        logger.info(
            f"{user} should be in Users group"
        )
                    
        try:
            cmdshell(f"net localgroup Users {user} /add")
        except:
            logger.error(f"Failed adding {user}.")
        else:
            logger.info(f"Promoted {user} to User.")

    # ask for confimation for all other group membership
    for group in usergroups:
        if input(f"Should {user} be in group: {group}? (Y/n) ").lower() == "n":
            try:
                cmdshell(f"net localgroup \"{group}\" {user} /delete")
            except:
                logger.error(f"Failed Removing {user} from {group}.")
            else:
                logger.info(f"Removed {user} from {group}.")

def hardenuser(user: str, groups: dict[str, str]) -> None:
    rich.print(f"[bold]Hardening user: {user}[/]")

    setactive(user)
    setpassword(user)

    userdetails = cmdshell(f"net user {user}")

    usergroups = []
    for group in groups.keys():
        if group in userdetails:
            usergroups.append(groups[group])

    setgroups(user, usergroups)

    if not "Account expires              Never" in userdetails:
        logger.error(f"ACCOUNT EXPIRES FOR: {user} (user net user {user} for more info)")
    if not "Logon hours allowed          All" in userdetails:
        logger.error(f"SPECIFIED LOGON HOURS FOR: {user} (user net user {user} for more info)")
    if not "Password required            Yes" in userdetails:
        logger.error(f"PASSWORD NOT REQUIRED FOR: {user} (user net user {user} for more info)")
    if len(userdetails.split("\n")[15].split()) > 2:
        logger.error(f"LOGONSCRIPT FOUND FOR: {user} (user net user {user} for more info)")

#endregion

#region builtin accounts

def disableUser(user: str) -> None:
    try:
        cmdshell(f"net user {user} /active:no")
    except:
        logger.error(f"Failed disabling {user}.")
    else:
        logger.info(f"Disabled {user}.")

def hardenbuiltinaccounts() -> None:
    rich.print(f"[bold]Hardening builtin accounts[/]")
    logger.info(
        "Disabling builtin accounts"
    )
    for username in builtinusers:
        disableUser(username)
        setpassword(username)

#endregion