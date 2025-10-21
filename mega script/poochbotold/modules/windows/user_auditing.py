import logging
import re

import rich
import rich.table

from poochbotold import module
from poochbotold.options import OPTIONS
from poochbotold.utils import *

logger = logging.getLogger(__name__)

class EnumUsersException(Exception):
    pass

class User:
    name: str
    is_admin: bool
    groups: list[str]
    active: bool
    pwd_expires: bool
    pwd_changeable: bool
    is_builtin: bool

class UserAuditing(module.Module):
    """
    Creates/deletes users, promotes/demotes users, resets passwords, and enables password expiry.
    Used in conjunction with the parse_readme utility, it can automate all of user auditing.
    """

    name: str = "windows.user_auditing"
    aliases = ["user_auditing", "ua"]
    applies_to: list[OperatingSystem] = [
        OperatingSystem.WINDOWS,
        OperatingSystem.WINDOWS_SERVER,
    ]
    warnings: list = [
        "Do not use on Windows Server machines with Active Directory installed."
        "Does not work with groups other than Administrators and Users."
    ]

    builtin_users: list[str] = [
        "Administrator",
        "Guest",
        "WDAGUtilityAccount",
        "DefaultAccount",
    ]
    rejected_users: list = [
        "nolanjones",
        "poochbot",
    ]
    users: list[User]

    def __init__(self) -> None:
        super().__init__()
        self.users = []

    def do_enum_users(self, arg: str = None) -> None:
        """Show a table of all of the users on the system."""
        self._enumerate_users()
        table = rich.table.Table(
            "Username",
            "Is Admin",
            "Groups",
            "Active",
            "Password Expires",
            "Password Changeable",
            "Is Builtin",
        )
        for user in self.users:
            table.add_row(
                user.name,
                "[green]Yes" if user.is_admin else "[red]No",
                ", ".join(user.groups),
                "[green]Yes" if user.active else "[red]No",
                "[green]Yes" if user.pwd_expires else "[red]No",
                "[green]Yes" if user.pwd_changeable else "[red]No",
                "[green]Yes" if user.is_builtin else "[red]No",
            )
        rich.print(table)

    @module.Module.requires(
        OPTIONS["USERS"]["ADMIN_USERS"],
        OPTIONS["USERS"]["STD_USERS"],
    )
    def run(self) -> None:
        """GOes through the useer auditing process with the given user options"""

        try:
            self._enumerate_users()
            self._set_passwords()
            self._add_remove_users()
            self._enumerate_users()
            self._user_permissions()
            self._harden_builtin_accounts()
        except:
            logger.exception("Could not run module.")
            return

        logger.info("Completed user auditing.")

    def _enumerate_users(self) -> None:
        """Enumerates all users in the system"""

        self.users = []

        def get_users() -> None:
            """Get users from system"""

            try:
                net_user_result = cmdshell("net user")
                flag = False
                for line in net_user_result.split("\n"):
                    if "The command completed successfully" in line:
                        break
                    if flag:
                        for username in re.findall(r"\w+", line):
                            if username not in self.rejected_users:
                                user = User()
                                user.name = username
                                user.active = (
                                    "Account active               Yes"
                                    in cmdshell(f"net user {username}")
                                )
                                user.is_builtin = username in self.builtin_users
                                self.users.append(user)
                    if "-" in line:
                        flag = True
            except:
                logger.critical("Unable to enumerate users.")
                raise EnumUsersException()

            try:
                for user in self.users:
                    user.is_admin = "Administrators" in cmdshell(
                        f"net user {user.name}"
                    )
            except:
                logger.critical("Unable to group users.")
                raise EnumUsersException()

        def get_groups() -> list[str]:
            """Gets groups from system"""

            groups = []
            try:
                group_result = cmdshell("net localgroup")
                flag = False
                for line in group_result.split("\n"):
                    if "The command completed successfully" in line:
                        break
                    if flag:
                        groups.append(line.replace("*", ""))
                    if "----" in line:
                        flag = True
            except:
                logger.critical("Unable to enumerate users.")
                raise EnumUsersException()
            return groups

        def get_user_details(groups: list[str]) -> None:
            """Gets user details from system"""

            try:
                for user in self.users:
                    user.groups = []
                    user_details = cmdshell(f"net user {user.name}")
                    for group in groups:
                        if group in user_details:
                            user.groups.append(group)
                    user.active = "Account active               Yes" in user_details
                    user.pwd_expires = (
                        "Password expires             Never" not in user_details
                    )
                    user.pwd_changeable = (
                        "User may change password     Yes" in user_details
                    )
            except:
                logger.exception("Unable to compile user details.")
                raise EnumUsersException()

        get_users()
        groups = get_groups()
        get_user_details(groups)

        logger.info("Enumerated and grouped users.")

    def _set_passwords(self):
        """Set passwords of all users to secure password"""

        logger.info("Resetting passwords and enabling password expiry for all users.")
        for user in self.users:
            try:
                cmdshell(f"net user {user.name} CyberP@triot22")  # Resetting password
            except:
                logger.error(f"Failed setting password for {user.name}.")
            else:
                logger.info(f"Set {user.name}'s password to CyberP@triot22.")

            try:
                cmdshell(
                    f"wmic useraccount where \"Name='{user.name}'\" set PasswordExpires=true"
                )  # Setting password expiry
            except:
                logger.error(f"Failed enabling password expiry for {user.name}.")
            else:
                logger.info(f"Disabled password expiry for {user.name}.")

    def _add_remove_users(self) -> None:
        """Checking for the correct list of users"""

        def check_absent_users() -> None:
            """Checking for missing users"""

            absent_usernames = [
                username
                for username in [
                    *OPTIONS["USERS"]["ADMIN_USERS"].value,
                    *OPTIONS["USERS"]["STD_USERS"].value,
                ]
                if username not in [user.name for user in self.users if user.active]
            ]
            if absent_usernames:
                logger.info("Absent users detected. Creating/enabling these users.")
                for username in absent_usernames:
                    if cmdrc(f"net user {username}").returncode != 0:
                        try:
                            cmdshell(f"net user {username} CyberP@triot22 /add")
                        except:
                            logger.error(f"Failed adding {username}.")
                        else:
                            logger.info(
                                f"Added {username} with password CyberP@triot22."
                            )
                    else:
                        try:
                            cmdshell(f"net user {username} /active:yes")
                        except:
                            logger.error(f"Failed activating {username}.")
                        else:
                            logger.info(f"Activated {username}.")
            else:
                logger.info("No absent users detected.")

        def check_unauthorized_users() -> None:
            """Checking for unauthorized users"""

            unauthorized_usernames = [
                user.name
                for user in self.users
                if user.name
                not in [
                    *OPTIONS["USERS"]["ADMIN_USERS"].value,
                    *OPTIONS["USERS"]["STD_USERS"].value,
                ]
                and user.active
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
            else:
                logger.info("No unauthorized users detected.")

        check_absent_users()
        check_unauthorized_users()

    def _user_permissions(self) -> None:
        """Checking the roles of all users"""

        def check_admin_users() -> None:
            """Checking the roles of admin users"""
            incorrect_admins = [
                username
                for username in OPTIONS["USERS"]["STD_USERS"].value
                if username in [user.name for user in self.users if user.is_admin]
            ]
            if incorrect_admins:
                logger.info(
                    "Detected users that should not be administrators. Demoting these users."
                )
                for username in incorrect_admins:
                    try:
                        cmdshell(f"net localgroup Administrators {username} /delete")
                    except:
                        logger.error(f"Failed demoting {username}.")
                    else:
                        logger.info(f"Demoted {username} from Administrator.")
            else:
                logger.info(
                    "No users were detected that should not be Administrators and are."
                )

        def check_standard_users() -> None:
            """Checking the roles of standard users"""
            incorrect_stds = [
                username
                for username in OPTIONS["USERS"]["ADMIN_USERS"].value
                if username in [user.name for user in self.users if not user.is_admin]
            ]
            if incorrect_stds:
                logger.info(
                    "Detected users that should be Administrators. Promoting these users."
                )
                for username in incorrect_stds:
                    try:
                        cmdshell(f"net localgroup Administrators {username} /add")
                    except:
                        logger.error(f"Failed promoting {username}.")
                    else:
                        logger.info(f"Promoted {username} to Administrator.")
            else:
                logger.info(
                    "No users were detected that should be Administrators and aren't."
                )

        check_admin_users()
        check_standard_users()

    def _harden_builtin_accounts(self) -> None:
        """Hardens the builtin accounts of Administrator and Guest"""

        logger.info(
            "Disabling and setting passwords for Administrator and Guest accounts."
        )
        for username in ["Administrator", "Guest"]:
            try:
                cmdshell(f"net user {username} /active:no")
            except:
                logger.error(f"Failed disabling {username}.")
            else:
                logger.info(f"Disabled {username}.")

            try:
                cmdshell(f"net user {username} CyberP@triot21")
            except:
                logger.error(f"Failed setting password for {username}.")
            else:
                logger.info(f"Set {username}'s password to CyberP@triot21.")

            try:
                cmdshell(
                    f"wmic useraccount where \"Name='{username}'\" set PasswordExpires=true"
                )  # Setting password expiry
            except:
                logger.error(f"Failed enabling password expiry for {username}.")
            else:
                logger.info(f"Disabled password expiry for {username}.")
