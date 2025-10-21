# disable root: sudo passwd -l root
# TODO: change encryption type!!!
# TODO: yescrypt for ubuntu 22.04, sha512 for ubuntu 20.04 and earlier

import logging

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
    is_sudoer: bool
    groups: list[str]
    enc_pwd: str
    uid: int
    gid: int
    full_name: str
    home_dir: str
    shell: str
    unlocked: bool
    is_system: bool


class UserAuditing(module.Module):
    """
    Creates/deletes users, promotes/demotes users, resets passwords, and enables password expiry.
    Used in conjunction with the parse_readme utility, it can automate all of user auditing.
    """

    name: str = "ubuntu.user_auditing"
    aliases = ["user_auditing", "ua"]
    applies_to: list[OperatingSystem] = [
        OperatingSystem.UBUNTU,
        OperatingSystem.DEBIAN,
        OperatingSystem.FEDORA,
    ]
    rejected_users: list = ["poochbot"]
    users: list[User] = []

    def do_enum_users(self, arg: str = None) -> None:
        """Show a table of all of the users on the system."""
        self._enumerate_users()
        table = rich.table.Table(
            "Username",
            "Is Sudoer",
            "Groups",
            "Encrypted Password",
            "UID",
            "GID",
            "Full Name",
            "Home Directory",
            "Shell",
            "Unlocked",
            "Is System",
        )
        for user in self.users:
            table.add_row(
                user.name,
                "[green]Yes" if user.is_sudoer else "[red]No",
                ", ".join(user.groups),
                user.enc_pwd,
                user.uid,
                user.gid,
                user.full_name,
                user.home_dir,
                user.shell,
                "[green]Yes" if user.unlocked else "[red]No",
                "[green]Yes" if user.is_system else "[red]No",
            )
        rich.print(table)

    @module.Module.requires(
        OPTIONS["USERS"]["ADMIN_USERS"],
        OPTIONS["USERS"]["STD_USERS"],
    )
    def run(self) -> None:
        self._enumerate_users()
        self._add_remove_users()
        self._enumerate_users()
        self._user_permissions()
        self._set_passwords()
        self._secure_system_accts()
        self._account_expiry()

    def _enumerate_users(self) -> None:
        self.users = []

        try:
            uid_min, uid_max = map(
                int,
                cmdshell(
                    "grep -E '^UID_MIN|^UID_MAX' /etc/login.defs | awk '{print $2}'"
                )
                .strip()
                .split("\n"),
            )
        except:
            logger.exception("Failed getting UID_MIN and UID_MAX from login.defs.")
            raise

        try:
            passwd_file = cmd(["getent", "passwd"])
            for line in passwd_file.split("\n"):
                if not line:
                    continue
                user = User()

                (
                    user.name,
                    _,  # encrypted password, handled later
                    user.uid,
                    user.gid,
                    user.full_name,
                    user.home_dir,
                    user.shell,
                ) = line.split(":")

                user.is_system = not (uid_min <= int(user.uid) <= uid_max)
                self.users.append(user)
        except Exception as e:
            print(e)
            logger.critical("Unable to enumerate users.", exc_info=True)
            raise EnumUsersException

        for user in self.users:
            user.groups = []
            try:
                user.groups = cmd(["id", "-Gn", user.name]).rstrip().split(" ")
                user.is_sudoer = "sudo" in user.groups
            except:
                logger.critical(f"Unable to enumerate groups for user {user.name}.")
                raise EnumUsersException

            user.enc_pwd = ""
            try:
                user.enc_pwd = cmd(["getent", "shadow", user.name]).split(":")[1]
            except:
                logger.critical(
                    f"Unable to enumerate encrypted password for user {user.name}."
                )
                raise EnumUsersException

            # if the second field in `passwd -S` is P, then the account is unlocked, if it's L, it's locked.
            user.unlocked = cmd(["passwd", "-S", user.name]).split(" ")[1] == "P"

    def _set_passwords(self) -> None:
        logger.info("Setting user passwords.")
        for user in self.users:
            try:
                cmdshell(f"echo '{user.name}:CyberP@triot22' | chpasswd")
            except:
                logger.error(f"Failed setting password for {user.name}.")
            else:
                logger.info(f"Set {user.name}'s password to CyberP@triot22.")

    def _add_remove_users(self) -> None:
        def check_absent_users() -> None:
            absent_usernames = [
                username
                for username in [
                    *OPTIONS["USERS"]["ADMIN_USERS"].value,
                    *OPTIONS["USERS"]["STD_USERS"].value,
                ]
                if username not in [user.name for user in self.users if user.unlocked]
            ]
            if absent_usernames:
                logger.info("Absent users detected. Creating/enabling these users.")
                for username in absent_usernames:
                    if username in [user.name for user in self.users]:
                        try:
                            cmd(["usermod", "-U", username])
                        except:
                            logger.error(f"Failed unlocking {username}.")
                        else:
                            logger.info(f"Unlocked {username}.")
                    else:
                        try:
                            cmd(["useradd", username])
                        except:
                            logger.error(f"Failed adding {username}.")
                        else:
                            logger.info(f"Added {username}.")
            else:
                logger.info("No absent users detected.")

        def check_unauthorized_users() -> None:
            unauthorized_usernames = [
                user.name
                for user in self.users
                if not user.is_system
                and user.name
                not in [
                    *OPTIONS["USERS"]["ADMIN_USERS"].value,
                    *OPTIONS["USERS"]["STD_USERS"].value,
                ]
            ]
            if unauthorized_usernames:
                logger.info("Unauthorized users detected. Deleting these users.")
                print(unauthorized_usernames)
                cont = input("Continue? (y/n)")
                if cont != "y":
                    return
                for username in unauthorized_usernames:
                    try:
                        cmd(["userdel", username])
                    except:
                        logger.error(f"Failed removing {username}.")
                    else:
                        logger.info(f"Disabled {username}.")
            else:
                logger.info("No unauthorized users detected.")

        check_absent_users()
        check_unauthorized_users()

    def _user_permissions(self) -> None:
        def check_sudoers() -> None:
            incorrect_sudoers = [
                username
                for username in OPTIONS["USERS"]["STD_USERS"].value
                if username in [user.name for user in self.users if user.is_sudoer]
            ]
            if incorrect_sudoers:
                logger.info(
                    "Detected users that should not be sudoers. Demoting these users."
                )
                for username in incorrect_sudoers:
                    try:
                        cmdshell(f"gpasswd -d {username} sudo")
                    except:
                        logger.error(f"Failed demoting {username}.")
                    else:
                        logger.info(f"Removed {username} from sudoers group.")
            else:
                logger.info(
                    "No users were detected that should not be sudoers and are."
                )

        def check_standard() -> None:
            incorrect_stds = [
                username
                for username in OPTIONS["USERS"]["ADMIN_USERS"].value
                if username in [user.name for user in self.users if not user.is_sudoer]
            ]
            if incorrect_stds:
                logger.info(
                    "Detected users that should be sudoeres. Promoting these users."
                )
                for username in incorrect_stds:
                    try:
                        cmdshell(f"gpasswd -a {username} sudo")
                    except:
                        logger.error(f"Failed promoting {username}.")
                    else:
                        logger.info(f"Removed {username} from sudoers group.")
            else:
                logger.info("No users were detected that should be sudoers and aren't.")

        check_sudoers()
        check_standard()

    def _secure_system_accts(self) -> None:
        logger.info("Securing system accounts.")
        for user in [user for user in self.users if user.is_system]:
            if user.name not in ["root", "sync", "shutdown", "halt"]:
                try:
                    cmdshell(f"usermod -s $(which nologin) {user.name}")
                except:
                    logger.exception(
                        f"Failed setting shell to nologin for {user.name}."
                    )
                else:
                    logger.info(f"Set shell to nologin for {user.name}.")

            try:
                cmdshell(f"passwd -dl {user.name}")
            except:
                logger.exception(f"Failed locking {user.name}.")
            else:
                logger.info(f"Locked {user.name}.")

        try:
            cmdshell("usermod -g 0 root")
        except:
            logger.exception("Failed setting default GID to 0 for the root account.")
        else:
            logger.info("Set default GID to 0 for the root account.")

    def _account_expiry(self):
        logger.info("Setting user password expiry.")
        for user in self.users:
            try:
                cmdshell(f"chage --mindays 1 {user.name}")
            except:
                logger.exception(f"Failed setting mindays to 1 day for {user.name}.")
            else:
                logger.debug(f"Set mindays to 1 day for {user.name}.")

            try:
                cmdshell(f"chage --maxdays 42 {user.name}")
            except:
                logger.exception(f"Failed setting mindays to 42 days for {user.name}.")
            else:
                logger.debug(f"Set mindays to 42 days for {user.name}.")

            try:
                cmdshell(f"chage --warndays 7 {user.name}")
            except:
                logger.exception(f"Failed setting warndays to 7 days for {user.name}.")
            else:
                logger.debug(f"Set warndays to 7 days for {user.name}.")

            try:
                cmdshell(f"chage --inactive 30 {user.name}")
            except:
                logger.exception(
                    f"Failed setting inactive password lock to 30 days for {user.name}."
                )
            else:
                logger.debug(f"Set inactive password lock to 30 days for {user.name}.")
