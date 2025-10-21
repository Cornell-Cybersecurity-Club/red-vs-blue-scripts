import logging
import os

from poochbotold import module
from poochbotold.utils import *

logger = logging.getLogger(__name__)

class GroupPolicy(module.Module):
    """Prepares the machine for group policy configuration. Backs up, then resets group policy."""

    name: str = "windows.group_policy"
    aliases = ["group_policy", "gp"]
    applies_to: list[OperatingSystem] = [
        OperatingSystem.WINDOWS,
        OperatingSystem.WINDOWS_SERVER,
    ]
    options: dict = {}
    warnings: list = ["Be careful to not brick the machine!"]
    LGPO_PATH = ".\\programs\\LGPO.exe"
    GP_PATH = ".\\helpers\\group_policy\\Win10\\Old\\"

    def _export_gpo_backup(self):
        """Exports a backup of the current GPO to C:\\PoochBot\\backups\\gpedit"""

        os.makedirs(".\\backups\\gpedit\\", exist_ok=True)
        try:
            cmdshell(f"{self.LGPO_PATH} /b C:\\PoochBot\\backups\\gpedit")
        except:
            logger.exception(f"Failed exporting GPO backup.")
        else:
            logger.info("Exported GPO backup.")

    def _import_old_gpo_backup(self):
        """Reverts GPO back to the backup saved earlier"""

        try:
            cmdshell(f"{self.LGPO_PATH} /g .\\backups\\gpedit")
        except:
            logger.exception(f"Failed importing GPO backup.")
        else:
            logger.info("Imported GPO backup.")

    def _reset_gpo(self):
        """Reset GPO to defaults"""

        try:
            cmdshell('RD /S /Q "%WinDir%\\System32\\GroupPolicy"')
        except:
            logger.exception("Failed deleting machine policy.")
        else:
            logger.info("Deleted machine policy.")

        try:
            cmdshell('RD /S /Q "%WinDir%\\System32\\GroupPolicyUsers"')
        except:
            logger.exception("Failed deleting user policy.")
        else:
            logger.info("Deleted user policy.")

        try:
            subprocess.run(
                "secedit /configure /cfg C:\\Windows\\inf\\defltbase.inf /db defltbase.sdb /verbose",
                shell=True,
                capture_output=True,
                text=True,
            )
        except:
            logger.exception("Failed resetting local security policy.")
        else:
            logger.info("Reset local security policy.")
        self._force_update()

    def _force_update(self):
        """Force GPO to update"""

        try:
            cmdshell("gpupdate /force")
        except:
            logger.exception("Failed force updating GPO.")
        else:
            logger.info("Force updated group policy.")

    def _import_security(self):
        """Import the security section of the GPO"""

        try:
            cmdshell(f"{self.LGPO_PATH} /s {self.GP_PATH}Security.inf")
        except:
            logger.exception(f"Failed importing {self.GP_PATH}Security.inf.")
        else:
            logger.info("Imported Local Security Policy template.")

    def _import_audit(self):
        """Import the audit section of the GPO"""

        try:
            cmdshell(f"{self.LGPO_PATH} /ac {self.GP_PATH}Audit.csv")
        except:
            logger.exception(f"Failed importing {self.GP_PATH}Audit.csv.")
        else:
            logger.info("Imported Advanced Audit Policy configuration.")

    def _import_win_firewall(self):
        """Import the firewall section of the GPO"""

        try:
            cmdshell(f"{self.LGPO_PATH} /m {self.GP_PATH}Firewall.pol")
        except:
            logger.exception(f"Failed importing {self.GP_PATH}Firewall.pol.")
        else:
            logger.info(
                "Imported Security Settings\\Windows Defender Firewall with Advanced Security configuration."
            )

    def _import_ctrl_panel(self):
        """Import the control panel section of the GPO"""

        try:
            cmdshell(f"{self.LGPO_PATH} /m {self.GP_PATH}CtrlPanel.pol")
        except:
            logger.exception(f"Failed importing {self.GP_PATH}CtrlPanel.pol.")
        else:
            logger.info(
                "Imported Administrative Templates\\Control Panel configuration."
            )

    def _import_network(self):
        """Import the network section of the GPO"""

        try:
            cmdshell(f"{self.LGPO_PATH} /m {self.GP_PATH}Network.pol")
        except:
            logger.exception(f"Failed importing {self.GP_PATH}Network.pol.")
        else:
            logger.info("Imported Administrative Templates\\Network configuration.")

    def _import_system(self):
        """Import the system section of the GPO"""

        try:
            cmdshell(f"{self.LGPO_PATH} /m {self.GP_PATH}System.pol")
        except:
            logger.exception(f"Failed importing {self.GP_PATH}System.pol.")
        else:
            logger.info("Imported Administrative Templates\\System configuration.")

    def _import_wincomp_bitlocker(self):
        """Import the bitlocker section of the GPO"""

        try:
            cmdshell(f"{self.LGPO_PATH} /m {self.GP_PATH}WinComp.BitLocker.pol")
        except:
            logger.exception(f"Failed importing {self.GP_PATH}WinComp.BitLocker.pol.")
        else:
            logger.info(
                "Imported Administrative Templates\\Windows Configuration\\BitLocker Drive Encryption configuration."
            )

    def _import_wincomp_eventlog(self):
        """Import the eventlog section of the GPO"""

        try:
            cmdshell(f"{self.LGPO_PATH} /m {self.GP_PATH}WinComp.EventLog.pol")
        except:
            logger.exception(f"Failed importing {self.GP_PATH}WinComp.EventLog.pol.")
        else:
            logger.info(
                "Imported Administrative Templates\\Windows Configuration\\Event Log Service configuration."
            )

    def _import_wincomp_rds(self):
        """Import the RDS section of the GPO"""

        try:
            cmdshell(f"{self.LGPO_PATH} /m {self.GP_PATH}WinComp.RDS.pol")
        except:
            logger.exception(f"Failed importing {self.GP_PATH}WinComp.RDS.pol.")
        else:
            logger.info(
                "Imported Administrative Templates\\Windows Configuration\\Remote Desktop Services configuration."
            )

    def _import_wincomp_update(self):
        """Import the update section of the GPO"""

        try:
            cmdshell(f"{self.LGPO_PATH} /m {self.GP_PATH}WinComp.Update.pol")
        except:
            logger.exception(f"Failed importing {self.GP_PATH}WinComp.Update.pol.")
        else:
            logger.info(
                "Imported Administrative Templates\\Windows Configuration\\Windows Update configuration."
            )

    def _import_wincomp_other(self):
        """Import the other section of the GPO"""

        try:
            cmdshell(f"{self.LGPO_PATH} /m {self.GP_PATH}WinComp.Other.pol")
        except:
            logger.exception(f"Failed importing {self.GP_PATH}WinComp.Other.pol.")
        else:
            logger.info(
                "Imported Administrative Templates\\Windows Configuration configuration."
            )

    def run(self):
        """Runs all of group policy config."""
        
        self._export_gpo_backup()
        self._reset_gpo()
        self._force_update()
        logger.info("Finished preparing for group policy configuration.")
