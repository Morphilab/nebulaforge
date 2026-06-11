"""
NebulaForge - Secure command executor

"""

import re
import subprocess
from typing import List, Set, Tuple

DANGEROUS_PATTERNS = re.compile(r'[;|&$`\'"()#!{}]|\.\./|\.\.\\')

CONDA_ALWAYS_BLOCKED_FLAGS: Set[str] = {
    '--insecure', '--no-verify', '--force-reinstall',
    '--experimental', '--no-lock', '--clobber',
}

CONDA_ELEVATED_BLOCKED_FLAGS: Set[str] = {
    '--no-deps', '--reinstall', '--no-pin',
    '--no-channel-priority', '--override-channels',
    '--use-local', '--offline', '--copy',
    '--no-update-deps', '--no-default-package',
    '--no-python', '--unknown', '--repodata-fn', '--repodata-use-zst',
}

CONDA_CHANNEL_FLAGS: Set[str] = {'-c', '--channel'}


class SecureCommandRunner:
    """Command executor with security validations"""

    def __init__(self, config_manager, audit_logger):
        self.config_manager = config_manager
        self.audit_logger = audit_logger
        self.security_profile = config_manager.get_security_profile()

    def run_secure_command(self, command: List[str], context: str = "unknown") -> Tuple[bool, str]:
        self.refresh_profile()
        if not self._validate_command(command):
            return False, "Command not allowed by security policy"

        try:
            result = subprocess.run(  # noqa: S603 - shell=False and command is validated
                command,
                capture_output=True,
                text=True,
                timeout=self.security_profile.max_timeout,
                shell=False
            )
            if result.returncode == 0:
                self.audit_logger.log_secure_action("command_executed", context, "success")
                return True, result.stdout.strip()
            else:
                self.audit_logger.log_secure_action("command_execution_error", context, "error")
                return False, result.stderr.strip()
        except Exception as e:
            self.audit_logger.log_secure_action("command_execution_error", context, "error", {"error": str(e)})
            return False, str(e)

    def _validate_command(self, command: List[str]) -> bool:
        """Validate that the command is allowed and its arguments are safe"""
        if not command or command[0] not in self.security_profile.allowed_commands:
            return False
        profile_level = self.security_profile.level
        for arg in command[1:]:
            if DANGEROUS_PATTERNS.search(arg):
                return False
            if arg in CONDA_ALWAYS_BLOCKED_FLAGS:
                return False
            if arg in CONDA_ELEVATED_BLOCKED_FLAGS and profile_level in ('high', 'paranoid'):
                return False
            if arg in CONDA_CHANNEL_FLAGS and profile_level == 'paranoid':
                return False
        return True

    def refresh_profile(self) -> None:
        """Reload security profile from config"""
        self.security_profile = self.config_manager.get_security_profile()
