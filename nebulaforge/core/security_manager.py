"""

NebulaForge - Main security manager
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from nebulaforge.utils.command_runner import SecureCommandRunner

from .audit_logger import AuditLogger
from .backup_manager import BackupManager
from .config_manager import ConfigManager
from .dependency_checker import SecureDependencyChecker
from .error_handler import SecureErrorHandler
from .secrets import SecureCredentials
from .secure_store import SecureStore
from .security_models import SecurityProfile
from .security_validator import SecurityValidator
from .session import SessionManager


class SecurityManager:
    """Main orchestrator for NebulaForge"""

    # Operations that create, modify, restore, or remove an environment.
    # Import and clone targets use 'create'; install/update use 'modify'.
    MUTATING_OPERATIONS = frozenset({'create', 'modify', 'delete', 'restore'})

    def __init__(self, config_path: Optional[Path] = None, production_mode: Optional[bool] = None):
        self.config_manager = ConfigManager(config_path)
        self.production_mode = (
            production_mode if production_mode is not None
            else self.config_manager.get('core.production_mode', False)
        )

        self.config_manager.initialize_secure_directories()
        self.audit_logger = AuditLogger(self.config_manager)
        self.error_handler = SecureErrorHandler(self.audit_logger)
        self.command_runner = SecureCommandRunner(self.config_manager, self.audit_logger)
        self.backup_manager = BackupManager(
            self.config_manager,
            command_runner=self.command_runner,
            audit_logger=self.audit_logger,
        )
        self.dependency_checker = SecureDependencyChecker(self.config_manager, self.command_runner)
        self.validator = SecurityValidator(self.config_manager, self.audit_logger)

        data_dir = Path(self.config_manager.get('paths.secure_data_dir', '~/.nebulaforge/data')).expanduser()
        self.credentials = SecureCredentials(data_dir / 'credentials.enc')
        self.session_manager = SessionManager()
        self.secure_store = SecureStore(data_dir / 'secure_store.enc')

        # Load security profile as SecurityProfile object (avoids dict vs object errors)
        profile_name = self.config_manager.get('security.security_level', 'medium')
        self.security_profile: SecurityProfile = self.config_manager.get_security_profile(profile_name)

        self.audit_logger.log_secure_action(
            action="system_start",
            target="security_manager",
            status="success",
            details={"version": "1.0", "security_level": self.security_profile.level}
        )

    def require_confirmation_for(self, operation: str, target: str) -> bool:
        """Return whether an otherwise-allowed operation needs confirmation.

        Protected environments and production-mode mutations are hard denials,
        not confirmation prompts, so this returns False for them. Interfaces
        should call :meth:`authorize_operation` to obtain the denial message
        and only prompt when this method returns True.
        """
        if self._check_operation_allowed(operation, target):
            return False
        return bool(self.security_profile.require_confirmation)

    def _check_operation_allowed(self, operation: str, target: str) -> Optional[str]:
        """Return an error message if an operation is not allowed, None if ok."""
        if target in self.security_profile.protected_envs and operation in (
            'delete', 'modify', 'create', 'restore'
        ):
            return f"Environment '{target}' is protected and cannot be modified"
        if self.production_mode and operation in self.MUTATING_OPERATIONS:
            return (
                f"Cannot {operation} environments in production mode "
                "(read-only); disable it with 'nebulaforge config --production-mode off'"
            )
        return None

    def authorize_operation(self, operation: str, target: str, confirmed: bool = False) -> Optional[str]:
        """Return an error message when an operation must be blocked or confirmed.

        The returned message is suitable for a CLI/interactive display. A
        confirmation requirement is a policy outcome, not a hard denial; the
        caller can prompt the user and retry with ``confirmed=True``.
        """
        not_allowed = self._check_operation_allowed(operation, target)
        if not_allowed:
            return not_allowed
        if self.require_confirmation_for(operation, target) and not confirmed:
            target_label = f"'{target}'" if target else "the backup environment"
            return f"Confirmation required to {operation} {target_label}"
        return None

    def get_security_info(self) -> Dict[str, Any]:
        """Get security information safely"""
        return {
            'profile_name': self.security_profile.name,
            'level': self.security_profile.level,
            'description': self.security_profile.description,
            'allowed_commands': self.security_profile.allowed_commands,
            'protected_envs_count': len(self.security_profile.protected_envs),
            'max_timeout': self.security_profile.max_timeout,
            'production_mode': self.production_mode,
        }

    def create_secure_environment(self, env_config: Dict[str, Any], confirmed: bool = False) -> Tuple[bool, str]:
        """Create secure environment"""
        env_name = env_config.get('name', '')
        python_version = env_config.get('python_version', '')
        packages = env_config.get('packages', [])

        if not self.validator.validate_env_name(env_name):
            return False, "Invalid environment name"

        not_allowed = self.authorize_operation('create', env_name, confirmed)
        if not_allowed:
            return False, not_allowed

        valid, invalid = self.validator.validate_package_list(packages)
        if not valid:
            return False, f"Invalid packages: {', '.join(invalid)}"

        command: List[str] = ['conda', 'create', '-n', str(env_name), '-y']
        if python_version:
            command.extend([f'python={python_version}'])
        if packages:
            command.extend(packages)

        success, output = self.command_runner.run_secure_command(command, 'create_environment')

        if success:
            self.audit_logger.log_secure_action("environment_created", env_name, "success")
            return True, f"Environment '{env_name}' created successfully"
        else:
            self.audit_logger.log_secure_action("environment_creation_failed", env_name, "error")
            return False, f"Error creating environment: {output}"

    def list_environments(self) -> Tuple[bool, List[str]]:
        """List available environments"""
        try:
            success, output = self.command_runner.run_secure_command(
                ['conda', 'env', 'list', '--json'], 'list_environments'
            )
            if success:
                data = json.loads(output)
                envs = [Path(p).name for p in data.get('envs', [])]
                return True, envs
            return False, []
        except Exception as e:
            self.error_handler.handle_system_error(e, "list_environments")
            return False, []

    def install_packages(
        self,
        env_name: str,
        packages: List[str],
        conflict_check: bool = True,
        confirmed: bool = False,
    ) -> Tuple[bool, str]:
        """Install packages in an environment"""
        if not self.validator.validate_env_name(env_name):
            return False, "Invalid environment name"

        not_allowed = self.authorize_operation('modify', env_name, confirmed)
        if not_allowed:
            return False, not_allowed

        valid, invalid = self.validator.validate_package_list(packages)
        if not valid:
            return False, f"Invalid packages: {', '.join(invalid)}"

        if conflict_check:
            conflicts = self.dependency_checker.check_conflicts(env_name, packages)
            if conflicts:
                return False, f"Conflicts detected: {', '.join(conflicts)}"

        command = ['conda', 'install', '-n', env_name, '-y'] + packages
        success, output = self.command_runner.run_secure_command(command, env_name)

        if success:
            self.audit_logger.log_secure_action("packages_installed", env_name, "success")
            return True, f"Packages installed in '{env_name}'"
        else:
            self.audit_logger.log_secure_action("package_installation_failed", env_name, "error")
            return False, f"Error installing packages: {output}"

    def delete_environment(self, env_name: str, create_backup: bool = True, confirmed: bool = False) -> Tuple[bool, str]:
        """Delete environment with optional backup"""
        if not self.validator.validate_env_name(env_name):
            return False, "Invalid environment name"

        not_allowed = self.authorize_operation('delete', env_name, confirmed)
        if not_allowed:
            return False, not_allowed

        if create_backup:
            backup_success, msg = self.backup_manager.create_backup(env_name, "Pre-deletion backup")
            if not backup_success:
                return False, f"Error creating backup: {msg}"

        command = ['conda', 'env', 'remove', '-n', env_name, '-y']
        success, output = self.command_runner.run_secure_command(command, 'delete_environment')

        if success:
            self.audit_logger.log_secure_action("environment_deleted", env_name, "success")
            return True, f"Environment '{env_name}' deleted successfully"
        else:
            self.audit_logger.log_secure_action("environment_deletion_failed", env_name, "error")
            return False, f"Error deleting environment: {output}"

    def get_environment_info(self, env_name: str) -> Dict[str, Any]:
        """Get detailed environment information"""
        return self.dependency_checker.get_environment_info(env_name)

    def update_packages(
        self,
        env_name: str,
        packages: Optional[List[str]] = None,
        confirmed: bool = False,
    ) -> Tuple[bool, str]:
        """Update packages"""
        if not self.validator.validate_env_name(env_name):
            return False, "Invalid environment name"

        not_allowed = self.authorize_operation('modify', env_name, confirmed)
        if not_allowed:
            return False, not_allowed

        if packages:
            valid, invalid = self.validator.validate_package_list(packages)
            if not valid:
                return False, f"Invalid packages: {', '.join(invalid)}"

        command = ['conda', 'update', '-n', env_name, '-y']
        if packages:
            command.extend(packages)
        else:
            command.append('--all')

        success, output = self.command_runner.run_secure_command(command, env_name)

        if success:
            self.audit_logger.log_secure_action("packages_updated", env_name, "success")
            return True, f"Packages updated in '{env_name}'"
        else:
            self.audit_logger.log_secure_action("package_update_failed", env_name, "error")
            return False, f"Error updating packages: {output}"

    def run_security_diagnostics(self) -> Dict[str, Any]:
        """Run security diagnostics"""
        try:
            from .secure_diagnostics import SecureDiagnostics
            diagnostics = SecureDiagnostics(self.config_manager, self.command_runner, audit_logger=self.audit_logger)
            results = diagnostics.run_comprehensive_diagnostics()
            if 'security_profile' not in results:
                results['security_profile'] = self.get_security_info()
            return results
        except Exception as e:
            self.audit_logger.log_secure_action("diagnostics_failed", "security_manager", "error")
            return {'error': str(e), 'overall_security_score': 0}

    def get_audit_trail(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get audit trail records"""
        return self.audit_logger.get_audit_trail(limit)

    def change_security_level(self, new_level: str) -> bool:
        """Change security level"""
        if new_level not in self.config_manager.security_profiles:
            return False

        self.config_manager.set('security.security_level', new_level)
        self.security_profile = self.config_manager.get_security_profile(new_level)

        self.audit_logger.log_secure_action("security_level_changed", "system", "success")
        return True

    def clone_environment(self, source_env: str, target_env: str, confirmed: bool = False) -> Tuple[bool, str]:
        """Clone environment"""
        if not (
            self.validator.validate_existing_env_name(source_env)
            and self.validator.validate_env_name(target_env)
        ):
            return False, "Invalid environment name"

        not_allowed = self.authorize_operation('create', target_env, confirmed)
        if not_allowed:
            return False, not_allowed

        success, envs = self.list_environments()
        if not success or source_env not in envs:
            return False, f"Environment '{source_env}' does not exist"

        command = ['conda', 'create', '--clone', source_env, '-n', target_env, '-y']
        success, output = self.command_runner.run_secure_command(command, 'clone_environment')

        if success:
            self.audit_logger.log_secure_action("environment_cloned", f"{source_env}->{target_env}", "success")
            return True, "Environment cloned successfully"
        else:
            return False, f"Error cloning environment: {output}"

    def export_environment(self, env_name: str, filename: str) -> Tuple[bool, str]:
        """Export environment to a file within the backup directory"""
        if not self.validator.validate_existing_env_name(env_name):
            return False, "Invalid environment name"

        if not self.validator.validate_filename(filename):
            return False, "Invalid filename"

        backup_dir = self.config_manager.get_secure_path('paths.backup_dir')
        export_path = (backup_dir / filename).resolve()
        if not self._is_path_within_backup_dir(export_path):
            return False, "Export path must be inside the configured backup directory"

        command = ['conda', 'env', 'export', '-n', env_name, '-f', str(export_path)]
        success, output = self.command_runner.run_secure_command(command, env_name)

        if success:
            self.audit_logger.log_secure_action("environment_exported", env_name, "success")
            return True, f"Environment exported to {export_path}"
        else:
            return False, f"Error exporting environment: {output}"

    def _is_path_within_backup_dir(self, candidate: Path) -> bool:
        """Return True when candidate resolves inside the configured backup directory."""
        try:
            backup_root = self.config_manager.get_secure_path('paths.backup_dir').resolve()
            candidate.resolve().relative_to(backup_root)
            return True
        except (ValueError, OSError, RuntimeError):
            return False

    def import_environment(
        self,
        import_path: Path,
        env_name: Optional[str] = None,
        confirmed: bool = False,
    ) -> Tuple[bool, str]:
        """Import environment from a file inside the configured backup directory."""
        if not import_path.exists() or not import_path.is_file():
            return False, f"File not found: {import_path}"

        resolved = import_path.resolve()
        if resolved.suffix not in ('.yaml', '.yml'):
            return False, "Import file must be a .yaml or .yml file"

        if not env_name:
            env_name = import_path.stem

        if not self.validator.validate_env_name(env_name):
            return False, "Invalid environment name"

        not_allowed = self.authorize_operation('create', env_name, confirmed)
        if not_allowed:
            return False, not_allowed

        if not self._is_path_within_backup_dir(resolved):
            self.audit_logger.log_secure_action(
                "environment_import_rejected",
                env_name,
                "warning",
                details={"path": str(resolved), "reason": "outside backup directory"},
            )
            return False, "Import file must be located inside the configured backup directory"

        command = ['conda', 'env', 'create', '-n', env_name, '-f', str(resolved)]
        success, output = self.command_runner.run_secure_command(command, 'import_environment')

        if success:
            self.audit_logger.log_secure_action("environment_imported", env_name, "success")
            return True, "Environment imported successfully"
        else:
            return False, f"Error importing environment: {output}"

    def create_backup(self, env_name: str, description: str = "") -> Tuple[bool, str]:
        """Create a verified backup of an environment."""
        return self.backup_manager.create_backup(env_name, description)

    def list_backups(self, env_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """List available backups, optionally filtered by environment name."""
        return self.backup_manager.list_backups(env_name)

    def restore_backup(
        self,
        backup_file: str,
        env_name: Optional[str] = None,
        confirmed: bool = False,
    ) -> Tuple[bool, str]:
        """Restore an environment from a verified backup file."""
        not_allowed = self.authorize_operation('restore', env_name or '', confirmed)
        if not_allowed:
            return False, not_allowed
        return self.backup_manager.restore_backup(backup_file, env_name)

    def set_production_mode(self, enabled: bool) -> bool:
        """Persist and apply the production-mode setting."""
        self.production_mode = bool(enabled)
        self.config_manager.set('core.production_mode', self.production_mode)
        self.audit_logger.log_secure_action(
            "production_mode_changed",
            "system",
            "success",
            details={"enabled": self.production_mode},
        )
        return True

    def get_system_status(self) -> Dict[str, Any]:
        """General system status"""
        success, envs = self.list_environments()
        return {
            'security_profile': self.get_security_info(),
            'environments_count': len(envs) if success else 0,
            'production_mode': self.production_mode,
            'system_health': 'healthy' if success else 'degraded',
            'credentials_active': self.credentials.has_password(),
            'secure_store_locked': self.secure_store.is_locked(),
            'active_sessions': len(self.session_manager.get_active_sessions()),
        }

    def unlock_credentials(self, master_password: str) -> None:
        """Unlock encrypted credential store"""
        self.credentials.set_password(master_password)

    def unlock_secure_store(self, master_password: str) -> None:
        """Unlock encrypted data store"""
        self.secure_store.unlock(master_password)

    def store_credential(self, service: str, username: str, password: str) -> None:
        """Store encrypted credential"""
        self.credentials.store(service, {'username': username, 'password': password})

    def get_credential(self, service: str) -> Optional[Dict[str, str]]:
        """Retrieve decrypted credential"""
        return self.credentials.retrieve(service)

    def store_data(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        """Store encrypted data in persistent store"""
        self.secure_store.put(key, value, ttl_seconds)

    def get_data(self, key: str) -> Optional[Any]:
        """Retrieve decrypted data from persistent store"""
        return self.secure_store.get(key)

    def create_session_token(self, data: Optional[Dict] = None) -> str:
        """Create a session token"""
        session = self.session_manager.create_session(data)
        return session.token

    def validate_session(self, token: str) -> bool:
        """Validate if a session token is still active"""
        return self.session_manager.get_session(token) is not None
