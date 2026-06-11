"""
NebulaForge - Shared service layer between CLI and TUI interfaces
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional

from nebulaforge.core.security_manager import SecurityManager
from nebulaforge.core.security_validator import SecurityValidator


class ServiceResult(NamedTuple):
    success: bool
    message: str
    data: Any = None


class EnvironmentService:
    """Shared service encapsulating all business logic.
    Interfaces (CLI/TUI) only handle input/output and menus."""

    def __init__(self, production_mode: bool = False):
        self.sm = SecurityManager(production_mode=production_mode)
        self.validator = SecurityValidator(
            config_manager=self.sm.config_manager,
            audit_logger=self.sm.audit_logger
        )

    # ── Helpers ─────────────────────────────────────────────

    def validate_env_name(self, name: str) -> bool:
        return self.validator.validate_env_name(name)

    def validate_packages(self, packages: List[str]) -> ServiceResult:
        valid, invalid = self.validator.validate_package_list(packages)
        if not valid:
            return ServiceResult(False, f"Invalid packages: {', '.join(invalid)}", invalid)
        return ServiceResult(True, "")

    def validate_filename(self, name: str) -> bool:
        return self.validator.validate_filename(name)

    def require_confirmation_for(self, operation: str, target: str) -> bool:
        return self.sm.require_confirmation_for(operation, target)

    def get_security_info(self) -> Dict[str, Any]:
        return self.sm.get_security_info()

    # ── Environments ─────────────────────────────────────────

    def list_environments(self) -> ServiceResult:
        success, envs = self.sm.list_environments()
        if not success:
            return ServiceResult(False, "Could not list environments")
        return ServiceResult(True, f"{len(envs)} environments found", envs)

    def create_environment(self, name: str, python_version: str = "3.9",
                           packages: Optional[List[str]] = None) -> ServiceResult:
        if not self.validate_env_name(name):
            return ServiceResult(False, "Invalid environment name")

        pkgs = packages or []
        if pkgs:
            result = self.validate_packages(pkgs)
            if not result.success:
                return result

        success, message = self.sm.create_secure_environment({
            'name': name,
            'python_version': python_version,
            'packages': pkgs,
        })
        return ServiceResult(success, message)

    def get_environment_info(self, env_name: str) -> ServiceResult:
        info = self.sm.get_environment_info(env_name)
        if 'error' in info:
            return ServiceResult(False, info['error'], info)
        return ServiceResult(True, "", info)

    def install_packages(self, env_name: str, packages: List[str]) -> ServiceResult:
        if not self.validate_env_name(env_name):
            return ServiceResult(False, "Invalid environment name")

        result = self.validate_packages(packages)
        if not result.success:
            return result

        success, message = self.sm.install_packages(env_name, packages)
        return ServiceResult(success, message)

    def update_packages(self, env_name: str, packages: Optional[List[str]] = None) -> ServiceResult:
        if not self.validate_env_name(env_name):
            return ServiceResult(False, "Invalid environment name")

        success, message = self.sm.update_packages(env_name, packages)
        return ServiceResult(success, message)

    def list_packages(self, env_name: str) -> ServiceResult:
        info = self.sm.get_environment_info(env_name)
        if 'error' in info:
            return ServiceResult(False, info['error'])
        return ServiceResult(True, "", info.get('packages', []))

    def delete_environment(self, env_name: str, create_backup: bool = True) -> ServiceResult:
        if not self.validate_env_name(env_name):
            return ServiceResult(False, "Invalid environment name")

        success, message = self.sm.delete_environment(env_name, create_backup)
        return ServiceResult(success, message)

    def clone_environment(self, source: str, target: str) -> ServiceResult:
        if not self.validate_env_name(source) or not self.validate_env_name(target):
            return ServiceResult(False, "Invalid environment name")

        success, message = self.sm.clone_environment(source, target)
        return ServiceResult(success, message)

    def export_environment(self, env_name: str, filename: str) -> ServiceResult:
        if not self.validate_env_name(env_name):
            return ServiceResult(False, "Invalid environment name")

        if not self.validate_filename(filename):
            return ServiceResult(False, "Invalid filename")

        success, message = self.sm.export_environment(env_name, filename)
        return ServiceResult(success, message)

    def import_environment(self, filepath: Path, env_name: Optional[str] = None) -> ServiceResult:
        if not filepath.exists() or not filepath.is_file():
            return ServiceResult(False, f"File not found: {filepath}")

        success, message = self.sm.import_environment(filepath, env_name)
        return ServiceResult(success, message)

    # ── Diagnostics and auditing ─────────────────────────────

    def run_diagnostics(self) -> ServiceResult:
        try:
            diagnostics = self.sm.run_security_diagnostics()
            return ServiceResult('error' not in diagnostics, "", diagnostics)
        except Exception as e:
            return ServiceResult(False, str(e), {'overall_security_score': 0})

    def get_audit_trail(self, limit: int = 10) -> ServiceResult:
        trail = self.sm.get_audit_trail(limit)
        return ServiceResult(True, f"{len(trail)} entries", trail)

    # ── Configuration ────────────────────────────────────────

    def get_available_profiles(self) -> List[str]:
        return list(self.sm.config_manager.security_profiles.keys())

    def change_security_level(self, level: str) -> ServiceResult:
        if level not in self.sm.config_manager.security_profiles:
            return ServiceResult(False, f"Unknown profile: {level}")
        success = self.sm.change_security_level(level)
        return ServiceResult(success, f"Security level changed to: {level}")

    # ── Vulnerabilities ──────────────────────────────────────

    def check_vulnerabilities(self, env_name: str) -> ServiceResult:
        if not self.validate_env_name(env_name):
            return ServiceResult(False, "Invalid environment name")
        vulns = self.sm.dependency_checker.check_vulnerabilities(env_name)
        return ServiceResult(True, f"{len(vulns)} vulnerabilities found", vulns)

    def get_outdated_packages(self, env_name: str) -> ServiceResult:
        if not self.validate_env_name(env_name):
            return ServiceResult(False, "Invalid environment name")
        outdated = self.sm.dependency_checker.get_outdated_packages(env_name)
        return ServiceResult(True, f"{len(outdated)} outdated packages", outdated)

    # ── Credentials and security ─────────────────────────────

    def get_system_status(self) -> Dict[str, Any]:
        return self.sm.get_system_status()

    def unlock_credentials(self, master_password: str) -> None:
        self.sm.unlock_credentials(master_password)

    def unlock_secure_store(self, master_password: str) -> None:
        self.sm.unlock_secure_store(master_password)

    def store_credential(self, service: str, username: str, password: str) -> None:
        self.sm.store_credential(service, username, password)

    def get_credential(self, service: str) -> Optional[Dict[str, str]]:
        return self.sm.get_credential(service)

    def get_current_profile_name(self) -> str:
        return getattr(self.sm.security_profile, 'name', 'Unknown')
