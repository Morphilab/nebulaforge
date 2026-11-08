"""
NebulaForge - Secure backup manager
"""

import hashlib
import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from nebulaforge.utils.command_runner import SecureCommandRunner

from .audit_logger import AuditLogger
from .config_manager import ConfigManager
from .security_validator import SecurityValidator

_ENV_INFO_CACHE_TTL = timedelta(seconds=60)


class BackupManager:
    """Backup manager with integrity verification for NebulaForge"""

    def __init__(
        self,
        config_manager: ConfigManager,
        command_runner: SecureCommandRunner,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.config_manager = config_manager
        self.audit_logger = audit_logger or AuditLogger(config_manager)
        self.command_runner = command_runner
        self.backup_dir = Path(config_manager.get('paths.backup_dir', '~/.nebulaforge/backups')).expanduser()
        self._ensure_backup_dir()
        self.validator = SecurityValidator(config_manager=config_manager)
        self._env_info_cache: Dict[str, Tuple[datetime, Optional[Dict[str, Any]]]] = {}

    def _ensure_backup_dir(self) -> None:
        """Ensure backup directory exists with secure permissions"""
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.chmod(0o700)

    def create_backup(self, env_name: str, description: str = "") -> Tuple[bool, str]:
        """Create environment backup with integrity checksum"""
        if not self.validator.validate_existing_env_name(env_name):
            return False, "Invalid environment name"
        try:
            success, environments = self._list_environments()
            if not success or env_name not in environments:
                return False, f"Environment '{env_name}' not found"
            env_info = self._get_environment_info(env_name)
            if not env_info:
                return False, f"Could not get environment info for '{env_name}'"

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_filename = f"backup_{env_name}_{timestamp}.yaml"
            backup_path = self.backup_dir / backup_filename

            backup_data = {
                'name': env_name,
                'timestamp': timestamp,
                'description': description,
                'channels': env_info.get('channels', []),
                'dependencies': env_info.get('dependencies', []),
                'metadata': {
                    'python_version': env_info.get('python_version', 'unknown'),
                    'package_count': len(env_info.get('dependencies', [])),
                    'created_by': 'nebulaforge_v1'
                }
            }

            with open(backup_path, 'w', encoding='utf-8') as f:
                yaml.dump(backup_data, f, default_flow_style=False, indent=2)

            # SHA-256 checksum of file on disk
            checksum = self._calculate_checksum(backup_path)
            checksum_path = backup_path.with_suffix('.yaml.sha256')
            with open(checksum_path, 'w', encoding='utf-8') as f:
                f.write(f"{checksum}  {backup_filename}\n")
            checksum_path.chmod(0o600)

            backup_path.chmod(0o600)

            self.audit_logger.log_secure_action(
                action="backup_created",
                target=env_name,
                status="success",
                details={"filename": backup_filename}
            )

            self._cleanup_old_backups()

            return True, f"Backup created successfully: {backup_filename}"

        except Exception as e:
            self.audit_logger.log_secure_action("backup_error", env_name, "error", {"error": str(e)})
            return False, f"Error creating backup: {str(e)}"

    def _resolve_safe_backup_path(self, backup_file: str) -> Optional[Path]:
        """Resolve backup_file and ensure it stays within the configured backup_dir.

        This prevents arbitrary file reads by restricting restores to files that
        live under the user's backup directory. Symlink resolution is also applied
        to avoid path-traversal attacks via symlinked parents.
        """
        try:
            candidate = Path(backup_file).expanduser()
            if not candidate.is_absolute():
                candidate = (self.backup_dir / candidate).resolve()
            else:
                candidate = candidate.resolve()

            backup_root = self.backup_dir.resolve()
            try:
                candidate.relative_to(backup_root)
            except ValueError:
                return None
            return candidate
        except Exception:
            return None

    def _is_protected_env(self, env_name: str) -> bool:
        """Return True when the active profile protects the given environment."""
        try:
            profile = self.config_manager.get_security_profile()
            protected = getattr(profile, 'protected_envs', None) or []
            return env_name in protected
        except Exception:
            return False

    def _unique_env_name(self, prefix: str, existing: List[str]) -> str:
        """Return a temporary environment name that does not collide."""
        for _ in range(10):
            candidate = f"{prefix}{uuid.uuid4().hex[:8]}"
            if candidate not in existing:
                return candidate
        raise RuntimeError("Could not generate a unique temporary environment name")

    def _remove_environment(self, env_name: str) -> Tuple[bool, str]:
        """Remove an environment as part of restore cleanup."""
        return self.command_runner.run_secure_command(
            ['conda', 'env', 'remove', '-n', env_name, '-y'],
            'cleanup_restore_environment',
        )

    def _rename_environment(self, source: str, destination: str) -> Tuple[bool, str]:
        """Rename an environment using conda's rename command."""
        return self.command_runner.run_secure_command(
            ['conda', 'rename', '-n', source, destination],
            'rename_environment',
        )

    def restore_backup(self, backup_file: str, env_name: Optional[str] = None) -> Tuple[bool, str]:
        """Restore an environment from a backup without destroying a live target.

        The restored environment is first materialized under a temporary name.
        When a target already exists, the old environment is renamed aside
        before the new one is moved into place. Any failure rolls the original
        environment back (or preserves it under a quarantine name if rollback
        itself fails), so the restore never silently deletes the target.
        """
        try:
            backup_path = self._resolve_safe_backup_path(backup_file)
            if backup_path is None:
                return False, "Backup path must be located inside the configured backup directory"
            if not backup_path.exists():
                return False, f"Backup file not found: {backup_file}"

            with open(backup_path, encoding='utf-8') as f:
                backup_data = yaml.safe_load(f)

            if not isinstance(backup_data, dict):
                return False, "Invalid backup file: expected a YAML mapping"

            # Verify integrity against separate .sha256 file
            checksum_path = backup_path.with_suffix('.yaml.sha256')
            if not self._verify_checksum(backup_path, checksum_path):
                return False, "Invalid checksum - backup is corrupt or has been modified"

            if not env_name:
                env_name = backup_data.get('name')

            if not env_name:
                return False, "Could not determine environment name"

            if not self.validator.validate_env_name(env_name):
                return False, "Invalid environment name in backup"

            if self._is_protected_env(env_name):
                return False, f"Environment '{env_name}' is protected and cannot be restored"

            listed, environments = self._list_environments()
            if not listed:
                return False, "Could not list environments; refusing to modify existing environments"

            target_exists = env_name in environments
            temp_name = self._unique_env_name("nf_restore_", environments)
            quarantine_name = (
                self._unique_env_name("nf_quarantine_", environments + [temp_name])
                if target_exists else None
            )

            temp_env_file = self.backup_dir / f"temp_restore_{uuid.uuid4().hex}.yaml"
            temp_data = {
                'name': temp_name,
                'channels': backup_data.get('channels', []),
                'dependencies': backup_data.get('dependencies', [])
            }

            try:
                with open(temp_env_file, 'w', encoding='utf-8') as f:
                    yaml.dump(temp_data, f, default_flow_style=False)
                temp_env_file.chmod(0o600)

                create_ok, create_output = self.command_runner.run_secure_command(
                    ['conda', 'env', 'create', '-n', temp_name, '-f', str(temp_env_file)],
                    'restore_backup',
                )
                if not create_ok:
                    self._remove_environment(temp_name)
                    return False, f"Error creating temporary restore environment: {create_output}"

                if target_exists:
                    assert quarantine_name is not None
                    backup_ok, backup_msg = self.create_backup(
                        env_name, f"Pre-restore backup for {backup_path.name}"
                    )
                    if not backup_ok:
                        self.audit_logger.log_system_event(
                            "pre_restore_backup_failed",
                            f"Could not create pre-restore backup for '{env_name}': {backup_msg}"
                        )

                    rename_ok, rename_output = self._rename_environment(env_name, quarantine_name)
                    if not rename_ok:
                        self._remove_environment(temp_name)
                        return False, (
                            "Could not move the existing environment aside; "
                            f"it was left untouched: {rename_output}"
                        )

                rename_ok, rename_output = self._rename_environment(temp_name, env_name)
                if not rename_ok:
                    rollback_message = "No existing environment needed rollback."
                    if quarantine_name:
                        rollback_ok, rollback_output = self._rename_environment(quarantine_name, env_name)
                        if rollback_ok:
                            rollback_message = "The original environment was restored."
                        else:
                            rollback_message = (
                                f"The original environment is preserved as '{quarantine_name}' "
                                f"because rollback failed: {rollback_output}"
                            )
                    self._remove_environment(temp_name)
                    return False, f"Error finalizing restore: {rename_output}. {rollback_message}"

                cleanup_note = ""
                if quarantine_name:
                    cleanup_ok, cleanup_output = self._remove_environment(quarantine_name)
                    if not cleanup_ok:
                        cleanup_note = (
                            f" Old environment left as '{quarantine_name}' "
                            f"because cleanup failed: {cleanup_output}"
                        )
                        self.audit_logger.log_secure_action(
                            "restore_quarantine_cleanup_failed",
                            quarantine_name,
                            "warning",
                            details={"error": cleanup_output},
                        )

                self._env_info_cache.pop(env_name, None)
                self.audit_logger.log_secure_action("backup_restored", env_name, "success")
                return True, f"Environment '{env_name}' restored successfully from backup.{cleanup_note}"

            finally:
                temp_env_file.unlink(missing_ok=True)

        except Exception as e:
            self.audit_logger.log_secure_action("restore_error", env_name or "unknown", "error")
            return False, f"Error restoring backup: {str(e)}"

    def list_backups(self, env_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """List available backups"""
        backups = []
        try:
            for backup_file in self.backup_dir.glob("backup_*.yaml"):
                backup_info = self.get_backup_info(backup_file)
                if 'error' not in backup_info:
                    if env_name is None or backup_info.get('env_name') == env_name:
                        backups.append(backup_info)

            # Sort by date (most recent first)
            backups.sort(key=lambda x: x.get('created_time', ''), reverse=True)
        except Exception:
            pass
        return backups

    def get_backup_info(self, backup_file: Path) -> Dict[str, Any]:
        """Get backup information"""
        if not backup_file.exists():
            return {"error": "File not found"}

        try:
            with open(backup_file, encoding='utf-8') as f:
                data = yaml.safe_load(f)

            return {
                "env_name": data.get("name", "Unknown"),
                "channels": data.get("channels", []),
                "dependencies_count": len(data.get("dependencies", [])),
                "file_size": backup_file.stat().st_size,
                "created_time": datetime.fromtimestamp(backup_file.stat().st_mtime).isoformat(),
                "description": data.get("description", ""),
                "python_version": data.get("metadata", {}).get("python_version", "unknown")
            }
        except Exception as e:
            return {"error": f"Could not read backup: {str(e)}"}

    def _list_environments(self) -> Tuple[bool, List[str]]:
        """List available environments"""
        try:
            success, output = self.command_runner.run_secure_command(
                ['conda', 'env', 'list', '--json'], 'list_environments'
            )
            if not success:
                return False, []
            data = json.loads(output)
            envs = [Path(p).name for p in data.get('envs', [])]
            return True, envs
        except Exception:
            return False, []

    def _get_environment_info(self, env_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed environment information (cached with TTL)"""
        cached_time, cached_result = self._env_info_cache.get(env_name, (datetime.min, None))
        if cached_result is not None and datetime.now() - cached_time < _ENV_INFO_CACHE_TTL:
            return cached_result

        try:
            env_info = self._fetch_environment_info(env_name)
            self._env_info_cache[env_name] = (datetime.now(), env_info)
            return env_info
        except Exception:
            self._env_info_cache[env_name] = (datetime.now(), None)
            return None

    def _fetch_environment_info(self, env_name: str) -> Optional[Dict[str, Any]]:
        """Fetch environment info from conda"""
        try:
            # Use conda env export to get channels and packages in one command
            success, output = self.command_runner.run_secure_command(
                ['conda', 'env', 'export', '-n', env_name, '--json'], 'get_environment_info'
            )
            if success:
                export_data = json.loads(output)
                if isinstance(export_data, dict):
                    channels = export_data.get('channels', [])
                    dependencies = []

                    for dep in export_data.get('dependencies', []):
                        if isinstance(dep, str):
                            name, _, version = dep.partition('=')
                            dependencies.append({
                                'name': name,
                                'version': version,
                                'channel': ''
                            })
                        elif isinstance(dep, dict):
                            dependencies.append({'name': list(dep.keys())[0], 'version': '', 'channel': ''})

                    python_version = 'unknown'
                    for dep in export_data.get('dependencies', []):
                        if isinstance(dep, str) and dep.startswith('python='):
                            python_version = dep.split('=')[1]
                            break

                    return {
                        'channels': channels,
                        'dependencies': dependencies,
                        'python_version': python_version
                    }

            # Fallback: use conda list
            success, output = self.command_runner.run_secure_command(
                ['conda', 'list', '-n', env_name, '--json'], 'get_environment_info'
            )
            if not success:
                return None

            packages = json.loads(output)
            python_version = 'unknown'
            for pkg in packages:
                if pkg.get('name') == 'python':
                    python_version = pkg.get('version', 'unknown')
                    break

            return {
                'channels': [],
                'dependencies': packages,
                'python_version': python_version
            }
        except Exception:
            return None

    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA-256 checksum of file on disk"""
        return hashlib.sha256(file_path.read_bytes()).hexdigest()

    def _verify_checksum(self, backup_path: Path, checksum_path: Path) -> bool:
        """Verify file checksum against separate .sha256 file"""
        try:
            if not checksum_path.exists():
                return False
            stored = checksum_path.read_text(encoding='utf-8').strip()
            expected_checksum = stored.split()[0]
            calculated = self._calculate_checksum(backup_path)
            return expected_checksum == calculated
        except Exception:
            return False

    def _cleanup_old_backups(self) -> None:
        """Clean up old backups per retention policy and orphaned checksum files"""
        try:
            retention_days = self.config_manager.get('security.backup_retention_days', 30)
            cutoff_date = datetime.now() - timedelta(days=retention_days)

            for backup_file in self.backup_dir.glob("backup_*.yaml"):
                if datetime.fromtimestamp(backup_file.stat().st_mtime) < cutoff_date:
                    checksum_file = backup_file.with_suffix('.yaml.sha256')
                    backup_file.unlink()
                    if checksum_file.exists():
                        checksum_file.unlink()

            for sha_file in self.backup_dir.glob("backup_*.yaml.sha256"):
                yaml_file = sha_file.with_suffix('').with_suffix('.yaml')
                if not yaml_file.exists():
                    sha_file.unlink()
        except Exception:
            pass
