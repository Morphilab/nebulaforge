"""
NebulaForge - Comprehensive security diagnostics

"""

import json
import os
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

from nebulaforge.utils.command_runner import SecureCommandRunner

from .audit_logger import AuditLogger
from .config_manager import ConfigManager
from .dependency_checker import SecureDependencyChecker


class SecureDiagnostics:
    """Comprehensive diagnostics system for NebulaForge"""

    def __init__(
        self,
        config_manager: ConfigManager,
        command_runner: SecureCommandRunner,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.config_manager = config_manager
        self.command_runner = command_runner
        self.audit_logger = audit_logger or AuditLogger(config_manager)
        self.dependency_checker = SecureDependencyChecker(config_manager, command_runner)

    def run_comprehensive_diagnostics(self) -> Dict[str, Any]:
        """Run complete system diagnostics"""
        try:
            diagnostics: Dict[str, Any] = {
                'system_health': self._check_system_health(),
                'security_status': self._check_security_status(),
                'environment_audit': self._audit_all_environments(),
                'configuration_validation': self._validate_configuration()
            }

            overall_score = self._calculate_security_score(diagnostics)
            diagnostics['overall_security_score'] = overall_score

            if overall_score >= 90:
                overall_status = 'excellent'
            elif overall_score >= 70:
                overall_status = 'good'
            elif overall_score >= 50:
                overall_status = 'fair'
            else:
                overall_status = 'poor'

            diagnostics['overall_status'] = overall_status
            diagnostics['recommendations'] = self._generate_recommendations(diagnostics)

            self.audit_logger.log_secure_action(
                action="comprehensive_diagnostics",
                target="system",
                status="success"
            )

            return diagnostics

        except Exception as e:
            self.audit_logger.log_secure_action(
                action="comprehensive_diagnostics_error",
                target="secure_diagnostics",
                status="error",
                details={"error": str(e)}
            )
            return {
                'error': f"Error in comprehensive diagnostics: {str(e)}",
                'overall_security_score': 0,
                'overall_status': 'error',
                'recommendations': ['Review system configuration']
            }

    def _check_system_health(self) -> Dict[str, Any]:
        """Check general system health"""
        health_checks: Dict[str, Any] = {}

        try:
            home_dir = Path.home()
            disk = shutil.disk_usage(home_dir)
            health_checks['disk_space'] = {
                'status': 'healthy' if disk.free > 2 * 1024**3 else 'warning',
                'free_gb': round(disk.free / 1024**3, 2),
                'total_gb': round(disk.total / 1024**3, 2)
            }
        except Exception as e:
            health_checks['disk_space'] = {'status': 'error', 'error': str(e)}

        try:
            import psutil
            mem = psutil.virtual_memory()
            health_checks['memory'] = {
                'status': 'healthy' if mem.available > 1 * 1024**3 else 'warning',
                'available_gb': round(mem.available / 1024**3, 2),
                'percent_used': mem.percent
            }
        except ImportError:
            health_checks['memory'] = {'status': 'unknown', 'note': 'psutil not available'}

        health_checks['conda'] = self._check_conda_availability()

        health_checks['directory_permissions'] = self._check_critical_directories()

        return health_checks

    def _check_security_status(self) -> Dict[str, Any]:
        """Security configuration status"""
        security_status = {}

        try:
            profile = self.config_manager.get_security_profile()
            security_status['security_profile'] = {
                'current': profile.name,
                'level': profile.level
            }
        except Exception:
            security_status['security_profile'] = {'current': 'Error', 'level': 'unknown'}

        security_status['audit_config'] = {
            'enabled': self.config_manager.get('audit.enable_audit', True)
        }
        security_status['backup_config'] = {
            'enabled': self.config_manager.get('security.enable_backup', True)
        }
        security_status['production_mode'] = self.config_manager.get('core.production_mode', False)

        return security_status

    def _audit_all_environments(self) -> Dict[str, Any]:
        """Audit all existing environments in parallel"""
        try:
            success, output = self.command_runner.run_secure_command(
                ['conda', 'env', 'list', '--json'], 'audit_environments'
            )
            if not success:
                return {'error': 'Could not get environment list'}

            env_data = json.loads(output)
            environments = [Path(p).name for p in env_data.get('envs', [])]

            audit_results = {}
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {
                    executor.submit(self._audit_single_environment, name): name
                    for name in environments
                }
                for future in as_completed(futures):
                    name = futures[future]
                    try:
                        audit_results[name] = future.result()
                    except Exception as ex:
                        audit_results[name] = {'error': str(ex)}

            return audit_results

        except Exception as e:
            return {'error': f'Error auditing environments: {e}'}

    def _audit_single_environment(self, env_name: str) -> Dict[str, Any]:
        """Single environment audit"""
        audit_result = {
            'package_count': 0,
            'python_version': 'unknown',
            'outdated_packages': [],
            'vulnerabilities': []
        }

        try:
            env_info = self.dependency_checker.get_environment_info(env_name)
            if 'error' not in env_info:
                audit_result['package_count'] = env_info.get('package_count', 0)
                audit_result['python_version'] = env_info.get('python_version', 'unknown')
                audit_result['outdated_packages'] = self.dependency_checker.get_outdated_packages(env_name)
                audit_result['vulnerabilities'] = env_info.get('security_issues', [])
        except Exception:
            pass

        return audit_result

    def _validate_configuration(self) -> Dict[str, Any]:
        """Validate current configuration"""
        validation_results = {
            'security_settings': {
                'production_mode': self.config_manager.get('core.production_mode', False),
                'default_profile': self.config_manager.get('security.security_level', 'medium')
            }
        }
        return validation_results

    def _check_conda_availability(self) -> Dict[str, Any]:
        """Check conda availability"""
        try:
            success, output = self.command_runner.run_secure_command(
                ['conda', '--version'], 'check_conda'
            )
            if success:
                return {'status': 'healthy', 'version': output.strip(), 'available': True}
            return {'status': 'unhealthy', 'available': False}
        except Exception as e:
            return {'status': 'error', 'available': False, 'error': str(e)}

    def _check_critical_directories(self) -> List[Dict[str, Any]]:
        """Check critical directory permissions"""
        critical_dirs = [
            Path(self.config_manager.get('paths.log_dir', '~/.nebulaforge/logs')).expanduser(),
            Path(self.config_manager.get('paths.backup_dir', '~/.nebulaforge/backups')).expanduser(),
            Path.home() / '.nebulaforge'
        ]

        results = []
        for directory in critical_dirs:
            try:
                exists = directory.exists()
                writable = os.access(directory, os.W_OK) if exists else False
                st = directory.stat()
                results.append({
                    'directory': str(directory),
                    'exists': exists,
                    'writable': writable,
                    'secure': (st.st_mode & 0o077) == 0
                })
            except Exception:
                results.append({'directory': str(directory), 'exists': False, 'secure': False})
        return results

    def _calculate_security_score(self, diagnostics: Dict[str, Any]) -> int:
        """Calculate overall security score"""
        score = 100
        try:
            health = diagnostics.get('system_health', {})
            if health.get('disk_space', {}).get('status') == 'warning':
                score -= 10
            if health.get('conda', {}).get('status') != 'healthy':
                score -= 20

            security = diagnostics.get('security_status', {})
            if not security.get('audit_config', {}).get('enabled', True):
                score -= 15

            profile_level = security.get('security_profile', {}).get('level', 'medium')
            if profile_level == 'low':
                score -= 15
            elif profile_level == 'high':
                score += 10
            elif profile_level == 'paranoid':
                score += 15

        except Exception:
            score = 70

        return max(0, min(score, 100))

    def _generate_recommendations(self, diagnostics: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on diagnostics"""
        recommendations = []
        health = diagnostics.get('system_health', {})

        if health.get('disk_space', {}).get('status') == 'warning':
            recommendations.append("Low disk space. Free up space before creating large environments.")

        if health.get('conda', {}).get('status') != 'healthy':
            recommendations.append("Conda is not available or has issues. Verify installation.")

        security = diagnostics.get('security_status', {})
        if security.get('security_profile', {}).get('level') == 'low':
            recommendations.append("Low security profile. Consider changing to 'medium' or higher.")

        return recommendations
