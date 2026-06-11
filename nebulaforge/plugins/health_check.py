"""
NebulaForge - Health check plugin
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from nebulaforge.utils.command_runner import SecureCommandRunner

from .base_plugin import BasePlugin


class HealthCheckPlugin(BasePlugin):
    """Plugin for Conda environment health checks"""

    def __init__(self, config_manager, audit_logger, command_runner: SecureCommandRunner):
        super().__init__(config_manager, audit_logger, command_runner=command_runner)

    def get_name(self) -> str:
        return "health_check"

    def get_description(self) -> str:
        return "Health and status check for Conda environments"

    def get_commands(self) -> Dict[str, str]:
        return {
            'check_health': 'Check complete environment health',
            'check_dependencies': 'Check dependencies and conflicts',
            'check_performance': 'Check performance and size'
        }

    def execute(self, command: str, **kwargs) -> Dict[str, Any]:
        """Execute plugin command"""
        if command == 'check_health':
            return self.check_health(**kwargs)
        elif command == 'check_dependencies':
            return self.check_dependencies(**kwargs)
        elif command == 'check_performance':
            return self.check_performance(**kwargs)
        else:
            return {'error': f'Unknown command: {command}'}

    def check_health(self, env_name: str) -> Dict[str, Any]:
        """Complete environment health check"""
        health_info: Dict[str, Any] = {
            'environment': env_name,
            'status': 'unknown',
            'checks': {},
            'issues': []
        }

        try:
            # Verify the environment exists
            if not self.validate_environment(env_name):
                health_info['status'] = 'error'
                health_info['issues'].append('Environment not found or inaccessible')
                return health_info

            # Run checks
            health_info['checks']['packages'] = self._check_packages(env_name)
            health_info['checks']['dependencies'] = self._check_dependencies(env_name)
            health_info['checks']['permissions'] = self._check_permissions(env_name)

            # Determine overall status
            if any(check.get('status') == 'error' for check in health_info['checks'].values()):
                health_info['status'] = 'error'
            elif any(check.get('status') == 'warning' for check in health_info['checks'].values()):
                health_info['status'] = 'warning'
            else:
                health_info['status'] = 'healthy'

            self.log_plugin_action('health_check', {'environment': env_name, 'status': health_info['status']})

        except Exception as e:
            health_info['status'] = 'error'
            health_info['issues'].append(f'Verification error: {str(e)}')

        return health_info

    def check_dependencies(self, env_name: str) -> Dict[str, Any]:  # type: ignore[override]
        """Verify dependencies and conflicts"""
        deps_info: Dict[str, Any] = {
            'environment': env_name,
            'conflicts': [],
            'missing_deps': [],
            'circular_deps': []
        }

        try:
            success, output = self.command_runner.run_secure_command(  # type: ignore[union-attr]
                ['conda', 'list', '-n', env_name, '--json'], 'check_dependencies'
            )

            if success:
                packages = json.loads(output)
                package_names = [pkg['name'] for pkg in packages]

                # Detect duplicates
                duplicates = {name for name in package_names if package_names.count(name) > 1}
                if duplicates:
                    deps_info['conflicts'].append(f'Duplicate packages: {", ".join(duplicates)}')

                # Known conflicts
                known_conflicts = self._check_known_conflicts(packages)
                deps_info['conflicts'].extend(known_conflicts)

            self.log_plugin_action('dependency_check', {'environment': env_name, 'issues': len(deps_info['conflicts'])})

        except Exception as e:
            deps_info['conflicts'].append(f'Error checking dependencies: {str(e)}')

        return deps_info

    def check_performance(self, env_name: str) -> Dict[str, Any]:
        """Verify environment performance"""
        perf_info: Dict[str, Any] = {
            'environment': env_name,
            'metrics': {},
            'recommendations': []
        }

        try:
            size_check = self._check_environment_size(env_name)
            perf_info['metrics']['size_mb'] = size_check.get('size_mb', 0)

            if size_check.get('size_mb', 0) > 1000:
                perf_info['recommendations'].append('Environment is too large. Consider cleaning unused packages.')

            load_time = self._check_load_time(env_name)
            perf_info['metrics']['load_time_ms'] = load_time

            if load_time > 5000:
                perf_info['recommendations'].append('High load time. Optimize the environment.')

            heavy_packages = self._find_heavy_packages(env_name)
            if heavy_packages:
                perf_info['metrics']['heavy_packages'] = heavy_packages
                perf_info['recommendations'].append(f'Heavy packages detected: {", ".join(heavy_packages)}')

            self.log_plugin_action('performance_check', {'environment': env_name, 'metrics': perf_info['metrics']})

        except Exception as e:
            perf_info['recommendations'].append(f'Performance check error: {str(e)}')

        return perf_info

    # ======================== HELPER METHODS ========================

    def _check_packages(self, env_name: str) -> Dict[str, Any]:
        check_result: Dict[str, Any] = {'status': 'unknown', 'total_packages': 0, 'broken_packages': 0, 'details': []}

        try:
            success, output = self.command_runner.run_secure_command(  # type: ignore[union-attr]
                ['conda', 'list', '-n', env_name, '--json'], 'check_packages'
            )

            if success:
                packages = json.loads(output)
                check_result['total_packages'] = len(packages)

                broken = [
                    pkg.get('name', 'unknown') for pkg in packages
                    if not pkg.get('name') or not pkg.get('version')
                ]
                check_result['broken_packages'] = len(broken)
                check_result['details'] = broken

                check_result['status'] = 'warning' if broken else 'healthy'
            else:
                check_result['status'] = 'error'

        except Exception as e:
            check_result['status'] = 'error'
            check_result['details'].append(f'Error: {str(e)}')

        return check_result

    def _check_dependencies(self, env_name: str) -> Dict[str, Any]:
        check_result: Dict[str, Any] = {'status': 'unknown', 'dependency_issues': []}

        try:
            success, output = self.command_runner.run_secure_command(  # type: ignore[union-attr]
                ['conda', 'list', '-n', env_name, '--json'], 'check_dependencies'
            )
            if success:
                packages = json.loads(output)
                dep_issues = self._scan_for_broken_packages(packages)
                if dep_issues:
                    check_result['status'] = 'warning'
                    check_result['dependency_issues'] = dep_issues
                else:
                    check_result['status'] = 'healthy'
            else:
                check_result['status'] = 'error'
                check_result['dependency_issues'].append('Could not retrieve package list')
        except Exception as e:
            check_result['status'] = 'error'
            check_result['dependency_issues'].append(f'Error: {str(e)}')

        return check_result

    def _scan_for_broken_packages(self, packages: List[Dict]) -> List[str]:
        issues: List[str] = []
        for pkg in packages:
            if not pkg.get('name') or not pkg.get('version'):
                issues.append(f"Broken package: {pkg.get('name', 'unknown')}")
            if pkg.get('name', '').startswith('_'):
                issues.append(f"Internal/private package: {pkg.get('name')}")
        return issues

    def _check_permissions(self, env_name: str) -> Dict[str, Any]:
        check_result: Dict[str, Any] = {'status': 'unknown', 'permission_issues': []}

        try:
            success, output = self.command_runner.run_secure_command(  # type: ignore[union-attr]
                ['conda', 'info', '--json'], 'check_permissions'
            )

            if success:
                conda_info = json.loads(output)
                for env_dir in conda_info.get('envs_dirs', []):
                    env_path = Path(env_dir).expanduser() / env_name
                    if env_path.exists():
                        if not self._check_directory_permissions(env_path):
                            check_result['permission_issues'].append(f'Insecure permissions on: {env_path}')
                            check_result['status'] = 'warning'
                        else:
                            check_result['status'] = 'healthy'
                        break
                else:
                    check_result['status'] = 'error'
        except Exception as e:
            check_result['status'] = 'error'
            check_result['permission_issues'].append(f'Error: {str(e)}')

        return check_result

    def _check_environment_size(self, env_name: str) -> Dict[str, Any]:
        try:
            success, output = self.command_runner.run_secure_command(  # type: ignore[union-attr]
                ['conda', 'info', '--json'], 'check_environment_size'
            )
            if success:
                conda_info = json.loads(output)
                for env_dir in conda_info.get('envs_dirs', []):
                    env_path = Path(env_dir).expanduser() / env_name
                    if env_path.exists():
                        total_size = sum(
                            f.stat().st_size for f in env_path.rglob('*')
                            if f.is_file() and not f.is_symlink()
                        )
                        return {'size_mb': round(total_size / (1024 * 1024), 2)}
            return {'size_mb': 0}
        except Exception:
            return {'size_mb': 0}

    def _check_load_time(self, env_name: str) -> float:
        try:
            import time
            start = time.time()
            self.command_runner.run_secure_command(  # type: ignore[union-attr]
                ['conda', 'list', '-n', env_name, '--json'], 'check_load_time'
            )
            return round((time.time() - start) * 1000, 2)
        except Exception:
            return 0.0

    def _find_heavy_packages(self, env_name: str) -> List[str]:
        heavy = []
        try:
            success, output = self.command_runner.run_secure_command(  # type: ignore[union-attr]
                ['conda', 'list', '-n', env_name, '--json'], 'find_heavy_packages'
            )
            if success:
                packages = json.loads(output)
                known_heavy = ['tensorflow', 'pytorch', 'opencv', 'nvidia', 'cudatoolkit']
                heavy = [pkg['name'] for pkg in packages if any(h in pkg['name'].lower() for h in known_heavy)]
        except Exception:
            pass
        return heavy

    def _check_known_conflicts(self, packages: List[Dict]) -> List[str]:
        conflicts = []
        known_conflicts = [('tensorflow', 'tensorflow-gpu'), ('opencv', 'opencv-python'), ('pillow', 'pil')]
        package_names = [pkg['name'] for pkg in packages]

        for p1, p2 in known_conflicts:
            if p1 in package_names and p2 in package_names:
                conflicts.append(f'Known conflict: {p1} and {p2}')
        return conflicts

    def _check_directory_permissions(self, directory: Path) -> bool:
        try:
            stat = directory.stat()
            return (stat.st_mode & 0o022) == 0  # Solo propietario puede escribir
        except Exception:
            return False
