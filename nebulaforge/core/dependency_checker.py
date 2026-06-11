"""
NebulaForge - Secure dependency checker

"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from nebulaforge.utils.command_runner import SecureCommandRunner
from nebulaforge.utils.vulnerability_db import check_package_vulnerabilities as _check_pkg_vulns

from .config_manager import ConfigManager


class SecureDependencyChecker:
    """Dependency checker with security analysis"""

    def __init__(self, config_manager: ConfigManager, command_runner: SecureCommandRunner):
        self.config_manager = config_manager
        self.command_runner = command_runner

    def get_environment_info(self, env_name: str) -> Dict[str, Any]:
        try:
            success, output = self.command_runner.run_secure_command(
                ['conda', 'list', '-n', env_name, '--json'], 'get_environment_info'
            )
            if not success:
                return {'error': f"Could not get info for environment '{env_name}'"}

            packages = json.loads(output)
            return {
                'name': env_name,
                'package_count': len(packages),
                'packages': packages,
                'python_version': self._get_python_version(packages),
                'security_issues': self._check_security_issues(packages)
            }
        except Exception as e:
            return {'error': f"Error analyzing environment: {e}"}

    def check_vulnerabilities(self, env_name: str) -> List[Dict[str, str]]:
        vulnerabilities = []
        try:
            env_info = self.get_environment_info(env_name)
            if 'error' in env_info:
                return [{'package': 'unknown', 'issue': env_info['error']}]

            for pkg in env_info.get('packages', []):
                issues = self._check_package_vulnerabilities(pkg.get('name', ''), pkg.get('version', ''))
                vulnerabilities.extend(issues)
        except Exception as e:
            vulnerabilities.append({'package': 'system', 'issue': f'Error: {e}'})
        return vulnerabilities

    def get_outdated_packages(self, env_name: str) -> List[Dict[str, str]]:
        outdated = []
        try:
            success, output = self.command_runner.run_secure_command(
                ['conda', 'list', '-n', env_name, '--outdated', '--json'],
                'get_outdated_packages'
            )
            if success:
                pkgs = json.loads(output)
                for pkg in pkgs:
                    outdated.append({
                        'package': pkg.get('name', ''),
                        'current_version': pkg.get('version', ''),
                        'latest_version': pkg.get('latest_version', '')
                    })
        except Exception:
            pass
        return outdated

    def _get_python_version(self, packages: List[Dict]) -> str:
        for pkg in packages:
            if pkg.get('name') == 'python':
                return pkg.get('version', 'unknown')
        return 'unknown'

    def _check_security_issues(self, packages: List[Dict]) -> List[Dict]:
        issues = []
        problematic = {
            'pycrypto': ('Deprecated, use cryptography instead', 'high'),
            'urllib3': ('Old versions have known vulnerabilities', 'high'),
            'ssl': ('Obsolete SSL libraries are insecure', 'high'),
            'setuptools': ('Ensure latest version for security fixes', 'medium'),
            'pip': ('Ensure latest version for dependency resolution fixes', 'medium'),
            'openssl': ('Check for known OpenSSL vulnerabilities', 'high'),
        }
        for pkg in packages:
            name = pkg.get('name', '').lower()
            if name in problematic:
                reason, severity = problematic[name]
                issues.append({'package': pkg.get('name'), 'issue': reason, 'severity': severity})
        return issues

    def _check_package_vulnerabilities(self, pkg_name: str, pkg_version: str) -> List[Dict]:
        return _check_pkg_vulns(pkg_name, pkg_version)

    def check_conflicts(self, env_name: str, new_packages: List[str]) -> List[str]:
        conflicts: List[str] = []
        try:
            success, output = self.command_runner.run_secure_command(
                ['conda', 'list', '-n', env_name, '--json'], 'check_conflicts'
            )
            if not success:
                return []

            existing = json.loads(output)
            existing_names = {pkg.get('name') for pkg in existing if pkg.get('name')}

            for pkg_spec in new_packages:
                base_name = pkg_spec.split('=')[0].split('>')[0].split('<')[0].strip()
                if base_name in existing_names:
                    conflicts.append(f"Package '{base_name}' is already installed in '{env_name}'")

            known_incompatible = {
                ('tensorflow', 'tensorflow-gpu'),
                ('pytorch', 'pytorch-cpu'),
                ('opencv-python', 'opencv-python-headless'),
                ('pillow', 'pil'),
                ('numpy', 'numpy-base'),
            }
            for pkg_spec in new_packages:
                base_name = pkg_spec.split('=')[0].split('>')[0].split('<')[0].strip()
                for a, b in known_incompatible:
                    if base_name == a and b in existing_names:
                        conflicts.append(f"Known conflict: '{base_name}' is incompatible with installed '{b}'")
                    if base_name == b and a in existing_names:
                        conflicts.append(f"Known conflict: '{base_name}' is incompatible with installed '{a}'")
        except Exception:
            pass
        return conflicts
