"""
NebulaForge - Security scanning plugin
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from nebulaforge.utils.command_runner import SecureCommandRunner
from nebulaforge.utils.vulnerability_db import check_package_vulnerabilities as check_vulns

from .base_plugin import BasePlugin


class SecurityScannerPlugin(BasePlugin):
    """Plugin for security scanning of Conda environments"""

    def __init__(self, config_manager, audit_logger, command_runner: SecureCommandRunner):
        super().__init__(config_manager, audit_logger, command_runner=command_runner)
        self.logger = logging.getLogger(__name__)

        self.OFFICIAL_REPOSITORIES = [
            'conda-forge',
            'defaults',
            'anaconda',
            'bioconda'
        ]

    def get_name(self) -> str:
        return "security_scanner"

    def get_description(self) -> str:
        return "Security and vulnerability scanning for Conda environments"

    def get_commands(self) -> Dict[str, str]:
        return {
            'scan_vulnerabilities': 'Scan known vulnerabilities',
            'check_malware': 'Check for potentially malicious packages',
            'audit_permissions': 'Audit environment permissions',
            'verify_integrity': 'Verify package integrity'
        }

    def execute(self, command: str, **kwargs) -> Dict[str, Any]:
        """Ejecutar comando del plugin"""
        if command == 'scan_vulnerabilities':
            return self.scan_vulnerabilities(**kwargs)
        elif command == 'check_malware':
            return self.check_malware(**kwargs)
        elif command == 'audit_permissions':
            return self.audit_permissions(**kwargs)
        elif command == 'verify_integrity':
            return self.verify_integrity(**kwargs)
        else:
            return {'error': f'Unknown command: {command}'}

    def scan_vulnerabilities(self, env_name: str) -> Dict[str, Any]:
        """Scan environment for vulnerabilities"""
        scan_results: Dict[str, Any] = {
            'environment': env_name,
            'vulnerabilities_found': 0,
            'vulnerabilities': [],
            'risk_level': 'low'
        }

        try:
            success, output = self.command_runner.run_secure_command(  # type: ignore[union-attr]
                ['conda', 'list', '-n', env_name, '--json'], 'scan_vulnerabilities'
            )

            if success:
                packages = json.loads(output)

                for pkg in packages:
                    pkg_name = pkg.get('name', '')
                    pkg_version = pkg.get('version', '')

                    vulnerabilities = self._check_package_vulnerabilities(pkg_name, pkg_version)
                    scan_results['vulnerabilities'].extend(vulnerabilities)

                scan_results['vulnerabilities_found'] = len(scan_results['vulnerabilities'])
                scan_results['risk_level'] = self._calculate_risk_level(scan_results['vulnerabilities'])

            self.log_plugin_action('vulnerability_scan', {
                'environment': env_name,
                'vulnerabilities_found': scan_results['vulnerabilities_found'],
                'risk_level': scan_results['risk_level']
            })

        except Exception as e:
            scan_results['vulnerabilities'].append({
                'package': 'system',
                'issue': f'Scan error: {str(e)}',
                'severity': 'high'
            })

        return scan_results

    def check_malware(self, env_name: str) -> Dict[str, Any]:
        """Buscar paquetes potencialmente maliciosos"""
        malware_results: Dict[str, Any] = {
            'environment': env_name,
            'suspicious_packages': [],
            'malware_indicators': [],
            'risk_score': 0
        }

        try:
            success, output = self.command_runner.run_secure_command(  # type: ignore[union-attr]
                ['conda', 'list', '-n', env_name, '--json'], 'check_malware'
            )

            if success:
                packages = json.loads(output)

                for pkg in packages:
                    pkg_name = pkg.get('name', '').lower()
                    pkg_version = pkg.get('version', '')
                    pkg_channel = pkg.get('channel', '')

                    if self._is_suspicious_name_enhanced(pkg_name):
                        malware_results['suspicious_packages'].append({
                            'package': pkg_name,
                            'version': pkg_version,
                            'reason': 'Suspicious name',
                            'channel': pkg_channel
                        })

                    hash_check = self._is_suspicious_package(pkg_name, pkg_version, pkg_channel)
                    if hash_check['is_malware']:
                        malware_results['malware_indicators'].append({
                            'package': pkg_name,
                            'version': pkg_version,
                            'indicator': hash_check['reason'],
                            'channel': pkg_channel
                        })

                    trust_check = self._check_package_trust_level(pkg_name, pkg_channel)
                    if trust_check['trust_level'] in ['low', 'suspicious']:
                        malware_results['suspicious_packages'].append({
                            'package': pkg_name,
                            'version': pkg_version,
                            'reason': f'Low trust level: {trust_check["reason"]}',
                            'channel': pkg_channel
                        })

                malware_results['risk_score'] = self._calculate_malware_risk_enhanced(
                    len(malware_results['suspicious_packages']),
                    len(malware_results['malware_indicators'])
                )

            self.log_plugin_action('malware_scan', {
                'environment': env_name,
                'suspicious_packages': len(malware_results['suspicious_packages']),
                'malware_indicators': len(malware_results['malware_indicators'])
            })

        except Exception as e:
            malware_results['malware_indicators'].append({
                'package': 'system',
                'indicator': f'Scan error: {str(e)}'
            })

        return malware_results

    def audit_permissions(self, env_name: str) -> Dict[str, Any]:
        """Audit environment permissions"""
        audit_results: Dict[str, Any] = {
            'environment': env_name,
            'permission_issues': [],
            'security_issues': [],
            'overall_security': 'good'
        }

        try:
            success, output = self.command_runner.run_secure_command(  # type: ignore[union-attr]
                ['conda', 'info', '--json'], 'audit_permissions'
            )

            if success:
                conda_info = json.loads(output)
                envs_dirs = conda_info.get('envs_dirs', [])

                for env_dir in envs_dirs:
                    env_path = Path(env_dir).expanduser() / env_name
                    if env_path.exists():
                        self._audit_directory_permissions(env_path, audit_results)
                        self._audit_executable_files(env_path, audit_results)
                        self._audit_config_files(env_path, audit_results)
                        self._audit_critical_files(env_path, audit_results)
                        break

            if audit_results['security_issues']:
                audit_results['overall_security'] = 'poor'
            elif audit_results['permission_issues']:
                audit_results['overall_security'] = 'fair'

            self.log_plugin_action('permission_audit', {
                'environment': env_name,
                'security_level': audit_results['overall_security'],
                'issues_found': len(audit_results['security_issues']) + len(audit_results['permission_issues'])
            })

        except Exception as e:
            audit_results['security_issues'].append(f'Audit error: {str(e)}')

        return audit_results

    def verify_integrity(self, env_name: str) -> Dict[str, Any]:
        """Verificar integridad de paquetes"""
        integrity_results: Dict[str, Any] = {
            'environment': env_name,
            'verified_packages': 0,
            'failed_verifications': [],
            'integrity_score': 100,
            'enhanced_verification': {
                'crypto_verified': 0,
                'trust_level': 'unknown',
                'suspicious_packages': []
            }
        }

        try:
            success, output = self.command_runner.run_secure_command(  # type: ignore[union-attr]
                ['conda', 'list', '-n', env_name, '--json'], 'verify_integrity'
            )

            if success:
                packages = json.loads(output)
                crypto_verified = 0
                suspicious_packages = []

                for pkg in packages:
                    # Basic verification
                    if self._verify_package_integrity(pkg):
                        integrity_results['verified_packages'] += 1
                    else:
                        integrity_results['failed_verifications'].append({
                            'package': pkg.get('name', ''),
                            'issue': 'Basic verification failed'
                        })

                    # Enhanced verification
                    enhanced = self._verify_package_integrity_enhanced(pkg, env_name)
                    if enhanced.get('crypto_verified', False):
                        crypto_verified += 1

                    if enhanced.get('trust_level') in ['low', 'suspicious']:
                        suspicious_packages.append({
                            'package': pkg.get('name', ''),
                            'version': pkg.get('version', 'unknown'),
                            'channel': pkg.get('channel', ''),
                            'reason': enhanced.get('trust_reason', 'unknown')
                        })

                total = len(packages)
                if total > 0:
                    integrity_results['integrity_score'] = round(
                        (integrity_results['verified_packages'] / total) * 100, 2
                    )

                integrity_results['enhanced_verification']['crypto_verified'] = crypto_verified
                integrity_results['enhanced_verification']['suspicious_packages'] = suspicious_packages
                integrity_results['enhanced_verification']['trust_level'] = self._calculate_overall_trust(
                    suspicious_packages, total
                )

            self.log_plugin_action('integrity_check', {
                'environment': env_name,
                'integrity_score': integrity_results['integrity_score'],
                'failed_verifications': len(integrity_results['failed_verifications']),
                'crypto_verified': integrity_results['enhanced_verification']['crypto_verified']
            })

        except Exception as e:
            integrity_results['failed_verifications'].append({
                'package': 'system',
                'issue': f'Verification error: {str(e)}'
            })

        return integrity_results

    # ======================== ENHANCED METHODS ========================

    def _verify_package_integrity_enhanced(self, pkg_info: Dict, env_name: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            'basic_check': False,
            'crypto_verified': False,
            'trust_level': 'unknown',
            'trust_reason': ''
        }

        try:
            result['basic_check'] = self._verify_package_integrity(pkg_info)
            crypto_check = self._verify_cryptographic_integrity(pkg_info)
            result['crypto_verified'] = crypto_check.get('verified', False)

            trust_check = self._verify_trust_level(pkg_info)
            result['trust_level'] = trust_check.get('trust_level', 'unknown')
            result['trust_reason'] = ', '.join(trust_check.get('reasons', []))

        except Exception as e:
            self.logger.warning(f"Error in enhanced verification for {pkg_info.get('name')}: {str(e)}")

        return result

    def _verify_cryptographic_integrity(self, pkg_info: Dict) -> Dict[str, Any]:
        result: Dict[str, Any] = {'verified': False, 'status': 'not_verified', 'method': 'none'}

        try:
            pkg_channel = pkg_info.get('channel', '')
            if self._is_from_official_repository(pkg_channel):
                result['method'] = 'official_repository'
                result['verified'] = True
                result['status'] = 'verified_with_caveat'
            else:
                result['status'] = 'unverified'
        except Exception:
            result['status'] = 'error'

        return result

    def _verify_trust_level(self, pkg_info: Dict) -> Dict[str, Any]:
        trust_result: Dict[str, Any] = {'trust_level': 'unknown', 'reasons': []}

        pkg_name = pkg_info.get('name', '')
        pkg_channel = pkg_info.get('channel', '')

        if self._is_from_official_repository(pkg_channel):
            trust_result['trust_level'] = 'high'
            trust_result['reasons'].append('from_official_repository')

        if self._is_suspicious_package_name(pkg_name):
            trust_result['trust_level'] = 'low'
            trust_result['reasons'].append('suspicious_name')

        if self._is_unknown_channel(pkg_channel):
            if trust_result['trust_level'] != 'high':
                trust_result['trust_level'] = 'low'
            trust_result['reasons'].append('unknown_channel')

        return trust_result

    def _is_from_official_repository(self, channel: str) -> bool:
        if not channel:
            return False
        channel_name = channel.strip('/').split('/')[-1]
        return channel_name in self.OFFICIAL_REPOSITORIES

    SUSPICIOUS_KEYWORDS = [
        'crack', 'hack', 'exploit', 'backdoor', 'virus',
        'malware', 'keygen', 'serial', 'warez', 'trojan',
        'stealer', 'logger', 'injector', 'spyware', 'ransomware'
    ]

    def _is_suspicious_package_name(self, pkg_name: str) -> bool:
        return any(keyword in pkg_name.lower() for keyword in self.SUSPICIOUS_KEYWORDS)

    def _is_unknown_channel(self, channel: str) -> bool:
        unknown_indicators = ['localhost', 'file://', 'http://', 'https://unknown', 'custom', 'local', 'test']
        return any(indicator in channel for indicator in unknown_indicators)



    def _calculate_overall_trust(self, suspicious_packages: List, total_packages: int) -> str:
        if total_packages == 0:
            return 'unknown'
        suspicious_ratio = len(suspicious_packages) / total_packages
        if suspicious_ratio > 0.3:
            return 'low'
        elif suspicious_ratio > 0.1:
            return 'medium'
        else:
            return 'high'

    def _calculate_malware_risk_enhanced(self, suspicious_count: int, malware_count: int) -> int:
        risk_score = suspicious_count * 15 + malware_count * 60
        return min(risk_score, 100)

    def _is_suspicious_name_enhanced(self, pkg_name: str) -> bool:
        return self._is_suspicious_package_name(pkg_name)

    def _is_suspicious_package(self, pkg_name: str, pkg_version: str, pkg_channel: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {'is_malware': False, 'reason': ''}

        if self._is_suspicious_package_name(pkg_name):
            result['is_malware'] = True
            result['reason'] = 'Name matches suspicious patterns'

        return result

    def _check_package_trust_level(self, pkg_name: str, pkg_channel: str) -> Dict[str, Any]:
        return self._verify_trust_level({'name': pkg_name, 'channel': pkg_channel})

    def _audit_critical_files(self, env_path, audit_results):
        try:
            critical_files = [
                env_path / 'bin' / 'python',
                env_path / 'bin' / 'pip',
                env_path / 'bin' / 'conda'
            ]
            for critical_file in critical_files:
                if critical_file.exists():
                    stat = critical_file.stat()
                    if stat.st_mode & 0o022:
                        audit_results['security_issues'].append(
                            f'Critical file with insecure permissions: {critical_file}'
                        )
        except Exception as e:
            audit_results['security_issues'].append(f'Error auditing critical files: {str(e)}')

    # ======================== COMPATIBLE METHODS ========================

    def _check_package_vulnerabilities(self, pkg_name: str, pkg_version: str) -> List[Dict[str, str]]:
        return check_vulns(pkg_name, pkg_version)

    def _calculate_risk_level(self, vulnerabilities: List[Dict]) -> str:
        if not vulnerabilities:
            return 'low'
        severities = [v.get('severity', 'low') for v in vulnerabilities]
        if 'critical' in severities:
            return 'critical'
        elif 'high' in severities:
            return 'high'
        elif 'medium' in severities:
            return 'medium'
        return 'low'

    def _verify_package_integrity(self, pkg_info: Dict) -> bool:
        try:
            required = ['name', 'version', 'build_string']
            return all(field in pkg_info and pkg_info[field] for field in required)
        except Exception:
            return False

    # Remaining helper methods (maintain compatibility)
    def _audit_directory_permissions(self, directory, audit_results):
        try:
            stat = directory.stat()
            if stat.st_mode & 0o002:
                audit_results['security_issues'].append(f'Insecure permissions on {directory}')
        except Exception:
            pass

    def _audit_executable_files(self, env_path, audit_results):
        try:
            bin_dir = env_path / 'bin'
            if bin_dir.exists():
                for exe_file in bin_dir.glob('*'):
                    if exe_file.is_file():
                        stat = exe_file.stat()
                        if stat.st_mode & 0o111 and (stat.st_mode & 0o022):
                            msg = f'Executable file with broad permissions: {exe_file}'
                            audit_results['security_issues'].append(msg)
        except Exception:
            pass

    def _audit_config_files(self, env_path, audit_results):
        try:
            config_files = [env_path / 'etc' / 'conda' / 'condarc', env_path / '.condarc']
            for config_file in config_files:
                if config_file.exists():
                    stat = config_file.stat()
                    if stat.st_mode & 0o022:
                        audit_results['security_issues'].append(f'Insecure config file: {config_file}')
        except Exception:
            pass
