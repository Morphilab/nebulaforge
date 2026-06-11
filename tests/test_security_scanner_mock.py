"""
Tests para plugins/security_scanner.py (con mock de command_runner)
"""

from unittest.mock import MagicMock, PropertyMock
from nebulaforge.plugins.security_scanner import SecurityScannerPlugin


def _make_scanner(command_runner=None):
    cm = MagicMock()
    al = MagicMock()
    cr = command_runner or MagicMock()
    return SecurityScannerPlugin(cm, al, command_runner=cr)


def test_get_name():
    sc = _make_scanner()
    assert sc.get_name() == 'security_scanner'


def test_get_description():
    sc = _make_scanner()
    assert len(sc.get_description()) > 0


def test_get_commands():
    sc = _make_scanner()
    cmds = sc.get_commands()
    assert 'scan_vulnerabilities' in cmds
    assert 'check_malware' in cmds
    assert 'audit_permissions' in cmds
    assert 'verify_integrity' in cmds


def test_scan_vulnerabilities_success():
    cr = MagicMock()
    cr.run_secure_command.return_value = (True, '[{"name":"numpy","version":"1.21.0"}]')
    sc = _make_scanner(cr)
    result = sc.execute('scan_vulnerabilities', env_name='test_env')
    assert result['vulnerabilities_found'] > 0


def test_scan_vulnerabilities_no_vulns():
    cr = MagicMock()
    cr.run_secure_command.return_value = (True, '[{"name":"numpy","version":"1.26.0"}]')
    sc = _make_scanner(cr)
    result = sc.execute('scan_vulnerabilities', env_name='test_env')
    assert result['vulnerabilities_found'] == 0


def test_check_malware():
    cr = MagicMock()
    cr.run_secure_command.return_value = (True, '[{"name":"numpy","version":"1.21.0","channel":"conda-forge"}]')
    sc = _make_scanner(cr)
    result = sc.execute('check_malware', env_name='test_env')
    assert 'risk_score' in result


def test_unknown_command():
    sc = _make_scanner()
    result = sc.execute('nonexistent')
    assert 'error' in result


def test_verify_integrity():
    cr = MagicMock()
    cr.run_secure_command.return_value = (True, '[{"name":"python","version":"3.10.0","build_string":"h123"}]')
    sc = _make_scanner(cr)
    result = sc.execute('verify_integrity', env_name='test_env')
    assert 'integrity_score' in result


def test_risk_level_critical():
    sc = _make_scanner()
    result = sc._calculate_risk_level([{'severity': 'critical'}])
    assert result == 'critical'


def test_risk_level_high():
    sc = _make_scanner()
    result = sc._calculate_risk_level([{'severity': 'high'}])
    assert result == 'high'


def test_risk_level_low():
    sc = _make_scanner()
    result = sc._calculate_risk_level([])
    assert result == 'low'


def test_verify_package_integrity():
    sc = _make_scanner()
    assert sc._verify_package_integrity({'name': 'pkg', 'version': '1.0', 'build_string': 'b1'}) is True
    assert sc._verify_package_integrity({'name': '', 'version': '1.0', 'build_string': 'b1'}) is False


def test_is_from_official_repository():
    sc = _make_scanner()
    assert sc._is_from_official_repository('conda-forge') is True
    assert sc._is_from_official_repository('defaults') is True
    assert sc._is_from_official_repository('unknown-channel') is False


def test_suspicious_package_name():
    sc = _make_scanner()
    assert sc._is_suspicious_package_name('safe-pkg') is False
    assert sc._is_suspicious_package_name('malware-pkg') is True


def test_is_unknown_channel():
    sc = _make_scanner()
    assert sc._is_unknown_channel('localhost:8000') is True
    assert sc._is_unknown_channel('conda-forge') is False


def test_overall_trust():
    sc = _make_scanner()
    assert sc._calculate_overall_trust([], 10) == 'high'
    assert sc._calculate_overall_trust(['a', 'b'], 10) == 'medium'
    assert sc._calculate_overall_trust(['a', 'b', 'c', 'd'], 5) == 'low'
