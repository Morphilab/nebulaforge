"""
Tests para core/dependency_checker.py (con mock de command_runner)
"""

from unittest.mock import MagicMock
from nebulaforge.core.dependency_checker import SecureDependencyChecker


def _make_checker(command_runner=None):
    cm = MagicMock()
    cr = command_runner or MagicMock()
    return SecureDependencyChecker(cm, cr)


def test_get_environment_info_success():
    cr = MagicMock()
    cr.run_secure_command.return_value = (True, '[{"name":"python","version":"3.10.0"},{"name":"numpy","version":"1.21.0"}]')
    dc = _make_checker(cr)
    info = dc.get_environment_info('test_env')
    assert info['name'] == 'test_env'
    assert info['package_count'] == 2
    assert info['python_version'] == '3.10.0'


def test_get_environment_info_failure():
    cr = MagicMock()
    cr.run_secure_command.return_value = (False, 'error')
    dc = _make_checker(cr)
    info = dc.get_environment_info('test_env')
    assert 'error' in info


def test_get_environment_info_no_python():
    cr = MagicMock()
    cr.run_secure_command.return_value = (True, '[{"name":"numpy","version":"1.21.0"}]')
    dc = _make_checker(cr)
    info = dc.get_environment_info('test_env')
    assert info['python_version'] == 'unknown'


def test_check_vulnerabilities():
    cr = MagicMock()
    cr.run_secure_command.return_value = (True, '[{"name":"numpy","version":"1.21.0"}]')
    dc = _make_checker(cr)
    vulns = dc.check_vulnerabilities('test_env')
    assert len(vulns) > 0
    assert 'CVE' in vulns[0]['issue']


def test_check_vulnerabilities_safe_version():
    cr = MagicMock()
    cr.run_secure_command.return_value = (True, '[{"name":"numpy","version":"1.26.0"}]')
    dc = _make_checker(cr)
    vulns = dc.check_vulnerabilities('test_env')
    assert len(vulns) == 0


def test_check_vulnerabilities_with_error():
    cr = MagicMock()
    cr.run_secure_command.return_value = (False, 'failed')
    dc = _make_checker(cr)
    vulns = dc.check_vulnerabilities('test_env')
    assert len(vulns) == 1
    assert 'info' in vulns[0]['issue']


def test_get_outdated_packages():
    cr = MagicMock()
    cr.run_secure_command.return_value = (True, '[{"name":"numpy","version":"1.21.0","latest_version":"1.23.0"}]')
    dc = _make_checker(cr)
    outdated = dc.get_outdated_packages('test_env')
    assert len(outdated) == 1
    assert outdated[0]['package'] == 'numpy'
    assert outdated[0]['latest_version'] == '1.23.0'


def test_get_outdated_packages_empty():
    cr = MagicMock()
    cr.run_secure_command.return_value = (True, '[]')
    dc = _make_checker(cr)
    outdated = dc.get_outdated_packages('test_env')
    assert outdated == []


def test_check_security_issues_with_problematic():
    cr = MagicMock()
    cr.run_secure_command.return_value = (True, '[{"name":"pycrypto","version":"2.6.1"}]')
    dc = _make_checker(cr)
    info = dc.get_environment_info('test_env')
    assert len(info['security_issues']) > 0
