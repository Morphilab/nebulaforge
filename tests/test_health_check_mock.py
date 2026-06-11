"""
Tests para plugins/health_check.py (con mock de command_runner)
"""

from unittest.mock import MagicMock
from nebulaforge.plugins.health_check import HealthCheckPlugin


def _make_health_check(command_runner=None):
    cm = MagicMock()
    al = MagicMock()
    cr = command_runner or MagicMock()
    return HealthCheckPlugin(cm, al, command_runner=cr)


def test_get_name():
    hc = _make_health_check()
    assert hc.get_name() == 'health_check'


def test_get_commands():
    hc = _make_health_check()
    cmds = hc.get_commands()
    assert 'check_health' in cmds
    assert 'check_dependencies' in cmds
    assert 'check_performance' in cmds


def test_unknown_command():
    hc = _make_health_check()
    assert hc.execute('nonexistent') == {'error': 'Unknown command: nonexistent'}


def test_check_health_environment_not_found():
    cr = MagicMock()
    cr.run_secure_command.return_value = (False, 'not found')
    hc = _make_health_check(cr)
    result = hc.check_health('nonexistent_env')
    assert result['status'] == 'error'
    assert 'not found' in result['issues'][0].lower()


def test_check_health_success():
    cr = MagicMock()
    cr.run_secure_command.return_value = (True, '[{"name":"python","version":"3.10.0"}]')
    hc = _make_health_check(cr)
    result = hc.check_health('test_env')
    assert result['status'] in ('healthy', 'warning', 'error')


def test_check_dependencies_no_conflicts():
    cr = MagicMock()
    cr.run_secure_command.return_value = (True, '[{"name":"numpy","version":"1.21.0"}]')
    hc = _make_health_check(cr)
    result = hc.check_dependencies('test_env')
    assert 'conflicts' in result


def test_check_performance_success():
    cr = MagicMock()
    cr.run_secure_command.return_value = (True, '{"envs_dirs": ["/tmp"]}')
    hc = _make_health_check(cr)
    result = hc.check_performance('test_env')
    assert 'metrics' in result
    assert 'recommendations' in result


def test_known_conflicts():
    hc = _make_health_check()
    pkgs = [{'name': 'tensorflow'}, {'name': 'tensorflow-gpu'}]
    conflicts = hc._check_known_conflicts(pkgs)
    assert len(conflicts) == 1
    assert 'tensorflow' in conflicts[0]


def test_directory_permissions_check(tmp_path):
    hc = _make_health_check()
    d = tmp_path / 'testdir'
    d.mkdir(mode=0o700)
    assert hc._check_directory_permissions(d) is True
    d2 = tmp_path / 'open'
    d2.mkdir()
    d2.chmod(0o777)
    assert hc._check_directory_permissions(d2) is False


def test_find_heavy_packages():
    cr = MagicMock()
    cr.run_secure_command.return_value = (True, '[{"name":"tensorflow","version":"2.10.0"},{"name":"numpy","version":"1.21.0"}]')
    hc = _make_health_check(cr)
    heavy = hc._find_heavy_packages('test_env')
    assert 'tensorflow' in heavy
    assert 'numpy' not in heavy
