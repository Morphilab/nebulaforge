"""
Tests para utils/command_runner.py — edge cases
"""

from unittest.mock import MagicMock

from nebulaforge.utils.command_runner import SecureCommandRunner
from nebulaforge.core.security_models import SecurityProfile


def _make_runner(profile_level='medium'):
    cm = MagicMock()
    cm.get.side_effect = lambda key, default=None: {
        'security.security_level': profile_level,
    }.get(key, default)
    cm.get_security_profile.return_value = SecurityProfile(
        name='Test', level=profile_level, description='',
        allowed_commands=['conda', 'mamba', 'pip'],
        protected_envs=['base'], max_timeout=300,
        require_confirmation=True, enable_audit=True,
        enable_backup=True, validation_strictness='medium',
    )
    al = MagicMock()
    return SecureCommandRunner(cm, al)


def test_validate_command_allows_conda():
    sr = _make_runner()
    assert sr._validate_command(['conda', 'list']) is True


def test_validate_command_rejects_unknown():
    sr = _make_runner()
    assert sr._validate_command(['rm', '-rf', '/']) is False


def test_validate_command_rejects_dangerous_chars():
    sr = _make_runner()
    assert sr._validate_command(['conda', 'install', '$(malicious)']) is False
    assert sr._validate_command(['conda', 'install', '; rm -rf /']) is False


def test_validate_command_rejects_pipe():
    sr = _make_runner()
    assert sr._validate_command(['conda', 'list', '|', 'grep', 'foo']) is False


def test_validate_command_empty():
    sr = _make_runner()
    assert sr._validate_command([]) is False


def test_refresh_profile_updates_timeout():
    sr = _make_runner('high')
    old_timeout = sr.security_profile.max_timeout
    cm = MagicMock()
    cm.get_security_profile.return_value = SecurityProfile(
        name='Test', level='paranoid', description='',
        allowed_commands=['conda'], protected_envs=['base'],
        max_timeout=120, require_confirmation=True,
        enable_audit=True, enable_backup=True,
        validation_strictness='strict',
    )
    sr.config_manager = cm
    sr.refresh_profile()
    assert sr.security_profile.max_timeout == 120
    assert sr.security_profile.max_timeout != old_timeout


def test_run_secure_command_rejects_invalid():
    sr = _make_runner()
    success, output = sr.run_secure_command(['rm', '-rf', '/'], 'test')
    assert success is False
    assert 'not allowed' in output.lower()


def test_allows_no_deps_at_medium():
    sr = _make_runner('medium')
    assert sr._validate_command(['conda', 'install', '--no-deps', 'numpy']) is True


def test_rejects_no_deps_at_high():
    sr = _make_runner('high')
    assert sr._validate_command(['conda', 'install', '--no-deps', 'numpy']) is False


def test_rejects_always_blocked_force_reinstall():
    sr = _make_runner()
    assert sr._validate_command(['conda', 'install', '--force-reinstall', 'numpy']) is False


def test_rejects_always_blocked_insecure():
    sr = _make_runner()
    assert sr._validate_command(['conda', 'install', '--insecure', 'numpy']) is False


def test_rejects_always_blocked_no_verify():
    sr = _make_runner()
    assert sr._validate_command(['conda', 'install', '--no-verify', 'numpy']) is False


def test_allows_override_channels_at_medium():
    sr = _make_runner('medium')
    assert sr._validate_command(['conda', 'install', '--override-channels', 'numpy']) is True


def test_rejects_override_channels_at_high():
    sr = _make_runner('high')
    assert sr._validate_command(['conda', 'install', '--override-channels', 'numpy']) is False


def test_allows_copy_at_medium():
    sr = _make_runner('medium')
    assert sr._validate_command(['conda', 'create', '--copy', 'myenv']) is True


def test_rejects_always_blocked_experimental():
    sr = _make_runner()
    assert sr._validate_command(['conda', 'install', '--experimental', 'pkg']) is False


def test_allows_channel_at_medium():
    sr = _make_runner('medium')
    assert sr._validate_command(['conda', 'install', '-c', 'conda-forge', 'pkg']) is True


def test_allows_long_channel_at_medium():
    sr = _make_runner('medium')
    assert sr._validate_command(['conda', 'install', '--channel', 'defaults', 'pkg']) is True


def test_rejects_channel_at_paranoid():
    sr = _make_runner('paranoid')
    assert sr._validate_command(['conda', 'install', '-c', 'conda-forge', 'pkg']) is False


def test_allows_no_update_deps_at_medium():
    sr = _make_runner('medium')
    assert sr._validate_command(['conda', 'install', '--no-update-deps', 'pkg']) is True


def test_allows_safe_conda_install():
    sr = _make_runner()
    assert sr._validate_command(['conda', 'install', 'numpy', 'pandas']) is True


def test_allows_conda_list():
    sr = _make_runner()
    assert sr._validate_command(['conda', 'list', '--json', '-n', 'myenv']) is True
