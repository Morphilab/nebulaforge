"""
Tests para core/security_manager.py (con mock de dependencias)
"""

from unittest.mock import MagicMock, patch
from pathlib import Path

from nebulaforge.core.security_manager import SecurityManager
from nebulaforge.core.security_models import SecurityProfile


def _make_manager(config_path=None, **overrides):
    with patch('nebulaforge.core.security_manager.ConfigManager') as MockCM, \
         patch('nebulaforge.core.security_manager.AuditLogger') as MockAL, \
         patch('nebulaforge.core.security_manager.SecureCommandRunner') as MockCR, \
         patch('nebulaforge.core.security_manager.BackupManager') as MockBM, \
         patch('nebulaforge.core.security_manager.SecureDependencyChecker') as MockDC, \
         patch('nebulaforge.core.security_manager.SecurityValidator') as MockSV:

        cm_instance = MockCM.return_value
        cm_instance.get.side_effect = lambda key, default=None: {
            'core.production_mode': True,
            'security.security_level': 'medium',
            'paths.backup_dir': str(Path.home() / '.nebulaforge' / 'backups'),
        }.get(key, default)
        cm_instance.get_security_profile.return_value = SecurityProfile(
            name='Medium Security', level='medium', description='Balanced',
            allowed_commands=['conda', 'mamba', 'pip'],
            protected_envs=['base', 'root'], max_timeout=300,
            require_confirmation=True, enable_audit=True,
            enable_backup=True, validation_strictness='medium',
        )

        sm = SecurityManager.__new__(SecurityManager)
        sm.config_manager = cm_instance
        sm.audit_logger = MockAL.return_value
        sm.error_handler = MagicMock()
        sm.command_runner = MockCR.return_value
        sm.backup_manager = MockBM.return_value
        sm.dependency_checker = MockDC.return_value
        sm.validator = MockSV.return_value
        sm.security_profile = cm_instance.get_security_profile()
        sm.production_mode = True
        sm.credentials = MagicMock()
        sm.session_manager = MagicMock()
        sm.secure_store = MagicMock()

        # Apply overrides
        for k, v in overrides.items():
            setattr(sm, k, v)
        return sm


def test_get_security_info():
    sm = _make_manager()
    info = sm.get_security_info()
    assert info['level'] == 'medium'
    assert info['profile_name'] == 'Medium Security'


def test_validate_env_name_delegates():
    sm = _make_manager()
    sm.validator.validate_env_name.return_value = True
    sm.validator.validate_package_list.return_value = (True, [])
    sm.command_runner.run_secure_command.return_value = (True, '')
    result, msg = sm.create_secure_environment({'name': 'valid_env', 'python_version': '3.10'})
    assert result is True


def test_create_secure_environment_fails_invalid_name():
    sm = _make_manager()
    sm.validator.validate_env_name.return_value = False
    result, msg = sm.create_secure_environment({'name': 'bad name!'})
    assert result is False
    assert 'Invalid' in msg


def test_create_secure_environment_fails_invalid_packages():
    sm = _make_manager()
    sm.validator.validate_env_name.return_value = True
    sm.validator.validate_package_list.return_value = (False, ['hack-pkg'])
    result, msg = sm.create_secure_environment({'name': 'env1', 'packages': ['hack-pkg']})
    assert result is False
    assert 'Invalid' in msg


def test_list_environments_success():
    sm = _make_manager()
    sm.command_runner.run_secure_command.return_value = (True, '{"envs": ["/usr/env1", "/usr/env2"]}')
    ok, envs = sm.list_environments()
    assert ok is True
    assert 'env1' in envs
    assert 'env2' in envs


def test_list_environments_failure():
    sm = _make_manager()
    sm.command_runner.run_secure_command.return_value = (False, 'error')
    ok, envs = sm.list_environments()
    assert ok is False
    assert envs == []


def test_delete_environment_protected():
    sm = _make_manager()
    sm.security_profile.protected_envs = ['base']
    result, msg = sm.delete_environment('base')
    assert result is False
    assert 'protected' in msg.lower()


def test_delete_environment_success():
    sm = _make_manager()
    sm.production_mode = False
    sm.validator.validate_env_name.return_value = True
    sm.backup_manager.create_backup.return_value = (True, 'ok')
    sm.command_runner.run_secure_command.return_value = (True, '')
    result, msg = sm.delete_environment('my_env')
    assert result is True


def test_delete_environment_blocked_in_production():
    sm = _make_manager()
    sm.production_mode = True
    sm.validator.validate_env_name.return_value = True
    result, msg = sm.delete_environment('my_env')
    assert result is False
    assert 'production mode' in msg.lower()


def test_change_security_level_valid():
    sm = _make_manager()
    sm.config_manager.security_profiles = {'low': {}, 'medium': {}, 'high': {}}
    sm.config_manager.get_security_profile.return_value = sm.security_profile
    assert sm.change_security_level('high') is True


def test_change_security_level_invalid():
    sm = _make_manager()
    sm.config_manager.security_profiles = {'low': {}, 'medium': {}}
    assert sm.change_security_level('paranoid') is False


def test_get_system_status():
    sm = _make_manager()
    sm.command_runner.run_secure_command.return_value = (True, '{"envs": ["/usr/env1"]}')
    status = sm.get_system_status()
    assert 'security_profile' in status
    assert 'environments_count' in status
    assert status['environments_count'] == 1


def test_require_confirmation_for_protected_env():
    sm = _make_manager()
    sm.security_profile.protected_envs = ['base']
    result = sm.require_confirmation_for('delete', 'base')
    assert result is True


def test_require_confirmation_for_non_protected_medium():
    sm = _make_manager()
    sm.security_profile.level = 'medium'
    sm.security_profile.protected_envs = ['base']
    result = sm.require_confirmation_for('delete', 'myenv')
    assert result is True


def test_require_confirmation_low_level_no_prod():
    sm = _make_manager()
    sm.production_mode = False
    sm.security_profile.level = 'low'
    sm.security_profile.require_confirmation = False
    result = sm.require_confirmation_for('delete', 'myenv')
    assert result is False


def test_require_confirmation_non_delete_with_conf_flag():
    sm = _make_manager()
    sm.security_profile.require_confirmation = False
    sm.production_mode = False
    result = sm.require_confirmation_for('create', 'myenv')
    assert result is False


def test_check_operation_allowed_blocks_in_production():
    sm = _make_manager()
    sm.production_mode = True
    sm.validator.validate_env_name.return_value = True
    sm.backup_manager.create_backup.return_value = (True, 'ok')
    sm.command_runner.run_secure_command.return_value = (True, '')
    result, msg = sm.delete_environment('my_env')
    assert result is False
    assert 'production mode' in msg.lower()


def test_check_operation_allows_in_non_production():
    sm = _make_manager()
    sm.production_mode = False
    sm.validator.validate_env_name.return_value = True
    sm.backup_manager.create_backup.return_value = (True, 'ok')
    sm.command_runner.run_secure_command.return_value = (True, '')
    result, msg = sm.delete_environment('my_env')
    assert result is True
