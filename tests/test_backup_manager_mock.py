"""
Tests for core/backup_manager.py (with mock of command_runner)
"""

import hashlib
from unittest.mock import MagicMock

from nebulaforge.core.backup_manager import BackupManager
from nebulaforge.core.security_models import SecurityProfile


def _make_manager(tmp_path, command_runner=None):
    cm = MagicMock()
    cm.get.side_effect = lambda key, default=None: {
        'paths.backup_dir': str(tmp_path / 'backups'),
        'security.enable_audit': True,
    }.get(key, default)
    cr = command_runner or MagicMock()
    # Provide a real audit_logger to avoid FS issues with mock paths
    from nebulaforge.core.audit_logger import AuditLogger
    cm.get_secure_path.return_value = tmp_path / 'logs'
    al = AuditLogger(cm)
    return BackupManager(cm, cr, audit_logger=al)


def test_backup_dir_created(tmp_path):
    cr = MagicMock()
    bm = _make_manager(tmp_path, cr)
    assert bm.backup_dir.exists()


def test_list_backups_no_backups(tmp_path):
    cr = MagicMock()
    bm = _make_manager(tmp_path, cr)
    backups = bm.list_backups()
    assert backups == []


def test_list_backups_with_backup_file(tmp_path):
    cr = MagicMock()
    bm = _make_manager(tmp_path, cr)
    backup_file = bm.backup_dir / 'backup_my_env_20240101_000000.yaml'
    bm.backup_dir.mkdir(parents=True, exist_ok=True)
    backup_file.write_text('name: my_env\nchannels: []\ndependencies: []\n', encoding='utf-8')
    backups = bm.list_backups()
    assert len(backups) >= 1
    assert backups[0]['env_name'] == 'my_env'


def test_create_backup_success(tmp_path):
    cr = MagicMock()
    cr.run_secure_command.side_effect = [
        (True, '{"envs": ["/usr/envs/test_env"]}'),
        (True, '{"channels": ["conda-forge"], "dependencies": ["python=3.10.0", "numpy=1.21.0"]}'),
    ]
    bm = _make_manager(tmp_path, cr)
    ok, msg = bm.create_backup('test_env', 'test backup')
    assert ok is True
    assert 'Backup created' in msg


def test_create_backup_env_not_found(tmp_path):
    cr = MagicMock()
    cr.run_secure_command.return_value = (True, '{"envs": ["other_env"]}')
    bm = _make_manager(tmp_path, cr)
    ok, msg = bm.create_backup('test_env')
    assert ok is False
    assert 'not found' in msg


def test_create_backup_generates_checksum(tmp_path):
    cr = MagicMock()
    cr.run_secure_command.side_effect = [
        (True, '{"envs": ["/usr/envs/test_env"]}'),
        (True, '{"channels": ["conda-forge"], "dependencies": ["python=3.10.0", "numpy=1.21.0"]}'),
    ]
    bm = _make_manager(tmp_path, cr)
    bm.create_backup('test_env')
    yaml_files = list(bm.backup_dir.glob('backup_test_env_*.yaml'))
    sha_files = list(bm.backup_dir.glob('backup_test_env_*.yaml.sha256'))
    assert len(yaml_files) == 1
    assert len(sha_files) == 1
    sha_content = sha_files[0].read_text()
    expected_name = sha_files[0].name.replace('.sha256', '')
    assert expected_name in sha_content


def test_backup_info_with_existing_file(tmp_path):
    cr = MagicMock()
    bm = _make_manager(tmp_path, cr)
    bm.backup_dir.mkdir(parents=True, exist_ok=True)
    f = bm.backup_dir / 'backup_test.yaml'
    f.write_text('name: test_env\nchannels: [conda-forge]\ndependencies: [numpy]\n', encoding='utf-8')
    info = bm.get_backup_info(f)
    assert info['env_name'] == 'test_env'
    assert info['dependencies_count'] == 1


def test_backup_info_not_found(tmp_path):
    cr = MagicMock()
    bm = _make_manager(tmp_path, cr)
    info = bm.get_backup_info(tmp_path / 'nonexistent.yaml')
    assert 'error' in info


def _write_backup_with_checksum(bm, filename, content):
    backup_path = bm.backup_dir / filename
    backup_path.write_text(content, encoding='utf-8')
    checksum = hashlib.sha256(backup_path.read_bytes()).hexdigest()
    backup_path.with_suffix('.yaml.sha256').write_text(
        f"{checksum}  {filename}\n", encoding='utf-8'
    )
    return backup_path


def test_create_backup_rejects_invalid_env_name(tmp_path):
    cr = MagicMock()
    bm = _make_manager(tmp_path, cr)
    ok, msg = bm.create_backup('../escape')
    assert ok is False
    assert 'Invalid environment name' in msg
    cr.run_secure_command.assert_not_called()


def test_create_backup_allows_protected_existing_name(tmp_path):
    cr = MagicMock()
    bm = _make_manager(tmp_path, cr)
    bm._list_environments = MagicMock(return_value=(True, ['base']))
    bm._get_environment_info = MagicMock(return_value={
        'channels': [], 'dependencies': [], 'python_version': '3.12',
    })

    ok, msg = bm.create_backup('base')
    assert ok is True
    assert list(bm.backup_dir.glob('backup_base_*.yaml'))


def test_restore_rejects_invalid_env_name_from_backup(tmp_path):
    cr = MagicMock()
    bm = _make_manager(tmp_path, cr)
    _write_backup_with_checksum(
        bm,
        'backup_evil_20240101_000000.yaml',
        'name: ../escape\nchannels: []\ndependencies: []\n',
    )

    ok, msg = bm.restore_backup('backup_evil_20240101_000000.yaml')
    assert ok is False
    assert 'Invalid environment name' in msg
    cr.run_secure_command.assert_not_called()


def test_restore_rejects_protected_environment(tmp_path):
    cr = MagicMock()
    bm = _make_manager(tmp_path, cr)
    bm.config_manager.get_security_profile.return_value = SecurityProfile(
        name='Medium Security', level='medium', description='',
        allowed_commands=['conda'], protected_envs=['base', 'root', 'prod'],
        max_timeout=300, require_confirmation=True, enable_audit=True,
        enable_backup=True, validation_strictness='medium',
    )
    _write_backup_with_checksum(
        bm,
        'backup_prod_20240101_000000.yaml',
        'name: prod\nchannels: []\ndependencies: []\n',
    )

    ok, msg = bm.restore_backup('backup_prod_20240101_000000.yaml')
    assert ok is False
    assert 'protected' in msg.lower()
    cr.run_secure_command.assert_not_called()


def test_restore_rejects_reserved_environment_name(tmp_path):
    cr = MagicMock()
    bm = _make_manager(tmp_path, cr)
    bm.config_manager.get_security_profile.return_value = SecurityProfile(
        name='Medium Security', level='medium', description='',
        allowed_commands=['conda'], protected_envs=['base', 'root', 'prod'],
        max_timeout=300, require_confirmation=True, enable_audit=True,
        enable_backup=True, validation_strictness='medium',
    )
    _write_backup_with_checksum(
        bm,
        'backup_system_20240101_000000.yaml',
        'name: system\nchannels: []\ndependencies: []\n',
    )

    ok, msg = bm.restore_backup('backup_system_20240101_000000.yaml')
    assert ok is False
    assert 'Invalid environment name' in msg
    cr.run_secure_command.assert_not_called()


def test_restore_cleans_temp_file_after_success(tmp_path):
    cr = MagicMock()
    cr.run_secure_command.side_effect = [
        (True, '{"envs": []}'),
        (True, ''),
        (True, ''),
    ]
    bm = _make_manager(tmp_path, cr)
    _write_backup_with_checksum(
        bm,
        'backup_myenv_20240101_000000.yaml',
        'name: myenv\nchannels: []\ndependencies: [python=3.12]\n',
    )

    ok, msg = bm.restore_backup('backup_myenv_20240101_000000.yaml')
    assert ok is True
    assert not list(bm.backup_dir.glob('temp_restore_*.yaml'))


def test_restore_replaces_existing_environment_atomically(tmp_path):
    cr = MagicMock()
    cr.run_secure_command.side_effect = [
        (True, ''),  # create temporary environment
        (True, ''),  # rename old environment aside
        (True, ''),  # rename temporary environment into place
        (True, ''),  # remove quarantine
    ]
    bm = _make_manager(tmp_path, cr)
    bm._list_environments = MagicMock(return_value=(True, ['myenv']))
    bm.create_backup = MagicMock(return_value=(True, 'pre-restore backup'))

    _write_backup_with_checksum(
        bm,
        'backup_myenv_20240101_000000.yaml',
        'name: myenv\nchannels: []\ndependencies: [python=3.12]\n',
    )

    ok, msg = bm.restore_backup('backup_myenv_20240101_000000.yaml')
    assert ok is True
    commands = [call.args[0] for call in cr.run_secure_command.call_args_list]
    assert commands[0][:3] == ['conda', 'env', 'create']
    assert commands[1][:2] == ['conda', 'rename'] and commands[1][2] == '-n'
    assert commands[2][:2] == ['conda', 'rename'] and commands[2][4] == 'myenv'
    assert commands[3][:3] == ['conda', 'env', 'remove']


def test_restore_create_failure_keeps_original(tmp_path):
    cr = MagicMock()
    cr.run_secure_command.side_effect = [
        (False, 'create failed'),
        (True, ''),  # cleanup temporary environment
    ]
    bm = _make_manager(tmp_path, cr)
    bm._list_environments = MagicMock(return_value=(True, ['myenv']))
    bm.create_backup = MagicMock(return_value=(True, 'pre-restore backup'))

    _write_backup_with_checksum(
        bm,
        'backup_myenv_20240101_000000.yaml',
        'name: myenv\nchannels: []\ndependencies: [python=3.12]\n',
    )

    ok, msg = bm.restore_backup('backup_myenv_20240101_000000.yaml')
    assert ok is False
    assert 'temporary' in msg.lower()
    commands = [call.args[0] for call in cr.run_secure_command.call_args_list]
    assert all(cmd[:2] != ['conda', 'rename'] for cmd in commands)


def test_restore_rename_old_failure_keeps_original(tmp_path):
    cr = MagicMock()
    cr.run_secure_command.side_effect = [
        (True, ''),              # create temporary environment
        (False, 'rename failed'),  # move old aside fails
        (True, ''),              # cleanup temporary environment
    ]
    bm = _make_manager(tmp_path, cr)
    bm._list_environments = MagicMock(return_value=(True, ['myenv']))
    bm.create_backup = MagicMock(return_value=(True, 'pre-restore backup'))

    _write_backup_with_checksum(
        bm,
        'backup_myenv_20240101_000000.yaml',
        'name: myenv\nchannels: []\ndependencies: [python=3.12]\n',
    )

    ok, msg = bm.restore_backup('backup_myenv_20240101_000000.yaml')
    assert ok is False
    assert 'untouched' in msg.lower()
    commands = [call.args[0] for call in cr.run_secure_command.call_args_list]
    rename_targets = [cmd for cmd in commands if cmd[:2] == ['conda', 'rename']]
    assert len(rename_targets) == 1


def test_restore_rename_new_failure_rolls_back(tmp_path):
    cr = MagicMock()
    cr.run_secure_command.side_effect = [
        (True, ''),               # create temporary environment
        (True, ''),               # move old aside
        (False, 'final rename failed'),  # move temp into place fails
        (True, ''),               # rollback: move old back
        (True, ''),               # cleanup temporary environment
    ]
    bm = _make_manager(tmp_path, cr)
    bm._list_environments = MagicMock(return_value=(True, ['myenv']))
    bm.create_backup = MagicMock(return_value=(True, 'pre-restore backup'))

    _write_backup_with_checksum(
        bm,
        'backup_myenv_20240101_000000.yaml',
        'name: myenv\nchannels: []\ndependencies: [python=3.12]\n',
    )

    ok, msg = bm.restore_backup('backup_myenv_20240101_000000.yaml')
    assert ok is False
    assert 'original environment was restored' in msg.lower()


def test_restore_refuses_when_environment_list_fails(tmp_path):
    cr = MagicMock()
    cr.run_secure_command.return_value = (False, 'conda unavailable')
    bm = _make_manager(tmp_path, cr)
    _write_backup_with_checksum(
        bm,
        'backup_myenv_20240101_000000.yaml',
        'name: myenv\nchannels: []\ndependencies: []\n',
    )

    ok, msg = bm.restore_backup('backup_myenv_20240101_000000.yaml')
    assert ok is False
    assert 'refusing' in msg.lower()
    cr.run_secure_command.assert_called_once_with(
        ['conda', 'env', 'list', '--json'], 'list_environments'
    )
