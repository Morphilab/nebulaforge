"""
Tests para core/backup_manager.py (con mock de command_runner)
"""

from unittest.mock import MagicMock
from pathlib import Path

from nebulaforge.core.backup_manager import BackupManager


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
