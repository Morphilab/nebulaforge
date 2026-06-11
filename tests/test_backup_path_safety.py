"""
Tests for the path-traversal hardening of BackupManager.restore_backup().

These tests verify that restore_backup() refuses to operate on backup files
located outside the configured backup directory.
"""
from unittest.mock import MagicMock
from pathlib import Path

import pytest

from nebulaforge.core.backup_manager import BackupManager


def _make_manager(tmp_path, command_runner=None):
    cm = MagicMock()
    cm.get.side_effect = lambda key, default=None: {
        'paths.backup_dir': str(tmp_path / 'backups'),
        'security.enable_audit': True,
    }.get(key, default)
    cr = command_runner or MagicMock()
    cm.get_secure_path.return_value = tmp_path / 'logs'
    from nebulaforge.core.audit_logger import AuditLogger
    al = AuditLogger(cm)
    return BackupManager(cm, cr, audit_logger=al)


def test_restore_rejects_absolute_outside_backup_dir(tmp_path):
    """restore_backup() must reject absolute paths outside the backup dir."""
    cr = MagicMock()
    bm = _make_manager(tmp_path, cr)
    outside = tmp_path / 'etc' / 'malicious.yaml'
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_text('name: x\nchannels: []\ndependencies: []\n', encoding='utf-8')

    ok, msg = bm.restore_backup(str(outside))
    assert ok is False
    assert 'backup directory' in msg.lower()
    cr.run_secure_command.assert_not_called()


def test_restore_rejects_parent_traversal(tmp_path):
    """Path traversal using ../ must be rejected."""
    cr = MagicMock()
    bm = _make_manager(tmp_path, cr)
    traversal = str(bm.backup_dir / '..' / '..' / 'etc' / 'passwd.yaml')

    ok, msg = bm.restore_backup(traversal)
    assert ok is False
    assert 'backup directory' in msg.lower()


def test_restore_rejects_symlink_escaping_backup_dir(tmp_path):
    """A symlink inside backup_dir that points outside must be rejected."""
    cr = MagicMock()
    bm = _make_manager(tmp_path, cr)

    outside_dir = tmp_path / 'outside'
    outside_dir.mkdir()
    real_backup = outside_dir / 'real.yaml'
    real_backup.write_text('name: x\nchannels: []\ndependencies: []\n', encoding='utf-8')

    link_path = bm.backup_dir / 'linked.yaml'
    link_path.symlink_to(real_backup)

    ok, msg = bm.restore_backup(str(link_path))
    assert ok is False
    assert 'backup directory' in msg.lower()


def test_restore_accepts_relative_path_within_backup_dir(tmp_path):
    """A bare filename (resolved against backup_dir) must be accepted (subject to checksum)."""
    cr = MagicMock()
    bm = _make_manager(tmp_path, cr)
    name = 'backup_myenv_20240101_000000.yaml'
    backup = bm.backup_dir / name
    backup.write_text('name: myenv\nchannels: []\ndependencies: []\n', encoding='utf-8')
    # No checksum sidecar -> checksum fails, but path is accepted
    ok, msg = bm.restore_backup(name)
    assert ok is False
    assert 'checksum' in msg.lower()


def test_restore_accepts_absolute_path_inside_backup_dir(tmp_path):
    """An absolute path inside the backup directory must be accepted (subject to checksum)."""
    cr = MagicMock()
    bm = _make_manager(tmp_path, cr)
    name = 'backup_myenv_20240101_000001.yaml'
    backup = bm.backup_dir / name
    backup.write_text('name: myenv\nchannels: []\ndependencies: []\n', encoding='utf-8')
    ok, msg = bm.restore_backup(str(backup))
    assert ok is False
    assert 'checksum' in msg.lower()


def test_resolve_safe_backup_path_returns_none_for_escape(tmp_path):
    """Direct unit test of _resolve_safe_backup_path()."""
    cr = MagicMock()
    bm = _make_manager(tmp_path, cr)
    outside = str(tmp_path / 'outside.yaml')
    assert bm._resolve_safe_backup_path(outside) is None
