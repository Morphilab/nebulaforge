"""
Tests for core/audit_logger.py
"""

from unittest.mock import MagicMock
from pathlib import Path
from nebulaforge.core.audit_logger import AuditLogger


def _make_config(tmp_path):
    cm = MagicMock()
    cm.get_secure_path.return_value = tmp_path / 'logs'
    cm.get.side_effect = lambda key, default=None: {
        'security.security_level': 'medium'
    }.get(key, default)
    return cm


def test_logger_initialization(tmp_path):
    cm = _make_config(tmp_path)
    al = AuditLogger(cm)
    assert al.session_id is not None
    assert len(al.session_id) == 32


def test_audit_log_writes_file(tmp_path):
    cm = _make_config(tmp_path)
    al = AuditLogger(cm)
    al.log_secure_action('test_action', 'target1', 'success')
    logs = al.get_audit_trail()
    assert len(logs) >= 1
    assert logs[-1]['action'] == 'test_action'
    assert logs[-1]['target'] == 'target1'
    assert logs[-1]['status'] == 'success'


def test_get_audit_trail_limit(tmp_path):
    cm = _make_config(tmp_path)
    al = AuditLogger(cm)
    for i in range(10):
        al.log_secure_action(f'action_{i}', 'target', 'success')
    logs = al.get_audit_trail(limit=3)
    assert len(logs) <= 3


def test_log_system_event(tmp_path):
    cm = _make_config(tmp_path)
    al = AuditLogger(cm)
    al.log_system_event('test_event', 'message text')
    # The system event goes to system_file, not audit_file
    system_file = tmp_path / 'logs' / 'system_events.log'
    assert system_file.exists()
    content = system_file.read_text()
    assert 'test_event' in content
    assert 'message text' in content


def test_log_secure_action_with_details(tmp_path):
    cm = _make_config(tmp_path)
    al = AuditLogger(cm)
    al.log_secure_action('test', 'target', 'error', details={'reason': 'timeout'})
    logs = al.get_audit_trail()
    assert logs[-1]['details']['reason'] == 'timeout'


def test_session_id_persistent_in_session(tmp_path):
    cm = _make_config(tmp_path)
    al = AuditLogger(cm)
    sid = al.session_id
    al.log_secure_action('a', 'b', 'success')
    logs = al.get_audit_trail()
    assert logs[-1]['session_id'] == sid


def test_verify_audit_chain_valid(tmp_path):
    cm = _make_config(tmp_path)
    al = AuditLogger(cm)
    al.log_secure_action('action1', 'target1', 'success')
    al.log_secure_action('action2', 'target2', 'error', details={'code': 1})
    result = al.verify_audit_chain()
    assert result['valid'] is True
    assert result['entries'] >= 2  # 2 log_secure_action calls


def test_verify_audit_chain_detects_tampering(tmp_path):
    cm = _make_config(tmp_path)
    al = AuditLogger(cm)
    al.log_secure_action('action1', 'target1', 'success')
    al.log_secure_action('action2', 'target2', 'success')

    # Tamper with the log file
    log_file = tmp_path / 'logs' / 'security_audit.log'
    content = log_file.read_text()
    tampered = content.replace('success', 'tampered', 1)
    log_file.write_text(tampered)

    result = al.verify_audit_chain()
    assert result['valid'] is False
    assert result['broken_at'] is not None


def test_verify_audit_chain_empty_file(tmp_path):
    cm = _make_config(tmp_path)
    al = AuditLogger(cm)
    log_file = tmp_path / 'logs' / 'security_audit.log'
    if log_file.exists():
        log_file.unlink()
    result = al.verify_audit_chain(log_file)
    assert result['valid'] is True
    assert result['entries'] == 0


def test_audit_entry_has_previous_hash(tmp_path):
    cm = _make_config(tmp_path)
    al = AuditLogger(cm)
    al.log_secure_action('action1', 'target1', 'success')
    logs = al.get_audit_trail()
    # All entries after genesis should have previous_hash
    for entry in logs:
        assert 'previous_hash' in entry
        assert len(entry['previous_hash']) == 64
