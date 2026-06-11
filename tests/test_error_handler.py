"""
Tests para core/error_handler.py
"""

from unittest.mock import MagicMock
from nebulaforge.core.error_handler import SecureErrorHandler


def test_create_error_response():
    eh = SecureErrorHandler()
    resp = eh.create_error_response(True, "done")
    assert resp['success'] is True
    assert resp['message'] == "done"
    assert 'timestamp' in resp


def test_error_response_with_details():
    eh = SecureErrorHandler()
    resp = eh.create_error_response(False, "fail", {"code": 42})
    assert resp['details'] == {'code': 42}


def test_handle_system_error_logs(capsys):
    mock_logger = MagicMock()
    eh = SecureErrorHandler(audit_logger=mock_logger)
    eh.handle_system_error(ValueError("bad value"), "test_context")
    assert mock_logger.log_secure_action.called


def test_handle_security_error_logs(capsys):
    mock_logger = MagicMock()
    eh = SecureErrorHandler(audit_logger=mock_logger)
    eh.handle_security_error(PermissionError("denied"), "delete", "env_x")
    assert mock_logger.log_secure_action.called


def test_extract_error_info():
    eh = SecureErrorHandler()
    try:
        raise RuntimeError("boom")
    except RuntimeError as e:
        info = eh._extract_error_info(e, "my_context")
    assert info['context'] == 'my_context'
    assert info['type'] == 'RuntimeError'
    assert info['message'] == 'boom'


def test_safe_stderr_output_no_crash():
    eh = SecureErrorHandler()
    info = {'context': 'test', 'type': 'Error', 'message': 'msg', 'timestamp': 'now'}
    eh._safe_stderr_output(info)
