"""
Tests para plugins/base_plugin.py
"""

from unittest.mock import MagicMock
from nebulaforge.plugins.base_plugin import BasePlugin


class SimplePlugin(BasePlugin):
    def get_name(self):
        return 'simple_test'

    def get_description(self):
        return 'A test plugin'

    def get_commands(self):
        return {'ping': 'Return pong'}

    def execute(self, command, **kwargs):
        if command == 'ping':
            return {'result': 'pong'}
        return {'error': 'unknown'}


def test_base_plugin_initialization():
    cm = MagicMock()
    al = MagicMock()
    p = SimplePlugin(cm, al)
    assert p.get_name() == 'simple_test'
    assert p.get_description() == 'A test plugin'
    assert p.is_available() is True
    assert p.check_dependencies() == []


def test_base_plugin_get_plugin_info():
    cm = MagicMock()
    al = MagicMock()
    p = SimplePlugin(cm, al)
    info = p.get_plugin_info()
    assert info['name'] == 'simple_test'
    assert info['version'] == '1.0.0'
    assert 'ping' in info['commands']


def test_base_plugin_execute():
    cm = MagicMock()
    al = MagicMock()
    p = SimplePlugin(cm, al)
    assert p.execute('ping') == {'result': 'pong'}
    assert p.execute('unknown') == {'error': 'unknown'}


def test_base_plugin_log_plugin_action():
    cm = MagicMock()
    al = MagicMock()
    p = SimplePlugin(cm, al)
    p.log_plugin_action('test', {'key': 'value'})
    assert al.log_system_event.called


def test_check_dependencies_missing():
    cm = MagicMock()
    al = MagicMock()
    p = SimplePlugin(cm, al)
    p.get_required_dependencies = lambda: ['nonexistent_module_xyz']
    missing = p.check_dependencies()
    assert 'nonexistent_module_xyz' in missing
    assert p.is_available() is False


def test_check_dependencies_rejects_invalid_name():
    """Names with dangerous characters must be flagged even if 'importable'."""
    cm = MagicMock()
    al = MagicMock()
    p = SimplePlugin(cm, al)
    p.get_required_dependencies = lambda: ['os;rm -rf /', '../etc/passwd']
    missing = p.check_dependencies()
    assert 'os;rm -rf /' in missing
    assert '../etc/passwd' in missing


def test_check_dependencies_does_not_use_dunder_import():
    """Regression: verify we no longer rely on __import__() for availability checks."""
    import nebulaforge.plugins.base_plugin as bp
    src = open(bp.__file__, encoding='utf-8').read()
    assert '__import__' not in src
    assert 'importlib.util.find_spec' in src
