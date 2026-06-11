"""
Tests para ConfigManager
"""

from pathlib import Path


def test_config_default_values(tmp_path):
    monkeypatch = __import__('pytest').MonkeyPatch()
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)

    from nebulaforge.core.config_manager import ConfigManager
    config_path = tmp_path / '.nebulaforge' / 'config' / 'config.yaml'
    cm = ConfigManager(config_path=config_path)

    assert cm.get('core.production_mode') is True
    assert cm.get('security.security_level') == 'medium'
    assert cm.get('nonexistent.key', 'default') == 'default'


def test_config_set_and_get(tmp_path):
    monkeypatch = __import__('pytest').MonkeyPatch()
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)

    from nebulaforge.core.config_manager import ConfigManager
    config_path = tmp_path / '.nebulaforge' / 'config' / 'config.yaml'
    cm = ConfigManager(config_path=config_path)

    cm.set('security.security_level', 'high')
    assert cm.get('security.security_level') == 'high'


def test_security_profile_from_config(tmp_path):
    monkeypatch = __import__('pytest').MonkeyPatch()
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)

    from nebulaforge.core.config_manager import ConfigManager
    config_path = tmp_path / '.nebulaforge' / 'config' / 'config.yaml'
    cm = ConfigManager(config_path=config_path)

    profile = cm.get_security_profile('paranoid')
    assert profile.name == 'Paranoid Security'
    assert profile.level == 'paranoid'
    assert profile.allowed_commands == ['conda']
    assert profile.require_confirmation is True


def test_merge_configs_user_overrides_default(tmp_path):
    monkeypatch = __import__('pytest').MonkeyPatch()
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)

    from nebulaforge.core.config_manager import ConfigManager
    config_path = tmp_path / '.nebulaforge' / 'config' / 'config.yaml'
    cm = ConfigManager(config_path=config_path)

    cm.set('core.max_command_timeout', 600)
    assert cm.get('core.max_command_timeout') == 600
    assert cm.get('core.production_mode') is True
