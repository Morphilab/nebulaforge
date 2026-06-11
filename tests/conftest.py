"""
NebulaForge - Shared test fixtures
"""

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock

from nebulaforge.core.security_models import SecurityProfile


@pytest.fixture
def temp_home(tmp_path, monkeypatch):
    """Redirect Path.home() to a temporary directory"""
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    return tmp_path


@pytest.fixture
def mock_config_manager():
    """ConfigManager mock with common defaults"""
    cm = MagicMock()
    cm.get.side_effect = lambda key, default=None: {
        'core.production_mode': False,
        'core.max_command_timeout': 300,
        'security.security_level': 'medium',
        'security.enable_audit': True,
        'security.enable_backup': True,
        'security.backup_retention_days': 30,
        'paths.backup_dir': '~/.nebulaforge/backups',
        'paths.log_dir': '~/.nebulaforge/logs',
        'paths.secure_data_dir': '~/.nebulaforge/data',
    }.get(key, default)
    cm.security_profiles = {'low': {}, 'medium': {}, 'high': {}, 'paranoid': {}}
    cm.get_security_profile.return_value = SecurityProfile(
        name='Medium Security', level='medium', description='Test profile',
        allowed_commands=['conda', 'mamba', 'pip'],
        protected_envs=['base', 'root'],
        max_timeout=300, require_confirmation=True,
        enable_audit=True, enable_backup=True, validation_strictness='medium',
    )
    cm.get_secure_path.return_value = MagicMock()
    return cm


@pytest.fixture
def mock_audit_logger():
    """AuditLogger mock"""
    al = MagicMock()
    return al


@pytest.fixture
def mock_command_runner():
    """SecureCommandRunner mock"""
    cr = MagicMock()
    return cr


@pytest.fixture
def sample_packages_json():
    """Sample conda package list in JSON"""
    return json.dumps([
        {"name": "python", "version": "3.10.0", "build_string": "h123"},
        {"name": "numpy", "version": "1.26.0", "build_string": "h456"},
        {"name": "pandas", "version": "2.0.0", "build_string": "h789"},
    ])


@pytest.fixture
def sample_envs_json():
    """Sample conda environment list in JSON"""
    return json.dumps({
        "envs": ["/opt/conda/envs/test_env", "/opt/conda/envs/dev_env"]
    })
