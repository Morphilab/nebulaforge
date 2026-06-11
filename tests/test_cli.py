"""
Basic CLI tests
"""

from pathlib import Path
from nebulaforge.interfaces.cli import NebulaForgeCLI
from nebulaforge.core.security_manager import SecurityManager


def test_cli_initialization(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    config_path = tmp_path / '.nebulaforge' / 'config' / 'config.yaml'
    sm = SecurityManager(config_path=config_path, production_mode=False)
    cli = NebulaForgeCLI(sm)
    assert cli is not None
    assert hasattr(cli, 'parser')
