"""
Basic CLI tests
"""

from types import SimpleNamespace
from unittest.mock import patch

from nebulaforge.core.environment_service import ServiceResult
from nebulaforge.interfaces.cli import NebulaForgeCLI


def _make_cli():
    with patch('nebulaforge.interfaces.cli.EnvironmentService') as mock_service:
        cli = NebulaForgeCLI(production_mode=False)
        cli.svc = mock_service.return_value
        return cli


def test_cli_initialization(tmp_path, monkeypatch):
    monkeypatch.setattr('pathlib.Path.home', lambda: tmp_path)
    cli = NebulaForgeCLI(production_mode=False)
    assert cli is not None
    assert hasattr(cli, 'parser')


def test_argparse_errors_return_non_zero_exit_code():
    cli = _make_cli()
    assert cli.run_from_args(['remove']) == 2


def test_handle_remove_production_mode_returns_2():
    cli = _make_cli()
    cli.svc.delete_environment.return_value = ServiceResult(
        False, "Cannot delete environments in production mode"
    )
    args = SimpleNamespace(environment='myenv', no_backup=False)
    assert cli.handle_remove(args) == 2


def test_handle_install_passes_conflict_check_flag():
    cli = _make_cli()
    cli.svc.validate_env_name.return_value = True
    cli.svc.validate_packages.return_value = ServiceResult(True, "")
    cli.svc.install_packages.return_value = ServiceResult(True, "Installed")
    args = SimpleNamespace(
        environment='myenv', packages=['numpy'], no_conflict_check=True
    )

    assert cli.handle_install(args) == 0
    cli.svc.install_packages.assert_called_once_with(
        'myenv', ['numpy'], conflict_check=False, confirmed=False
    )


def test_handle_backup_list_uses_service():
    cli = _make_cli()
    cli.svc.list_backups.return_value = ServiceResult(
        True, "1 backups found", [{'env_name': 'myenv'}]
    )
    args = SimpleNamespace(create=None, list=True, restore=None)

    assert cli.handle_backup(args) == 0
    cli.svc.list_backups.assert_called_once_with()


def test_handle_backup_restore_uses_service():
    cli = _make_cli()
    cli.svc.restore_backup.return_value = ServiceResult(True, "Restored")
    args = SimpleNamespace(create=None, list=False, restore='backup.yaml')

    assert cli.handle_backup(args) == 0
    cli.svc.restore_backup.assert_called_once_with('backup.yaml', confirmed=False)


def test_handle_backup_requires_action():
    cli = _make_cli()
    args = SimpleNamespace(create=None, list=False, restore=None)
    assert cli.handle_backup(args) == 1


def test_handle_config_production_mode():
    cli = _make_cli()
    cli.svc.set_production_mode.return_value = ServiceResult(
        True, "Production mode disabled"
    )
    args = SimpleNamespace(security_level=None, production_mode='off')

    assert cli.handle_config(args) == 0
    cli.svc.set_production_mode.assert_called_once_with(False)


def test_handle_config_requires_option():
    cli = _make_cli()
    args = SimpleNamespace(security_level=None, production_mode=None)
    assert cli.handle_config(args) == 1


def test_handle_install_confirmation_required_returns_2():
    cli = _make_cli()
    cli.svc.validate_env_name.return_value = True
    cli.svc.validate_packages.return_value = ServiceResult(True, "")
    cli.svc.install_packages.return_value = ServiceResult(
        False, "Confirmation required to modify 'myenv'"
    )
    args = SimpleNamespace(
        environment='myenv', packages=['numpy'], no_conflict_check=False, yes=False
    )
    assert cli.handle_install(args) == 2
    cli.svc.install_packages.assert_called_once_with(
        'myenv', ['numpy'], conflict_check=True, confirmed=False
    )


def test_handle_install_yes_confirms():
    cli = _make_cli()
    cli.svc.validate_env_name.return_value = True
    cli.svc.validate_packages.return_value = ServiceResult(True, "")
    cli.svc.install_packages.return_value = ServiceResult(True, "Installed")
    args = SimpleNamespace(
        environment='myenv', packages=['numpy'], no_conflict_check=False, yes=True
    )
    assert cli.handle_install(args) == 0
    cli.svc.install_packages.assert_called_once_with(
        'myenv', ['numpy'], conflict_check=True, confirmed=True
    )


def test_handle_create_policy_block_returns_2():
    cli = _make_cli()
    cli.svc.validate_env_name.return_value = True
    cli.svc.create_environment.return_value = ServiceResult(
        False, "Cannot create environments in production mode"
    )
    args = SimpleNamespace(name='myenv', python=None, packages=None, yes=True)
    assert cli.handle_create(args) == 2
    cli.svc.create_environment.assert_called_once_with(
        'myenv', '3.9', None, confirmed=True
    )


def test_handle_backup_restore_yes_confirms():
    cli = _make_cli()
    cli.svc.restore_backup.return_value = ServiceResult(True, "Restored")
    args = SimpleNamespace(create=None, list=False, restore='backup.yaml', yes=True)
    assert cli.handle_backup(args) == 0
    cli.svc.restore_backup.assert_called_once_with('backup.yaml', confirmed=True)
