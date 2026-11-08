"""
Real-Conda integration smoke test.

This test is skipped by default and only runs when the operator explicitly
opts in with NEBULAFORGE_RUN_CONDA_INTEGRATION=1. It creates a disposable
environment under isolated CONDA_ENVS_PATH / CONDA_PKGS_DIRS directories and
exercises the real service flow: import -> list -> backup -> restore -> delete.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Iterator, List

import pytest

from nebulaforge.core.environment_service import EnvironmentService

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which('conda') is None, reason='conda is not available'),
    pytest.mark.skipif(
        not os.environ.get('NEBULAFORGE_RUN_CONDA_INTEGRATION'),
        reason='set NEBULAFORGE_RUN_CONDA_INTEGRATION=1 to run real-Conda tests',
    ),
]


@pytest.fixture
def isolated_conda(tmp_path, monkeypatch) -> Iterator[None]:
    envs_dir = tmp_path / 'conda_envs'
    pkgs_dir = tmp_path / 'conda_pkgs'
    envs_dir.mkdir()
    pkgs_dir.mkdir()
    monkeypatch.setenv('CONDA_ENVS_PATH', str(envs_dir))
    monkeypatch.setenv('CONDA_PKGS_DIRS', str(pkgs_dir))
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    yield


def _conda_env_names() -> List[str]:
    result = subprocess.run(
        ['conda', 'env', 'list', '--json'],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        return []
    try:
        return [Path(p).name for p in json.loads(result.stdout).get('envs', [])]
    except json.JSONDecodeError:
        return []


def _remove_env(name: str) -> None:
    subprocess.run(
        ['conda', 'env', 'remove', '-n', name, '-y'],
        capture_output=True, text=True, check=False,
    )


def _cleanup_test_environments(name: str) -> None:
    for env_name in _conda_env_names():
        if env_name == name or env_name.startswith(('nf_restore_', 'nf_quarantine_')):
            _remove_env(env_name)


def test_real_conda_import_backup_restore_delete(isolated_conda, tmp_path):
    env_name = f"nf_it_{uuid.uuid4().hex[:8]}"
    service = EnvironmentService(production_mode=False)
    backup_dir = service.sm.config_manager.get_secure_path('paths.backup_dir')
    imported_yaml = backup_dir / f"{env_name}.yaml"

    try:
        imported_yaml.write_text(
            f"name: {env_name}\nchannels: []\ndependencies: []\n",
            encoding='utf-8',
        )

        imported = service.import_environment(imported_yaml, env_name, confirmed=True)
        assert imported.success, imported.message

        listed = service.list_environments()
        assert listed.success, listed.message
        assert env_name in (listed.data or [])

        backed_up = service.create_backup(env_name, "integration smoke test")
        assert backed_up.success, backed_up.message

        backup_files = sorted(backup_dir.glob(f"backup_{env_name}_*.yaml"))
        assert backup_files, "expected at least one backup file"

        restored = service.restore_backup(
            str(backup_files[-1]), env_name, confirmed=True
        )
        assert restored.success, restored.message

        listed_after_restore = service.list_environments()
        assert listed_after_restore.success
        assert env_name in (listed_after_restore.data or [])

        removed = service.delete_environment(env_name, create_backup=False, confirmed=True)
        assert removed.success, removed.message

    finally:
        _cleanup_test_environments(env_name)
        imported_yaml.unlink(missing_ok=True)
