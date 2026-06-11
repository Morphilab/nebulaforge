"""
Tests para SecureCommandRunner
"""

from pathlib import Path
from nebulaforge.utils.command_runner import SecureCommandRunner


class FakeConfigManager:
    def get_security_profile(self):
        from nebulaforge.core.security_models import SecurityProfile
        return SecurityProfile(
            name='test', level='high', description='test',
            allowed_commands=['conda', 'pip'],
            protected_envs=['base'], max_timeout=30,
            require_confirmation=True, enable_audit=True,
            enable_backup=True, validation_strictness='high'
        )


class FakeAuditLogger:
    def log_secure_action(self, *args, **kwargs):
        pass


def test_validate_command_allows_conda():
    runner = SecureCommandRunner(FakeConfigManager(), FakeAuditLogger())
    assert runner._validate_command(['conda', 'list', '--json']) is True


def test_validate_command_rejects_unknown():
    runner = SecureCommandRunner(FakeConfigManager(), FakeAuditLogger())
    assert runner._validate_command(['rm', '-rf', '/']) is False


def test_validate_command_rejects_dangerous_chars():
    runner = SecureCommandRunner(FakeConfigManager(), FakeAuditLogger())
    assert runner._validate_command(['conda', 'install', 'numpy; rm -rf /']) is False
    assert runner._validate_command(['conda', 'install', '../malicious']) is False
    assert runner._validate_command(['pip', 'install', '$(whoami)']) is False


def test_validate_command_allows_safe_args():
    runner = SecureCommandRunner(FakeConfigManager(), FakeAuditLogger())
    assert runner._validate_command(['conda', 'install', '-n', 'myenv', 'numpy']) is True
    assert runner._validate_command(['pip', 'install', 'requests==2.31.0']) is True


def test_refresh_profile_updates():
    runner = SecureCommandRunner(FakeConfigManager(), FakeAuditLogger())
    original_timeout = runner.security_profile.max_timeout
    runner.refresh_profile()
    assert runner.security_profile.max_timeout == original_timeout
