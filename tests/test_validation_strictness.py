"""
Tests for the validation_strictness-aware SecurityValidator.

These tests verify that the validator adjusts its env-name, package-name,
filename, reserved-keyword, and dangerous-keyword behavior based on the
profile's validation_strictness field.
"""
import pytest

from nebulaforge.core.security_models import SecurityProfile
from nebulaforge.core.security_validator import SecurityValidator


def _make_validator(strictness: str) -> SecurityValidator:
    profile = SecurityProfile(
        name=f"test-{strictness}",
        level=strictness,
        description="test",
        allowed_commands=["conda"],
        protected_envs=["base"],
        max_timeout=300,
        require_confirmation=True,
        enable_audit=True,
        enable_backup=True,
        validation_strictness=strictness,
    )
    return SecurityValidator(profile=profile)


@pytest.mark.parametrize("strictness", ["low", "medium", "high", "paranoid"])
def test_basic_valid_env_name(strictness):
    v = _make_validator(strictness)
    assert v.validate_env_name("my-env_1") is True


def test_paranoid_rejects_env_starting_with_digit():
    v = _make_validator("paranoid")
    assert v.validate_env_name("1env") is False
    assert v.validate_env_name("env") is False  # too short
    assert v.validate_env_name("good-env") is True


def test_low_accepts_dot_in_env_name():
    v = _make_validator("low")
    assert v.validate_env_name("env.with.dots") is True


def test_medium_rejects_dot_in_env_name():
    v = _make_validator("medium")
    assert v.validate_env_name("env.with.dots") is False


def test_paranoid_blocks_more_dangerous_keywords():
    v_paranoid = _make_validator("paranoid")
    v_low = _make_validator("low")
    v_medium = _make_validator("medium")
    # Both medium and paranoid block the core malware set
    assert v_medium.validate_package_name("malware-tool") is False
    assert v_paranoid.validate_package_name("malware-tool") is False
    # Only paranoid (and high) block the extended set
    assert v_low.validate_package_name("keylogger") is True
    assert v_paranoid.validate_package_name("keylogger") is False


def test_medium_strictness_keywords():
    v = _make_validator("medium")
    assert v.validate_package_name("exploit-kit") is False
    assert v.validate_package_name("keylogger") is True


def test_high_strictness_keywords():
    v = _make_validator("high")
    assert v.validate_package_name("keylogger") is False
    assert v.validate_package_name("rootkit") is False


def test_filename_strictness():
    v_low = _make_validator("low")
    v_paranoid = _make_validator("paranoid")
    # Spaces are allowed at low but not paranoid
    assert v_low.validate_filename("file name.yaml") is True
    assert v_paranoid.validate_filename("file name.yaml") is False
    # Paranoid requires starting with alphanumeric
    assert v_paranoid.validate_filename(".hidden.yaml") is False
    assert v_low.validate_filename(".hidden.yaml") is True


def test_reserved_envs_expand_with_strictness():
    v_low = _make_validator("low")
    v_medium = _make_validator("medium")
    v_high = _make_validator("high")
    v_paranoid = _make_validator("paranoid")
    assert v_low.validate_env_name("system") is True
    assert v_medium.validate_env_name("system") is False
    assert v_high.validate_env_name("prod") is False
    assert v_paranoid.validate_env_name("venv") is False


def test_unknown_strictness_falls_back_to_medium():
    v = SecurityValidator(
        profile=SecurityProfile(
            name="x", level="custom", description="",
            allowed_commands=[], protected_envs=[],
            max_timeout=300, require_confirmation=True,
            enable_audit=True, enable_backup=True,
            validation_strictness="nonexistent",
        )
    )
    # Should behave like medium (default fallback)
    assert v.validate_env_name("env.with.dots") is False
    assert v.validate_package_name("exploit") is False
