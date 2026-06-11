"""
Basic tests for NebulaForge validators
"""

from nebulaforge.core.security_validator import SecurityValidator


def test_validate_env_name():
    validator = SecurityValidator()
    
    assert validator.validate_env_name("my_env") is True
    assert validator.validate_env_name("my-env-123") is True
    assert validator.validate_env_name("base") is False      # reserved name
    assert validator.validate_env_name("root") is False
    assert validator.validate_env_name("") is False
    assert validator.validate_env_name("very_long_name_" * 10) is False


def test_validate_package_list():
    validator = SecurityValidator()
    
    # Valid case
    valid, invalid = validator.validate_package_list(["numpy", "pandas==2.0", "scikit-learn"])
    assert valid is True
    assert invalid == []

    # Invalid case
    valid, invalid = validator.validate_package_list(["numpy", "mal@package", ""])
    assert valid is False
    assert len(invalid) > 0