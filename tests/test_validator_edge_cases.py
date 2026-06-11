"""
Tests de edge cases para SecurityValidator
"""

from nebulaforge.core.security_validator import SecurityValidator


def test_validate_env_name_edge_cases():
    v = SecurityValidator()

    assert v.validate_env_name('a') is True
    assert v.validate_env_name('a' * 50) is True
    assert v.validate_env_name('a' * 51) is False
    assert v.validate_env_name('') is False
    assert v.validate_env_name(None) is False
    assert v.validate_env_name(123) is False
    assert v.validate_env_name('has spaces') is False
    assert v.validate_env_name('has/slash') is False
    assert v.validate_env_name('has_underscore') is True
    assert v.validate_env_name('has-hyphen') is True
    assert v.validate_env_name('CONDA') is False
    assert v.validate_env_name('Base') is False
    assert v.validate_env_name('ROOT') is False
    assert v.validate_env_name('System') is False
    assert v.validate_env_name('..') is False


def test_validate_package_name_edge_cases():
    v = SecurityValidator()

    assert v.validate_package_name('numpy') is True
    assert v.validate_package_name('scikit-learn') is True
    assert v.validate_package_name('numpy==1.24.0') is True
    assert v.validate_package_name('numpy>=1.20.0') is True
    assert v.validate_package_name('numpy<=1.25.0') is True
    assert v.validate_package_name('numpy>1.20.0') is True
    assert v.validate_package_name('numpy<2.0.0') is True
    assert v.validate_package_name('') is False
    assert v.validate_package_name(None) is False
    assert v.validate_package_name('  ') is False
    assert v.validate_package_name('numpy==') is False
    assert v.validate_package_name('../../../etc/passwd') is False
    assert v.validate_package_name('crack-lib') is False
    assert v.validate_package_name('hack-tool') is False
    assert v.validate_package_name('legit-package') is True


def test_validate_package_list():
    v = SecurityValidator()

    valid, invalid = v.validate_package_list(['numpy', 'pandas', 'scipy'])
    assert valid is True
    assert invalid == []

    valid, invalid = v.validate_package_list(['numpy', '', 'hack-tool'])
    assert valid is False
    assert len(invalid) == 2

    valid, invalid = v.validate_package_list([])
    assert valid is True
    assert invalid == []


def test_validate_filename():
    v = SecurityValidator()

    assert v.validate_filename('backup_env_2024.yaml') is True
    assert v.validate_filename('test.yaml') is True
    assert v.validate_filename('my-env.yml') is True
    assert v.validate_filename('/tmp/test.yaml') is False
    assert v.validate_filename('../etc/passwd') is False
    assert v.validate_filename('./test.yaml') is False
    assert v.validate_filename('') is False
    assert v.validate_filename(None) is False
    assert v.validate_filename(123) is False
    assert v.validate_filename('a' * 256) is False
