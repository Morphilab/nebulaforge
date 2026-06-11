"""
Tests for utils/helpers.py
"""

from nebulaforge.utils.helpers import SecurityHelper


def test_generate_secure_hash():
    h = SecurityHelper.generate_secure_hash('hello')
    assert len(h) == 64
    assert isinstance(h, str)


def test_generate_secure_hash_deterministic():
    h1 = SecurityHelper.generate_secure_hash('test')
    h2 = SecurityHelper.generate_secure_hash('test')
    assert h1 == h2


def test_generate_secure_hash_different():
    h1 = SecurityHelper.generate_secure_hash('abc')
    h2 = SecurityHelper.generate_secure_hash('xyz')
    assert h1 != h2


def test_get_system_info():
    info = SecurityHelper.get_system_info()
    assert 'platform' in info
    assert 'python_version' in info
    assert 'architecture' in info
