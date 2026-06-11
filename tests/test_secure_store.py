"""
Tests para core/secure_store.py
"""

import time
from pathlib import Path

from nebulaforge.core.secure_store import SecureStore


def test_put_and_get(tmp_path):
    store_path = tmp_path / 'store.enc'
    ss = SecureStore(store_path, 'mypassword')
    ss.put('api_key', 'sk-abc123')
    assert ss.get('api_key') == 'sk-abc123'


def test_get_nonexistent(tmp_path):
    store_path = tmp_path / 'store.enc'
    ss = SecureStore(store_path, 'mypassword')
    assert ss.get('nonexistent') is None


def test_delete(tmp_path):
    store_path = tmp_path / 'store.enc'
    ss = SecureStore(store_path, 'mypassword')
    ss.put('key1', 'value1')
    assert ss.delete('key1') is True
    assert ss.get('key1') is None
    assert ss.delete('key1') is False


def test_exists(tmp_path):
    store_path = tmp_path / 'store.enc'
    ss = SecureStore(store_path, 'mypassword')
    ss.put('key1', 'value1')
    assert ss.exists('key1') is True
    assert ss.exists('key2') is False


def test_keys(tmp_path):
    store_path = tmp_path / 'store.enc'
    ss = SecureStore(store_path, 'mypassword')
    ss.put('a', 1)
    ss.put('b', 2)
    assert set(ss.keys()) == {'a', 'b'}


def test_clear(tmp_path):
    store_path = tmp_path / 'store.enc'
    ss = SecureStore(store_path, 'mypassword')
    ss.put('a', 1)
    ss.put('b', 2)
    ss.clear()
    assert ss.keys() == []


def test_ttl_expiry(tmp_path):
    store_path = tmp_path / 'store.enc'
    ss = SecureStore(store_path, 'mypassword')
    ss.put('temp', 'value', ttl_seconds=1)
    assert ss.get('temp') == 'value'
    time.sleep(1.1)
    assert ss.get('temp') is None


def test_complex_value(tmp_path):
    store_path = tmp_path / 'store.enc'
    ss = SecureStore(store_path, 'mypassword')
    data = {'nested': {'list': [1, 2, 3]}, 'bool': True, 'number': 42}
    ss.put('complex', data)
    assert ss.get('complex') == data


def test_wrong_password_fails(tmp_path):
    store_path = tmp_path / 'store.enc'
    ss = SecureStore(store_path, 'rightpass')
    ss.put('key', 'value')
    ss_wrong = SecureStore(store_path, 'wrongpass')
    from cryptography.fernet import InvalidToken
    import pytest
    with pytest.raises(InvalidToken):
        ss_wrong.get('key')


def test_is_locked(tmp_path):
    store_path = tmp_path / 'store.enc'
    ss = SecureStore(store_path)
    assert ss.is_locked() is True
    ss.unlock('mypassword')
    assert ss.is_locked() is False


def test_unlock_and_put(tmp_path):
    store_path = tmp_path / 'store.enc'
    ss = SecureStore(store_path)
    ss.unlock('mypassword')
    ss.put('key', 'value')
    assert ss.get('key') == 'value'
