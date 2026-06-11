"""
Tests para core/secrets.py
"""

import json
from pathlib import Path

from nebulaforge.core.secrets import SecureCredentials


def test_store_and_retrieve(tmp_path):
    store_path = tmp_path / 'creds.enc'
    sc = SecureCredentials(store_path, 'mypassword')
    sc.store('pypi', {'username': 'alice', 'password': 'secret123'})
    result = sc.retrieve('pypi')
    assert result == {'username': 'alice', 'password': 'secret123'}


def test_retrieve_nonexistent(tmp_path):
    store_path = tmp_path / 'creds.enc'
    sc = SecureCredentials(store_path, 'mypassword')
    assert sc.retrieve('nonexistent') is None


def test_list_services(tmp_path):
    store_path = tmp_path / 'creds.enc'
    sc = SecureCredentials(store_path, 'mypassword')
    sc.store('pypi', {'username': 'alice', 'password': 'secret'})
    sc.store('conda', {'username': 'bob', 'token': 'abc123'})
    services = sc.list_services()
    assert set(services) == {'pypi', 'conda'}


def test_delete_service(tmp_path):
    store_path = tmp_path / 'creds.enc'
    sc = SecureCredentials(store_path, 'mypassword')
    sc.store('pypi', {'username': 'alice', 'password': 'secret'})
    assert sc.delete('pypi') is True
    assert sc.retrieve('pypi') is None
    assert sc.delete('pypi') is False


def test_change_master_password(tmp_path):
    store_path = tmp_path / 'creds.enc'
    sc = SecureCredentials(store_path, 'oldpass')
    sc.store('pypi', {'username': 'alice', 'password': 'secret'})
    sc.store('conda', {'username': 'bob', 'token': 'abc123'})
    sc.change_master_password('oldpass', 'newpass')
    sc2 = SecureCredentials(store_path, 'newpass')
    assert sc2.retrieve('pypi') == {'username': 'alice', 'password': 'secret'}
    assert sc2.retrieve('conda') == {'username': 'bob', 'token': 'abc123'}


def test_different_passwords_fail(tmp_path):
    store_path = tmp_path / 'creds.enc'
    sc = SecureCredentials(store_path, 'rightpass')
    sc.store('pypi', {'username': 'alice', 'password': 'secret'})
    sc_wrong = SecureCredentials(store_path, 'wrongpass')
    from cryptography.fernet import InvalidToken
    import pytest
    with pytest.raises(InvalidToken):
        sc_wrong.retrieve('pypi')


def test_has_password(tmp_path):
    store_path = tmp_path / 'creds.enc'
    sc = SecureCredentials(store_path)
    assert sc.has_password() is False
    sc.set_password('mypassword')
    assert sc.has_password() is True


def test_no_password_raises(tmp_path):
    store_path = tmp_path / 'creds.enc'
    sc = SecureCredentials(store_path)
    import pytest
    with pytest.raises(RuntimeError, match='Master password not set'):
        sc.store('test', {'key': 'value'})
