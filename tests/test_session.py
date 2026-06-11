"""
Tests para core/session.py
"""

import time
from nebulaforge.core.session import SessionManager


def test_create_session():
    sm = SessionManager()
    session = sm.create_session({'user': 'alice'})
    assert session.token is not None
    assert len(session.token) > 20


def test_get_valid_session():
    sm = SessionManager()
    s = sm.create_session({'user': 'alice'})
    retrieved = sm.get_session(s.token)
    assert retrieved is not None
    assert retrieved.data == {'user': 'alice'}


def test_get_invalid_session():
    sm = SessionManager()
    assert sm.get_session('nonexistent') is None


def test_invalidate_session():
    sm = SessionManager()
    s = sm.create_session()
    assert sm.invalidate_session(s.token) is True
    assert sm.get_session(s.token) is None


def test_invalidate_twice():
    sm = SessionManager()
    s = sm.create_session()
    assert sm.invalidate_session(s.token) is True
    assert sm.invalidate_session(s.token) is False


def test_expired_session():
    sm = SessionManager(session_ttl=0)
    s = sm.create_session()
    time.sleep(0.01)
    assert sm.get_session(s.token) is None


def test_refresh_session():
    sm = SessionManager(session_ttl=3600)
    s = sm.create_session()
    original_expiry = s.expires_at
    refreshed = sm.refresh_session(s.token)
    assert refreshed is not None
    assert refreshed.expires_at > original_expiry


def test_get_active_sessions():
    sm = SessionManager()
    sm.create_session({'user': 'alice'})
    sm.create_session({'user': 'bob'})
    active = sm.get_active_sessions()
    assert len(active) == 2


def test_invalidate_all():
    sm = SessionManager()
    sm.create_session()
    sm.create_session()
    assert sm.invalidate_all() == 2
    assert len(sm.get_active_sessions()) == 0


def test_max_sessions():
    sm = SessionManager(max_sessions=3)
    for i in range(5):
        sm.create_session({'i': i})
    assert len(sm.get_active_sessions()) <= 3


def test_session_token_unique():
    sm = SessionManager()
    tokens = {sm.create_session().token for _ in range(100)}
    assert len(tokens) == 100


def test_mask_token():
    sm = SessionManager()
    s = sm.create_session()
    active = sm.get_active_sessions()
    masked = active[0]['token']
    assert masked.startswith('ses_')
    assert masked.endswith('...')
    assert len(masked) == 19
