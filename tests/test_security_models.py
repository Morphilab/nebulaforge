"""
Tests para core/security_models.py
"""

from nebulaforge.core.security_models import SecurityProfile


def test_security_profile_from_dict():
    data = {
        'name': 'High Security',
        'level': 'high',
        'description': 'Strict',
        'allowed_commands': ['conda'],
        'protected_envs': ['base'],
        'max_timeout': 180,
        'require_confirmation': True,
        'enable_audit': True,
        'enable_backup': False,
        'validation_strictness': 'strict',
    }
    sp = SecurityProfile.from_dict(data)
    assert sp.name == 'High Security'
    assert sp.level == 'high'
    assert sp.max_timeout == 180
    assert sp.enable_backup is False


def test_security_profile_from_dict_defaults():
    sp = SecurityProfile.from_dict({})
    assert sp.name == ''
    assert sp.level == 'medium'
    assert sp.max_timeout == 300
    assert sp.require_confirmation is True


def test_security_profile_to_dict():
    sp = SecurityProfile(
        name='Low', level='low', description='Relaxed',
        allowed_commands=['conda', 'pip'], protected_envs=[],
        max_timeout=600, require_confirmation=False,
        enable_audit=False, enable_backup=True,
        validation_strictness='low',
    )
    d = sp.to_dict()
    assert d['name'] == 'Low'
    assert d['level'] == 'low'
    assert d['require_confirmation'] is False
