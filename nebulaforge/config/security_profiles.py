"""
NebulaForge - Security profiles
"""

# protected_envs guards operations on existing environments (confirmation
# required; delete/modify blocked). Blocking reserved names at creation time
# is a separate mechanism: SecurityValidator._STRICTNESS_RESERVED_ENVS.
SECURITY_PROFILES = {
    'low': {
        'name': 'Low Security',
        'level': 'low',
        'description': 'Maximum compatibility',
        'allowed_commands': ['conda', 'mamba', 'pip'],
        'protected_envs': ['base', 'root'],
        'max_timeout': 600,
        'require_confirmation': False,
        'enable_audit': True,
        'enable_backup': True,
        'validation_strictness': 'low'
    },
    'medium': {
        'name': 'Medium Security',
        'level': 'medium',
        'description': 'Recommended balance',
        'allowed_commands': ['conda', 'mamba', 'pip'],
        'protected_envs': ['base', 'root', 'prod'],
        'max_timeout': 300,
        'require_confirmation': True,
        'enable_audit': True,
        'enable_backup': True,
        'validation_strictness': 'medium'
    },
    'high': {
        'name': 'High Security',
        'level': 'high',
        'description': 'High protection',
        'allowed_commands': ['conda', 'mamba'],
        'protected_envs': ['base', 'root', 'prod'],
        'max_timeout': 180,
        'require_confirmation': True,
        'enable_audit': True,
        'enable_backup': True,
        'validation_strictness': 'high'
    },
    'paranoid': {
        'name': 'Paranoid Security',
        'level': 'paranoid',
        'description': 'Maximum security',
        'allowed_commands': ['conda'],
        'protected_envs': ['base', 'root', 'prod'],
        'max_timeout': 120,
        'require_confirmation': True,
        'enable_audit': True,
        'enable_backup': True,
        'validation_strictness': 'paranoid'
    }
}


def list_available_profiles():
    return list(SECURITY_PROFILES.keys())
