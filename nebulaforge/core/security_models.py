"""
Typed data models for security profiles
"""

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class SecurityProfile:
    """Modelo tipado para perfiles de seguridad"""
    name: str
    level: str
    description: str
    allowed_commands: List[str]
    protected_envs: List[str]
    max_timeout: int
    require_confirmation: bool
    enable_audit: bool
    enable_backup: bool
    validation_strictness: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityProfile':
        """Crear instancia desde diccionario"""
        return cls(
            name=data.get('name', ''),
            level=data.get('level', 'medium'),
            description=data.get('description', ''),
            allowed_commands=data.get('allowed_commands', []),
            protected_envs=data.get('protected_envs', []),
            max_timeout=data.get('max_timeout', 300),
            require_confirmation=data.get('require_confirmation', True),
            enable_audit=data.get('enable_audit', True),
            enable_backup=data.get('enable_backup', True),
            validation_strictness=data.get('validation_strictness', 'medium')
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convertir a diccionario"""
        return {
            'name': self.name,
            'level': self.level,
            'description': self.description,
            'allowed_commands': self.allowed_commands,
            'protected_envs': self.protected_envs,
            'max_timeout': self.max_timeout,
            'require_confirmation': self.require_confirmation,
            'enable_audit': self.enable_audit,
            'enable_backup': self.enable_backup,
            'validation_strictness': self.validation_strictness
        }



