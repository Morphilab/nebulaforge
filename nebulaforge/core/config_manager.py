"""
NebulaForge - Centralized configuration manager

"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from nebulaforge.config.security_profiles import SECURITY_PROFILES
from nebulaforge.core.security_models import SecurityProfile


class ConfigManager:
    """Centralized configuration manager"""

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or self._get_default_config_path()
        self.config = self._load_config()
        self.security_profiles = SECURITY_PROFILES

    def _get_default_config_path(self) -> Path:
        config_dir = Path.home() / ".nebulaforge" / "config"
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir / "config.yaml"

    def _load_config(self) -> Dict[str, Any]:
        default = self._get_default_config()
        if self.config_path.exists():
            try:
                with open(self.config_path, encoding='utf-8') as f:
                    user_config = yaml.safe_load(f) or {}
                return self._merge_configs(default, user_config)
            except Exception:
                return default
        else:
            self._save_config(default)
            return default

    def _get_default_config(self) -> Dict[str, Any]:
        return {
            'core': {'production_mode': True, 'max_command_timeout': 300},
            'security': {
                'security_level': 'medium',
                'require_confirmation': True,
                'enable_audit_logging': True,
            },
            'paths': {
                'secure_base_dir': '~/.nebulaforge',
                'backup_dir': '~/.nebulaforge/backups',
                'log_dir': '~/.nebulaforge/logs',
                'config_dir': '~/.nebulaforge/config',
                'secure_data_dir': '~/.nebulaforge/data'
            }
        }

    def _merge_configs(self, default: Dict, user: Dict) -> Dict:
        merged = default.copy()
        for k, v in user.items():
            if isinstance(v, dict) and k in merged and isinstance(merged[k], dict):
                merged[k] = self._merge_configs(merged[k], v)
            else:
                merged[k] = v
        return merged

    def _save_config(self, config: Dict) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)

    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split('.')
        value = self.config
        try:
            for k in keys:
                value = value[k]
            return value
        except Exception:
            return default

    def set(self, key: str, value: Any) -> None:
        keys = key.split('.')
        config = self.config
        for k in keys[:-1]:
            config.setdefault(k, {})
            config = config[k]
        config[keys[-1]] = value
        self._save_config(self.config)

    def get_security_profile(self, level: Optional[str] = None) -> SecurityProfile:
        profile_name = level or self.get('security.security_level', 'medium')
        data: Dict[str, Any] = self.security_profiles.get(profile_name, self.security_profiles['medium'])
        return SecurityProfile(**data)

    def initialize_secure_directories(self) -> None:
        directories = [
            Path(self.get('paths.secure_base_dir', '~/.nebulaforge')).expanduser(),
            Path(self.get('paths.backup_dir', '~/.nebulaforge/backups')).expanduser(),
            Path(self.get('paths.log_dir', '~/.nebulaforge/logs')).expanduser(),
            Path(self.get('paths.config_dir', '~/.nebulaforge/config')).expanduser(),
            Path(self.get('paths.secure_data_dir', '~/.nebulaforge/data')).expanduser()
        ]
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            try:
                directory.chmod(0o700)
            except Exception:
                pass

    def get_secure_path(self, path_key: str) -> Path:
        path_str = self.get(path_key, '')
        path = Path(path_str).expanduser()
        path.mkdir(parents=True, exist_ok=True)
        return path
