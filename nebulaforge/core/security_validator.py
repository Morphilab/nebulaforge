"""
NebulaForge - Central security validator

"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from nebulaforge.core.security_models import SecurityProfile

_LOW_DANGEROUS_KEYWORDS: set = set()
_MEDIUM_DANGEROUS_KEYWORDS = {
    'crack', 'hack', 'exploit', 'backdoor', 'virus',
    'malware', 'keygen', 'trojan', 'spyware',
}
_HIGH_DANGEROUS_KEYWORDS = _MEDIUM_DANGEROUS_KEYWORDS | {
    'crackme', 'warez', 'pirate', 'stealer', 'logger',
    'injector', 'ransomware', 'keylogger', 'rootkit',
}
_PARANOID_DANGEROUS_KEYWORDS = _HIGH_DANGEROUS_KEYWORDS | {
    'serial', 'patch', 'loader', 'activator', 'bypass',
    'cracktool', 'exploitkit', 'shellcode', 'payload',
}

_STRICTNESS_KEYWORDS = {
    'low': _LOW_DANGEROUS_KEYWORDS,
    'medium': _MEDIUM_DANGEROUS_KEYWORDS,
    'high': _HIGH_DANGEROUS_KEYWORDS,
    'paranoid': _PARANOID_DANGEROUS_KEYWORDS,
}

_LOW_ENV_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_.\-]{1,128}$')
_MEDIUM_ENV_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,50}$')
_HIGH_ENV_NAME_PATTERN = _MEDIUM_ENV_NAME_PATTERN
_PARANOID_ENV_NAME_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]{2,49}$')

_LOW_PACKAGE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9._+\-]+$')
_MEDIUM_PACKAGE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9._\-]+$')
_HIGH_PACKAGE_NAME_PATTERN = _MEDIUM_PACKAGE_NAME_PATTERN
_PARANOID_PACKAGE_NAME_PATTERN = re.compile(r'^[a-z][a-z0-9\-]{1,63}$')

_LOW_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9._\- ]{1,255}$')
_MEDIUM_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9._\-]{1,255}$')
_HIGH_FILENAME_PATTERN = _MEDIUM_FILENAME_PATTERN
_PARANOID_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._\-]{0,254}$')

_STRICTNESS_ENV_PATTERNS = {
    'low': _LOW_ENV_NAME_PATTERN,
    'medium': _MEDIUM_ENV_NAME_PATTERN,
    'high': _HIGH_ENV_NAME_PATTERN,
    'paranoid': _PARANOID_ENV_NAME_PATTERN,
}
_STRICTNESS_PACKAGE_PATTERNS = {
    'low': _LOW_PACKAGE_NAME_PATTERN,
    'medium': _MEDIUM_PACKAGE_NAME_PATTERN,
    'high': _HIGH_PACKAGE_NAME_PATTERN,
    'paranoid': _PARANOID_PACKAGE_NAME_PATTERN,
}
_STRICTNESS_FILENAME_PATTERNS = {
    'low': _LOW_FILENAME_PATTERN,
    'medium': _MEDIUM_FILENAME_PATTERN,
    'high': _HIGH_FILENAME_PATTERN,
    'paranoid': _PARANOID_FILENAME_PATTERN,
}
_STRICTNESS_RESERVED_ENVS = {
    'low': {'base', 'root'},
    'medium': {'base', 'root', 'system', 'conda'},
    'high': {'base', 'root', 'system', 'conda', 'prod'},
    'paranoid': {'base', 'root', 'system', 'conda', 'prod', 'env', 'venv'},
}


class SecurityValidator:
    """Central security validator for NebulaForge"""

    ENV_NAME_PATTERN = _MEDIUM_ENV_NAME_PATTERN
    PACKAGE_NAME_PATTERN = _MEDIUM_PACKAGE_NAME_PATTERN
    ALLOWED_FILENAME_PATTERN = _MEDIUM_FILENAME_PATTERN

    def __init__(self, config_manager=None, audit_logger=None, profile: Optional[SecurityProfile] = None):
        self.config_manager = config_manager
        self.audit_logger = audit_logger
        self.profile = profile

    def _strictness(self) -> str:
        if self.profile is None and self.config_manager is not None:
            try:
                profile_name = self.config_manager.get('security.security_level', 'medium')
                self.profile = self.config_manager.get_security_profile(profile_name)
            except Exception:
                self.profile = None
        if self.profile is not None:
            return getattr(self.profile, 'validation_strictness', None) or self.profile.level or 'medium'
        return 'medium'

    def _env_pattern(self):
        return _STRICTNESS_ENV_PATTERNS.get(self._strictness(), _MEDIUM_ENV_NAME_PATTERN)

    def _package_pattern(self):
        return _STRICTNESS_PACKAGE_PATTERNS.get(self._strictness(), _MEDIUM_PACKAGE_NAME_PATTERN)

    def _filename_pattern(self):
        return _STRICTNESS_FILENAME_PATTERNS.get(self._strictness(), _MEDIUM_FILENAME_PATTERN)

    def _reserved_envs(self) -> set:
        return _STRICTNESS_RESERVED_ENVS.get(self._strictness(), _STRICTNESS_RESERVED_ENVS['medium'])

    def _dangerous_keywords(self) -> set:
        return _STRICTNESS_KEYWORDS.get(self._strictness(), _MEDIUM_DANGEROUS_KEYWORDS)

    def validate_env_name(self, env_name: str) -> bool:
        if not env_name or not isinstance(env_name, str):
            return False
        if not self._env_pattern().match(env_name):
            return False
        if env_name.lower() in self._reserved_envs():
            return False
        return True

    def validate_package_name(self, package_spec: str) -> bool:
        """Validate package name with optional version specifier (==, >=, <=, etc.)"""
        if not package_spec or not isinstance(package_spec, str):
            return False

        spec = package_spec.strip()
        if not spec:
            return False

        match = re.match(r'^([a-zA-Z0-9._-]+)([><=!~]+\s*[a-zA-Z0-9.*_+\-]+)?$', spec)
        if not match:
            return False

        package_name = match.group(1)
        version_spec = match.group(2)

        if not self._package_pattern().match(package_name):
            return False

        if version_spec:
            if not re.match(r'^[><=!~]+\s*[a-zA-Z0-9.*_+\-]+$', version_spec):
                return False

        keywords = self._dangerous_keywords()
        if any(kw in package_name.lower() for kw in keywords):
            return False

        return True

    def validate_package_list(self, packages: List[str]) -> Tuple[bool, List[str]]:
        invalid = [p for p in packages if not self.validate_package_name(p)]
        return len(invalid) == 0, invalid

    def validate_filename(self, filename: str) -> bool:
        """Validate filename (no path) for export"""
        if not filename or not isinstance(filename, str):
            return False
        return bool(self._filename_pattern().match(filename))
