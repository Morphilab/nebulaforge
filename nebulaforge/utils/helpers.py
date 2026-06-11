"""
NebulaForge - General helper utilities
"""

import hashlib
from typing import Any, Dict


class SecurityHelper:
    """General security utilities"""

    @staticmethod
    def generate_secure_hash(data: str) -> str:
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    @staticmethod
    def get_system_info() -> Dict[str, Any]:
        import platform
        return {
            'platform': platform.system(),
            'python_version': platform.python_version(),
            'architecture': platform.machine()
        }
