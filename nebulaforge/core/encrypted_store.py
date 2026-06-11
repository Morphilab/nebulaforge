"""
NebulaForge - Shared encrypted storage base
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Dict, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def _atomic_write_json(path: Path, data: dict) -> None:
    tmp = path.with_suffix(f'.tmp.{os.urandom(4).hex()}')
    tmp.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
    tmp.chmod(0o600)
    tmp.replace(path)


class EncryptedStore:
    """Base class for Fernet-encrypted persistent storage"""

    def __init__(self, store_path: Path, master_password: Optional[str] = None):
        self.store_path = store_path
        self._key: Optional[bytes] = None
        if master_password:
            self._key = self._derive_key(master_password)

    def _derive_key(self, master_password: str) -> bytes:
        salt = self._load_or_create_salt()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

    def _load_or_create_salt(self) -> bytes:
        salt_path = self.store_path.with_suffix('.salt')
        if salt_path.exists():
            return salt_path.read_bytes()
        salt = os.urandom(16)
        salt_path.parent.mkdir(parents=True, exist_ok=True)
        salt_path.write_bytes(salt)
        return salt

    def _get_fernet(self) -> Fernet:
        if self._key is None:
            raise RuntimeError(
                "Master password not set. Call set_password() or unlock() first."
            )
        return Fernet(self._key)

    def _load_all(self) -> Dict[str, str]:
        if not self.store_path.exists():
            return {}
        raw = self.store_path.read_text(encoding='utf-8')
        if not raw.strip():
            return {}
        return json.loads(raw)

    def _save_all(self, data: Dict[str, str]) -> None:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_json(self.store_path, data)

    def has_password(self) -> bool:
        return self._key is not None
