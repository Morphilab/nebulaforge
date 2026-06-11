"""
NebulaForge - Encrypted credential storage
"""

from __future__ import annotations

import base64
import json
import os
from typing import Dict, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .encrypted_store import EncryptedStore


class SecureCredentials(EncryptedStore):
    """Encrypted credential store using Fernet (AES-128-CBC + HMAC-SHA256)"""

    def set_password(self, master_password: str) -> None:
        self._key = self._derive_key(master_password)

    def store(self, service: str, credentials: Dict[str, str]) -> None:
        f = self._get_fernet()
        data = json.dumps(credentials).encode()
        encrypted = f.encrypt(data)
        existing = self._load_all()
        existing[service] = encrypted.decode()
        self._save_all(existing)

    def retrieve(self, service: str) -> Optional[Dict[str, str]]:
        f = self._get_fernet()
        all_entries = self._load_all()
        raw = all_entries.get(service)
        if raw is None:
            return None
        decrypted = f.decrypt(raw.encode())
        return json.loads(decrypted.decode())

    def delete(self, service: str) -> bool:
        all_entries = self._load_all()
        if service not in all_entries:
            return False
        del all_entries[service]
        self._save_all(all_entries)
        return True

    def list_services(self) -> list:
        return list(self._load_all().keys())

    def change_master_password(self, old_password: str, new_password: str) -> None:
        self.set_password(old_password)
        all_entries = {}
        f_old = self._get_fernet()
        old_raw = self._load_all()
        for service, encrypted in old_raw.items():
            decrypted = f_old.decrypt(encrypted.encode())
            all_entries[service] = json.loads(decrypted.decode())

        old_salt_path = self.store_path.with_suffix('.salt')
        new_salt_path = self.store_path.with_suffix('.salt.new')
        tmp_store = self.store_path.with_suffix(f'.tmp.{os.urandom(4).hex()}')

        self._key = None

        new_salt = os.urandom(16)
        new_salt_path.write_bytes(new_salt)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32,
            salt=new_salt, iterations=600_000
        )
        new_key = base64.urlsafe_b64encode(kdf.derive(new_password.encode()))
        f_new = Fernet(new_key)

        new_store = {
            service: f_new.encrypt(json.dumps(creds).encode()).decode()
            for service, creds in all_entries.items()
        }
        tmp_store.write_text(json.dumps(new_store, ensure_ascii=False), encoding='utf-8')
        tmp_store.chmod(0o600)

        os.replace(str(tmp_store), str(self.store_path))
        os.replace(str(new_salt_path), str(old_salt_path))

        self._key = new_key
