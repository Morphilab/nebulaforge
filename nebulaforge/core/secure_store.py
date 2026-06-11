"""
NebulaForge - Encrypted key-value persistent store
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any, Optional

from .encrypted_store import EncryptedStore


class SecureStore(EncryptedStore):
    """Encrypted persistent store with per-entry expiration"""

    def unlock(self, master_password: str) -> None:
        self._key = self._derive_key(master_password)

    def is_locked(self) -> bool:
        return self._key is None

    def put(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        f = self._get_fernet()
        entry = {
            'value': value,
            'created_at': datetime.now().isoformat(),
        }
        if ttl_seconds is not None:
            expiry = datetime.now() + timedelta(seconds=ttl_seconds)
            entry['expires_at'] = expiry.isoformat()
        all_entries = self._load_all()
        all_entries[key] = f.encrypt(json.dumps(entry).encode()).decode()
        self._save_all(all_entries)

    def get(self, key: str) -> Optional[Any]:
        f = self._get_fernet()
        all_entries = self._load_all()
        raw = all_entries.get(key)
        if raw is None:
            return None
        decrypted = json.loads(f.decrypt(raw.encode()).decode())
        if 'expires_at' in decrypted:
            expiry = datetime.fromisoformat(decrypted['expires_at'])
            if datetime.now() > expiry:
                self.delete(key)
                return None
        return decrypted['value']

    def delete(self, key: str) -> bool:
        all_entries = self._load_all()
        if key not in all_entries:
            return False
        del all_entries[key]
        self._save_all(all_entries)
        return True

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def keys(self) -> list:
        self._evict_expired()
        return list(self._load_all().keys())

    def clear(self) -> None:
        self._save_all({})

    def _evict_expired(self) -> None:
        f = self._get_fernet()
        all_entries = self._load_all()
        now = datetime.now()
        expired_keys = []
        for key, encrypted in all_entries.items():
            try:
                decrypted = json.loads(f.decrypt(encrypted.encode()).decode())
                if 'expires_at' in decrypted:
                    if now > datetime.fromisoformat(decrypted['expires_at']):
                        expired_keys.append(key)
            except Exception:
                expired_keys.append(key)
        for key in expired_keys:
            all_entries.pop(key, None)
        if expired_keys:
            self._save_all(all_entries)
