"""
NebulaForge - Secure session management
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class Session:
    token: str
    created_at: float
    expires_at: float
    data: Dict[str, Any] = field(default_factory=dict)
    ip_address: Optional[str] = None


class SessionManager:
    """Session manager with cryptographically secure tokens and expiration"""

    def __init__(self, session_ttl: int = 3600, max_sessions: int = 100):
        self._sessions: Dict[str, Session] = {}
        self.session_ttl = session_ttl
        self.max_sessions = max_sessions

    def create_session(self, data: Optional[Dict[str, Any]] = None, ip_address: Optional[str] = None) -> Session:
        self._evict_expired()
        if len(self._sessions) >= self.max_sessions:
            self._evict_oldest()
        token = secrets.token_urlsafe(32)
        now = time.time()
        session = Session(
            token=token,
            created_at=now,
            expires_at=now + self.session_ttl,
            data=data or {},
            ip_address=ip_address,
        )
        self._sessions[token] = session
        return session

    def get_session(self, token: str) -> Optional[Session]:
        self._evict_expired()
        session = self._sessions.get(token)
        if session is None:
            return None
        if time.time() > session.expires_at:
            self.invalidate_session(token)
            return None
        return session

    def invalidate_session(self, token: str) -> bool:
        return self._sessions.pop(token, None) is not None

    def refresh_session(self, token: str) -> Optional[Session]:
        session = self.get_session(token)
        if session is None:
            return None
        session.expires_at = time.time() + self.session_ttl
        return session

    def get_active_sessions(self) -> list:
        self._evict_expired()
        return [
            {
                'token': self._mask_token(s.token),
                'created_at': datetime.fromtimestamp(s.created_at).isoformat(),
                'expires_at': datetime.fromtimestamp(s.expires_at).isoformat(),
                'ip_address': s.ip_address,
            }
            for s in self._sessions.values()
        ]

    def invalidate_all(self) -> int:
        count = len(self._sessions)
        self._sessions.clear()
        return count

    def _evict_expired(self) -> None:
        now = time.time()
        expired = [t for t, s in self._sessions.items() if now > s.expires_at]
        for token in expired:
            self._sessions.pop(token, None)

    def _evict_oldest(self) -> None:
        if not self._sessions:
            return
        oldest = min(self._sessions.items(), key=lambda x: x[1].created_at)
        self._sessions.pop(oldest[0], None)

    def _mask_token(self, token: str) -> str:
        h = hashlib.sha256(token.encode()).hexdigest()[:12]
        return f"ses_{h}..."
