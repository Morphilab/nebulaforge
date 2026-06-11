"""
NebulaForge - Secure audit logging system
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Optional

GENESIS_HASH = '0' * 64


class AuditLogger:
    """NebulaForge centralized audit system with cryptographic chaining"""

    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.log_dir = self.config_manager.get_secure_path('paths.log_dir')
        self.audit_file = self.log_dir / "security_audit.log"
        self.system_file = self.log_dir / "system_events.log"

        self._setup_logging()
        self.session_id = self._generate_session_id()
        self._last_audit_hash = self._load_last_hash(self.audit_file)
        self._last_system_hash = self._load_last_hash(self.system_file)
        self.log_system_event("audit_system_start", "Audit system initialized")

    def _load_last_hash(self, file_path) -> str:
        hash_path = file_path.with_suffix('.lasthash')
        try:
            if hash_path.exists():
                return hash_path.read_text(encoding='utf-8').strip()
        except Exception:
            pass
        if not file_path.exists() or file_path.stat().st_size == 0:
            return GENESIS_HASH
        try:
            with open(file_path, encoding='utf-8') as f:
                lines = f.readlines()
                if lines:
                    last = lines[-1].strip()
                    if last:
                        return hashlib.sha256(last.encode('utf-8')).hexdigest()
        except Exception:
            pass
        return GENESIS_HASH

    def _setup_logging(self) -> None:
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger('NEBULAFORGE')
        if not self.logger.handlers:
            handler = RotatingFileHandler(
                self.audit_file, maxBytes=100 * 1024 * 1024, backupCount=5, encoding='utf-8'
            )
            handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            handler.setLevel(logging.INFO)
            self.logger.setLevel(logging.INFO)
            self.logger.addHandler(handler)
        self._system_handler_name = '_system_events_handler'
        if not any(getattr(h, 'name', '') == self._system_handler_name for h in self.logger.handlers):
            sys_handler = RotatingFileHandler(
                self.system_file, maxBytes=100 * 1024 * 1024, backupCount=3, encoding='utf-8'
            )
            sys_handler.name = self._system_handler_name
            sys_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            sys_handler.setLevel(logging.DEBUG)
            self.logger.addHandler(sys_handler)

    def _generate_session_id(self) -> str:
        return secrets.token_hex(16)

    def log_secure_action(
        self, action: str, target: str, status: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'session_id': self.session_id,
            'action': action,
            'target': target,
            'status': status,
            'details': details or {},
            'security_level': self.config_manager.get('security.security_level', 'medium')
        }
        self._write_audit_entry(log_entry)
        msg = f"{action} on {target} - {status}"
        getattr(self.logger, status if status in ['warning', 'error'] else 'info')(msg)

    def log_system_event(self, event_type: str, message: str, details: Optional[Dict] = None) -> None:
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'session_id': self.session_id,
            'event_type': event_type,
            'message': message,
            'details': details or {}
        }
        self._write_system_entry(log_entry)
        self.logger.info(f"SYSTEM: {event_type} - {message}")

    def _write_entry_chain(self, entry: Dict, file_path, last_hash_attr: str) -> None:
        try:
            entry['previous_hash'] = getattr(self, last_hash_attr, GENESIS_HASH)
            line = json.dumps(entry, ensure_ascii=False) + '\n'
            with open(file_path, 'a', encoding='utf-8') as f:
                f.write(line)
            new_hash = hashlib.sha256(line.encode('utf-8')).hexdigest()
            setattr(self, last_hash_attr, new_hash)
            hash_path = file_path.with_suffix('.lasthash')
            tmp_hash = hash_path.with_suffix('.lasthash.tmp')
            tmp_hash.write_text(new_hash, encoding='utf-8')
            tmp_hash.replace(hash_path)
        except Exception as e:
            self.logger.warning(f"Failed to write audit entry: {e}")

    def _write_audit_entry(self, entry: Dict) -> None:
        self._write_entry_chain(entry, self.audit_file, '_last_audit_hash')

    def _write_system_entry(self, entry: Dict) -> None:
        self._write_entry_chain(entry, self.system_file, '_last_system_hash')

    def get_audit_trail(self, limit: int = 50) -> List[Dict]:
        entries = []
        try:
            if self.audit_file.exists():
                with open(self.audit_file, encoding='utf-8') as f:
                    lines = f.readlines()[-limit:]
                    for line in lines:
                        try:
                            entries.append(json.loads(line.strip()))
                        except Exception:
                            continue
        except Exception:
            pass
        return entries

    def verify_audit_chain(self, file_path=None) -> Dict[str, Any]:
        """Verify audit log hash chain integrity"""
        file_path = file_path or self.audit_file
        result: Dict[str, Any] = {'valid': True, 'entries': 0, 'broken_at': None, 'errors': []}
        if not file_path.exists():
            return result
        try:
            previous_hash = GENESIS_HASH
            with open(file_path, encoding='utf-8') as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        entry = json.loads(stripped)
                    except json.JSONDecodeError:
                        continue
                    if entry.get('previous_hash', '') != previous_hash:
                        result['valid'] = False
                        result['broken_at'] = result['entries']
                        result['errors'].append(f"Hash mismatch at entry {result['entries']}")
                    previous_hash = hashlib.sha256(line.encode('utf-8')).hexdigest()
                    result['entries'] += 1
        except Exception as e:
            result['valid'] = False
            result['errors'].append(str(e))
        return result
