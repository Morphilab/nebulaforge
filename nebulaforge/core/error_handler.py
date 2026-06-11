"""
NebulaForge - Secure error handler

"""
from __future__ import annotations

import sys
import traceback
from datetime import datetime
from typing import Any, Dict, Optional

from .audit_logger import AuditLogger


class SecureErrorHandler:
    """Centralized error handler with secure logging"""

    def __init__(self, audit_logger: Optional[AuditLogger] = None):
        self.audit_logger = audit_logger

    def handle_system_error(self, error: Exception, context: str = "unknown") -> None:
        error_info = self._extract_error_info(error, context)
        if self.audit_logger:
            self.audit_logger.log_secure_action("system_error", context, "error", {"error": str(error)})
        self._safe_stderr_output(error_info)

    def handle_security_error(self, error: Exception, operation: str, target: str) -> None:
        error_info = self._extract_error_info(error, f"security_{operation}")
        if self.audit_logger:
            self.audit_logger.log_secure_action("security_violation", target, "error")
        self._safe_stderr_output(error_info)

    def _extract_error_info(self, error: Exception, context: str) -> Dict[str, Any]:
        return {
            'timestamp': datetime.now().isoformat(),
            'context': context,
            'type': type(error).__name__,
            'message': str(error)[:500],
            'traceback': traceback.format_exc()[:1000]
        }

    def _safe_stderr_output(self, error_info: Dict[str, Any]) -> None:
        try:
            output = f"""
🚨 NEBULAFORGE ERROR
──────────────────────
• Context: {error_info['context']}
• Type: {error_info['type']}
• Message: {error_info['message']}
• Time: {error_info['timestamp']}
"""
            print(output, file=sys.stderr)
        except Exception:
            print("Critical error in NebulaForge", file=sys.stderr)

    def create_error_response(self, success: bool, message: str, details: Optional[Dict] = None) -> Dict:
        response = {
            'success': success,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        if details:
            response['details'] = details
        return response
