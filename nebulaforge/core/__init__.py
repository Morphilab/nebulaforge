"""
NebulaForge  - Core Package
Core modules for secure Conda environment management
"""

from .audit_logger import AuditLogger
from .backup_manager import BackupManager
from .cli_helpers import CLIHelpers, select_environment, wait_for_continue
from .config_manager import ConfigManager
from .dependency_checker import SecureDependencyChecker
from .encrypted_store import EncryptedStore
from .environment_service import EnvironmentService, ServiceResult
from .error_handler import SecureErrorHandler
from .interactive_cli import NebulaForgeInteractiveCLI, run_interactive_cli
from .secrets import SecureCredentials
from .secure_diagnostics import SecureDiagnostics
from .secure_store import SecureStore
from .security_manager import SecurityManager
from .security_validator import SecurityValidator
from .session import Session, SessionManager

__version__ = "1.0.0"
__author__ = "Morphilab"

__all__ = [
    'ConfigManager',
    'SecurityManager',
    'AuditLogger',
    'BackupManager',
    'SecureDependencyChecker',
    'SecureErrorHandler',
    'NebulaForgeInteractiveCLI',
    'run_interactive_cli',
    'SecurityValidator',
    'SecureDiagnostics',
    'CLIHelpers',
    'select_environment',
    'wait_for_continue',
    'SecureCredentials',
    'SessionManager',
    'Session',
    'SecureStore',
    'EnvironmentService',
    'ServiceResult',
]
